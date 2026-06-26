/**
 * rp2p.c - librp2p portable contract tests.
 * Summary: Validates exported librp2p behavior through the public C API.
 *
 * Author:  KaisarCode
 * Website: https://kaisarcode.com
 * License: https://www.gnu.org/licenses/gpl-3.0.html
 */

#ifndef _WIN32
#define _POSIX_C_SOURCE 200809L
#endif

#include "rp2p.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <process.h>
#include <winsock2.h>
#include <windows.h>
#else
#include <arpa/inet.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#endif

#define KC_TEST_HOST "127.0.0.1"

#ifdef _WIN32
typedef SOCKET kc_socket_t;
typedef HANDLE kc_thread_t;
#define KC_SOCKET_INVALID INVALID_SOCKET
#else
typedef int kc_socket_t;
typedef pthread_t kc_thread_t;
#define KC_SOCKET_INVALID -1
#endif

typedef struct {
    rp2p_t *ctx;
    unsigned short port;
    int result;
    kc_thread_t thread;
} kc_index_t;

typedef struct {
    rp2p_t *ctx;
    const char *host;
    unsigned short index_port;
    const char *id;
    const char *target;
    unsigned short bind_port;
    int proto;
    const char *pass;
    int result;
    kc_thread_t thread;
} kc_peer_t;

typedef struct {
    unsigned short port;
    int proto;
    volatile int stop;
    kc_thread_t thread;
} kc_echo_t;

typedef struct {
    char ids[8][RP2P_ID_MAX + 1];
    int count;
} kc_publishers_t;

static int signal_count = 0;

/**
 * Returns a process-specific base TCP or UDP port.
 * @return Port base.
 */
static unsigned short kc_port_base(void) {
#ifdef _WIN32
    return (unsigned short)(25000UL + ((unsigned long)_getpid() % 20000UL));
#else
    return (unsigned short)(25000UL + ((unsigned long)getpid() % 20000UL));
#endif
}

/**
 * Sleeps for a bounded number of milliseconds.
 * @param ms Milliseconds to sleep.
 * @return None.
 */
static void kc_sleep_ms(unsigned int ms) {
#ifdef _WIN32
    Sleep(ms);
#else
    struct timespec ts;

    ts.tv_sec = (time_t)(ms / 1000U);
    ts.tv_nsec = (long)(ms % 1000U) * 1000000L;
    while (nanosleep(&ts, &ts) != 0 && errno == EINTR) {
    }
#endif
}

/**
 * Starts platform socket state.
 * @return 0 on success, 1 on failure.
 */
static int kc_socket_start(void) {
#ifdef _WIN32
    WSADATA data;

    return WSAStartup(MAKEWORD(2, 2), &data) == 0 ? 0 : 1;
#else
    signal(SIGPIPE, SIG_IGN);
    return 0;
#endif
}

/**
 * Stops platform socket state.
 * @return 0 on success.
 */
static int kc_socket_stop(void) {
#ifdef _WIN32
    WSACleanup();
#endif
    return 0;
}

/**
 * Closes one socket.
 * @param fd Socket descriptor.
 * @return 0 on success, non-zero on failure.
 */
static int kc_socket_close(kc_socket_t fd) {
#ifdef _WIN32
    return closesocket(fd);
#else
    return close(fd);
#endif
}

/**
 * Creates an IPv4 socket.
 * @param proto RP2P protocol value.
 * @return Socket descriptor or invalid socket.
 */
static kc_socket_t kc_socket_create(int proto) {
    int type;

    type = proto == RP2P_PROTO_UDP ? SOCK_DGRAM : SOCK_STREAM;
    return socket(AF_INET, type, 0);
}

/**
 * Enables fast local port reuse where supported.
 * @param fd Socket descriptor.
 * @return 0 on success.
 */
static int kc_socket_reuse(kc_socket_t fd) {
    int one;

    one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const char *)&one, sizeof(one));
    return 0;
}

/**
 * Sets a receive timeout on one socket.
 * @param fd Socket descriptor.
 * @param ms Timeout in milliseconds.
 * @return 0 on success.
 */
static int kc_socket_timeout(kc_socket_t fd, unsigned int ms) {
#ifdef _WIN32
    DWORD tv;

    tv = (DWORD)ms;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv));
#else
    struct timeval tv;

    tv.tv_sec = (time_t)(ms / 1000U);
    tv.tv_usec = (suseconds_t)(ms % 1000U) * 1000;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv));
#endif
    return 0;
}

/**
 * Binds one IPv4 loopback socket.
 * @param fd Socket descriptor.
 * @param port TCP or UDP port.
 * @return 0 on success, 1 on failure.
 */
static int kc_socket_bind(kc_socket_t fd, unsigned short port) {
    struct sockaddr_in addr;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    return bind(fd, (const struct sockaddr *)&addr, sizeof(addr)) == 0 ? 0 : 1;
}

/**
 * Tests whether a loopback TCP port accepts a connection.
 * @param port TCP port.
 * @return 1 when open, 0 when closed.
 */
static int kc_port_open(unsigned short port) {
    kc_socket_t fd;
    struct sockaddr_in addr;
    int rc;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == KC_SOCKET_INVALID) return 0;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    rc = connect(fd, (const struct sockaddr *)&addr, sizeof(addr));
    kc_socket_close(fd);
    return rc == 0 ? 1 : 0;
}

/**
 * Waits until a TCP port reaches the expected open state.
 * @param port TCP port.
 * @param open Expected state.
 * @return 1 when state is observed, 0 on timeout.
 */
static int kc_wait_port(unsigned short port, int open) {
    int i;

    for (i = 0; i < 80; i++) {
        if (kc_port_open(port) == open) return 1;
        kc_sleep_ms(100U);
    }
    return 0;
}

/**
 * Verifies one integer result.
 * @param name Check name.
 * @param expected Expected value.
 * @param actual Actual value.
 * @return 0 on success, 1 on failure.
 */
static int expect_int(const char *name, int expected, int actual) {
    if (expected != actual) {
        fprintf(stderr, "%s: expected %d, got %d\n", name, expected, actual);
        return 1;
    }
    return 0;
}

/**
 * Verifies one string result.
 * @param name Check name.
 * @param expected Expected string.
 * @param actual Actual string.
 * @return 0 on success, 1 on failure.
 */
static int expect_string(const char *name, const char *expected, const char *actual) {
    if (actual == NULL || strcmp(expected, actual) != 0) {
        fprintf(stderr, "%s: expected '%s', got '%s'\n", name, expected,
            actual != NULL ? actual : "NULL");
        return 1;
    }
    return 0;
}

/**
 * Sets or clears a process environment variable.
 * @param name Variable name.
 * @param value Variable value, or NULL to clear.
 * @return 0 on success, 1 on failure.
 */
static int set_env_value(const char *name, const char *value) {
#ifdef _WIN32
    return _putenv_s(name, value != NULL ? value : "") == 0 ? 0 : 1;
#else
    if (value == NULL) return unsetenv(name) == 0 ? 0 : 1;
    return setenv(name, value, 1) == 0 ? 0 : 1;
#endif
}

/**
 * Stores one observed signal callback.
 * @param ctx Context passed by the library.
 * @return None.
 */
static void count_signal(rp2p_t *ctx) {
    if (ctx != NULL) signal_count++;
}

#ifdef _WIN32
/**
 * Runs one index thread.
 * @param arg Thread argument.
 * @return Thread return value.
 */
static DWORD WINAPI index_main(void *arg) {
    kc_index_t *index;

    index = (kc_index_t *)arg;
    index->result = rp2p_serve_index(index->ctx, NULL, index->port);
    return 0;
}

/**
 * Runs one peer thread.
 * @param arg Thread argument.
 * @return Thread return value.
 */
static DWORD WINAPI peer_main(void *arg) {
    kc_peer_t *peer;

    peer = (kc_peer_t *)arg;
    rp2p_set_protocol(peer->ctx, peer->proto);
    rp2p_set_port(peer->ctx, peer->bind_port);
    if (peer->pass != NULL) rp2p_set_pass(peer->ctx, peer->pass);
    if (peer->id != NULL) {
        peer->result = rp2p_wait(peer->ctx, peer->host, peer->index_port,
            peer->id, peer->bind_port);
    } else {
        peer->result = rp2p_connect(peer->ctx, peer->host, peer->index_port,
            "consumer", peer->target, peer->bind_port);
    }
    return 0;
}
#else
/**
 * Runs one index thread.
 * @param arg Thread argument.
 * @return Thread return value.
 */
static void *index_main(void *arg) {
    kc_index_t *index;

    index = (kc_index_t *)arg;
    index->result = rp2p_serve_index(index->ctx, NULL, index->port);
    return NULL;
}

/**
 * Runs one peer thread.
 * @param arg Thread argument.
 * @return Thread return value.
 */
static void *peer_main(void *arg) {
    kc_peer_t *peer;

    peer = (kc_peer_t *)arg;
    rp2p_set_protocol(peer->ctx, peer->proto);
    rp2p_set_port(peer->ctx, peer->bind_port);
    if (peer->pass != NULL) rp2p_set_pass(peer->ctx, peer->pass);
    if (peer->id != NULL) {
        peer->result = rp2p_wait(peer->ctx, peer->host, peer->index_port,
            peer->id, peer->bind_port);
    } else {
        peer->result = rp2p_connect(peer->ctx, peer->host, peer->index_port,
            "consumer", peer->target, peer->bind_port);
    }
    return NULL;
}
#endif

/**
 * Starts one portable thread.
 * @param thread Output thread handle.
 * @param fn Thread function.
 * @param arg Thread argument.
 * @return 0 on success, 1 on failure.
 */
static int thread_start(kc_thread_t *thread,
#ifdef _WIN32
    DWORD (WINAPI *fn)(void *),
#else
    void *(*fn)(void *),
#endif
    void *arg)
{
#ifdef _WIN32
    *thread = CreateThread(NULL, 0, fn, arg, 0, NULL);
    return *thread != NULL ? 0 : 1;
#else
    return pthread_create(thread, NULL, fn, arg) == 0 ? 0 : 1;
#endif
}

/**
 * Joins one portable thread.
 * @param thread Thread handle.
 * @return 0 on success, 1 on failure.
 */
static int thread_join(kc_thread_t thread) {
#ifdef _WIN32
    if (WaitForSingleObject(thread, 15000U) != WAIT_OBJECT_0) return 1;
    CloseHandle(thread);
    return 0;
#else
    return pthread_join(thread, NULL) == 0 ? 0 : 1;
#endif
}

/**
 * Starts one index server thread.
 * @param index Index state.
 * @param port Control port.
 * @return 0 on success, 1 on failure.
 */
static int index_start(kc_index_t *index, unsigned short port) {
    memset(index, 0, sizeof(*index));
    index->port = port;
    if (rp2p_open(&index->ctx) != RP2P_OK) return 1;
    if (thread_start(&index->thread, index_main, index) != 0) return 1;
    return kc_wait_port(port, 1) ? 0 : 1;
}

/**
 * Stops one index server thread.
 * @param index Index state.
 * @return 0 on success, 1 on failure.
 */
static int index_stop(kc_index_t *index) {
    int rc;

    rc = 0;
    if (index->ctx != NULL) rc += expect_int("stop index", RP2P_OK,
        rp2p_stop(index->ctx));
    rc += thread_join(index->thread);
    if (index->ctx != NULL) rc += expect_int("close index", RP2P_OK,
        rp2p_close(index->ctx));
    index->ctx = NULL;
    return rc == 0 ? 0 : 1;
}

/**
 * Records one publisher id.
 * @param id Publisher identifier.
 * @param userdata Publisher collection.
 * @return None.
 */
static void on_publisher(const char *id, void *userdata) {
    kc_publishers_t *publishers;

    publishers = (kc_publishers_t *)userdata;
    if (publishers->count >= 8) return;
    strncpy(publishers->ids[publishers->count], id, RP2P_ID_MAX);
    publishers->ids[publishers->count][RP2P_ID_MAX] = '\0';
    publishers->count++;
}

/**
 * Returns whether one publisher id was collected.
 * @param publishers Publisher collection.
 * @param id Publisher identifier.
 * @return 1 when found, 0 otherwise.
 */
static int has_publisher(kc_publishers_t *publishers, const char *id) {
    int i;

    for (i = 0; i < publishers->count; i++) {
        if (strcmp(publishers->ids[i], id) == 0) return 1;
    }
    return 0;
}

#ifdef _WIN32
/**
 * Runs one echo backend.
 * @param arg Thread argument.
 * @return Thread return value.
 */
static DWORD WINAPI echo_main(void *arg)
#else
/**
 * Runs one echo backend.
 * @param arg Thread argument.
 * @return Thread return value.
 */
static void *echo_main(void *arg)
#endif
{
    kc_echo_t *echo;
    kc_socket_t fd;
    char buf[4096];

    echo = (kc_echo_t *)arg;
    fd = kc_socket_create(echo->proto);
    if (fd == KC_SOCKET_INVALID) {
#ifdef _WIN32
        return 0;
#else
        return NULL;
#endif
    }
    kc_socket_reuse(fd);
    if (kc_socket_bind(fd, echo->port) != 0) {
        kc_socket_close(fd);
#ifdef _WIN32
        return 0;
#else
        return NULL;
#endif
    }
    if (echo->proto == RP2P_PROTO_TCP) {
        listen(fd, 16);
        while (!echo->stop) {
            kc_socket_t client;
            int n;

            client = accept(fd, NULL, NULL);
            if (client == KC_SOCKET_INVALID) {
                kc_sleep_ms(20U);
                continue;
            }
            while ((n = (int)recv(client, buf, (int)sizeof(buf), 0)) > 0) {
                send(client, buf, n, 0);
            }
            kc_socket_close(client);
        }
    } else {
        while (!echo->stop) {
            struct sockaddr_in src;
#ifdef _WIN32
            int slen;
#else
            socklen_t slen;
#endif
            int n;

            slen = sizeof(src);
            n = (int)recvfrom(fd, buf, (int)sizeof(buf), 0,
                (struct sockaddr *)&src, &slen);
            if (n > 0) sendto(fd, buf, n, 0, (struct sockaddr *)&src, slen);
        }
    }
    kc_socket_close(fd);
#ifdef _WIN32
    return 0;
#else
    return NULL;
#endif
}

/**
 * Starts one echo backend.
 * @param echo Echo backend state.
 * @param proto RP2P protocol value.
 * @param port Backend port.
 * @return 0 on success, 1 on failure.
 */
static int echo_start(kc_echo_t *echo, int proto, unsigned short port) {
    memset(echo, 0, sizeof(*echo));
    echo->proto = proto;
    echo->port = port;
    if (thread_start(&echo->thread, echo_main, echo) != 0) return 1;
    if (proto == RP2P_PROTO_TCP) return kc_wait_port(port, 1) ? 0 : 1;
    kc_sleep_ms(200U);
    return 0;
}

/**
 * Stops one echo backend.
 * @param echo Echo backend state.
 * @return 0 on success.
 */
static int echo_stop(kc_echo_t *echo) {
    echo->stop = 1;
    if (echo->proto == RP2P_PROTO_TCP) {
        kc_socket_t fd;

        fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd != KC_SOCKET_INVALID) {
            struct sockaddr_in addr;

            memset(&addr, 0, sizeof(addr));
            addr.sin_family = AF_INET;
            addr.sin_port = htons(echo->port);
            addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            connect(fd, (const struct sockaddr *)&addr, sizeof(addr));
            kc_socket_close(fd);
        }
    } else {
        kc_socket_t fd;
        struct sockaddr_in addr;

        fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd != KC_SOCKET_INVALID) {
            memset(&addr, 0, sizeof(addr));
            addr.sin_family = AF_INET;
            addr.sin_port = htons(echo->port);
            addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            sendto(fd, "", 1, 0, (const struct sockaddr *)&addr, sizeof(addr));
            kc_socket_close(fd);
        }
    }
    thread_join(echo->thread);
    return 0;
}

/**
 * Starts one publisher or consumer peer.
 * @param peer Peer state.
 * @return 0 on success, 1 on failure.
 */
static int peer_start(kc_peer_t *peer) {
    if (rp2p_open(&peer->ctx) != RP2P_OK) return 1;
    return thread_start(&peer->thread, peer_main, peer);
}

/**
 * Stops one peer thread.
 * @param peer Peer state.
 * @return 0 on success.
 */
static int peer_stop(kc_peer_t *peer) {
    if (peer->ctx != NULL) rp2p_stop(peer->ctx);
    thread_join(peer->thread);
    if (peer->ctx != NULL) rp2p_close(peer->ctx);
    peer->ctx = NULL;
    return 0;
}

/**
 * Sends one TCP payload to a loopback port and reads the echo.
 * @param port TCP port.
 * @param message Payload.
 * @param out Output buffer.
 * @param cap Output buffer capacity.
 * @return 0 on success, 1 on failure.
 */
static int tcp_roundtrip(unsigned short port, const char *message, char *out, size_t cap) {
    kc_socket_t fd;
    struct sockaddr_in addr;
    int n;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == KC_SOCKET_INVALID) return 1;
    kc_socket_timeout(fd, 5000U);
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(fd, (const struct sockaddr *)&addr, sizeof(addr)) != 0) {
        kc_socket_close(fd);
        return 1;
    }
    send(fd, message, (int)strlen(message), 0);
#ifdef _WIN32
    shutdown(fd, SD_SEND);
#else
    shutdown(fd, SHUT_WR);
#endif
    n = (int)recv(fd, out, (int)cap - 1, 0);
    kc_socket_close(fd);
    if (n <= 0) return 1;
    out[n] = '\0';
    return 0;
}

/**
 * Sends one UDP payload to a loopback port and reads the echo.
 * @param port UDP port.
 * @param message Payload.
 * @param out Output buffer.
 * @param cap Output buffer capacity.
 * @return 0 on success, 1 on failure.
 */
static int udp_roundtrip(unsigned short port, const char *message, char *out, size_t cap) {
    kc_socket_t fd;
    struct sockaddr_in addr;
    int n;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == KC_SOCKET_INVALID) return 1;
    kc_socket_timeout(fd, 5000U);
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sendto(fd, message, (int)strlen(message), 0,
        (const struct sockaddr *)&addr, sizeof(addr));
    n = (int)recv(fd, out, (int)cap - 1, 0);
    kc_socket_close(fd);
    if (n <= 0) return 1;
    out[n] = '\0';
    return 0;
}

/**
 * Verifies options, setters, validation helpers, and signal callbacks.
 * @return 0 on success, 1 on failure.
 */
static int case_api(void) {
    rp2p_options_t opts;
    rp2p_t *ctx;
    char err[128];
    int rc;

    rc = 0;
    opts = rp2p_options_default();
    rc += expect_int("default port", RP2P_PORT_DEFAULT, opts.index_port);
    rc += expect_int("default sweep", 20, opts.sweep);
    set_env_value("RP2P_INDEX", "idx.local:1234");
    set_env_value("RP2P_BIND", "127.0.0.1:4567");
    set_env_value("RP2P_PASS", "abc");
    set_env_value("RP2P_VIP", "vip vip-pass");
    set_env_value("RP2P_SWEEP", "9");
    set_env_value("RP2P_STUN", "stun:example.com:3478");
    rp2p_options_load_env(&opts);
    rc += expect_string("env index host", "idx.local", opts.index_host);
    rc += expect_int("env index port", 1234, opts.index_port);
    rc += expect_string("env bind host", "127.0.0.1", opts.bind_addr);
    rc += expect_int("env bind port", 4567, opts.bind_port);
    rc += expect_string("env pass", "abc", opts.pass);
    rc += expect_string("env vip", "vip vip-pass", opts.vip);
    rc += expect_int("env sweep", 9, opts.sweep);
    rc += expect_string("env stun", "stun:example.com:3478", opts.stun_url);
    rp2p_options_free(&opts);
    set_env_value("RP2P_INDEX", NULL);
    set_env_value("RP2P_BIND", NULL);
    set_env_value("RP2P_PASS", NULL);
    set_env_value("RP2P_VIP", NULL);
    set_env_value("RP2P_SWEEP", NULL);
    set_env_value("RP2P_STUN", NULL);
    rc += expect_int("valid id", 1, rp2p_is_valid_id("abcXYZ123"));
    rc += expect_int("invalid id", 0, rp2p_is_valid_id("bad:id"));
    rc += expect_int("valid pass", 1, rp2p_is_valid_pass_token("a._-+=,:@%/"));
    rc += expect_int("invalid pass", 0, rp2p_is_valid_pass_token("bad`pass"));
    rc += expect_int("open null", RP2P_ERROR, rp2p_open(NULL));
    rc += expect_int("open", RP2P_OK, rp2p_open(&ctx));
    rc += expect_int("set seats", RP2P_OK, rp2p_set_seats(ctx, 3));
    rc += expect_int("set pow", RP2P_OK, rp2p_set_pow(ctx, -1));
    rc += expect_int("set port", RP2P_OK, rp2p_set_port(ctx, 9000));
    rc += expect_int("set tcp", RP2P_OK, rp2p_set_protocol(ctx, RP2P_PROTO_TCP));
    rc += expect_int("set udp", RP2P_OK, rp2p_set_protocol(ctx, RP2P_PROTO_UDP));
    rc += expect_int("set bad proto", RP2P_ERROR, rp2p_set_protocol(ctx, 99));
    rc += expect_int("set pass", RP2P_OK, rp2p_set_pass(ctx, "secret"));
    rc += expect_int("set bad pass", RP2P_ERROR, rp2p_set_pass(ctx, "bad`pass"));
    rc += expect_int("set vip", RP2P_OK, rp2p_set_vip(ctx, "one pass1 two pass2",
        err, sizeof(err)));
    rc += expect_int("set vip odd", RP2P_ERROR, rp2p_set_vip(ctx, "one",
        err, sizeof(err)));
    signal_count = 0;
    rc += expect_int("on signal null", RP2P_ERROR, rp2p_on_signal(NULL, 2, count_signal));
    rc += expect_int("raise signal null", 0, rp2p_raise_signal(NULL, 2));
    rc += expect_int("listen signal null", RP2P_OK, rp2p_listen_signal(NULL, 2));
    rc += expect_int("register signal", RP2P_OK, rp2p_on_signal(ctx, 2, count_signal));
    rc += expect_int("raise signal", 1, rp2p_raise_signal(ctx, 2));
    rc += expect_int("signal count", 1, signal_count);
    rc += expect_int("stop", RP2P_OK, rp2p_stop(ctx));
    rc += expect_int("close", RP2P_OK, rp2p_close(ctx));
    return rc == 0 ? 0 : 1;
}

/**
 * Verifies listing, registration, and deregistration through the library API.
 * @return 0 on success, 1 on failure.
 */
static int case_index_catalog(void) {
    unsigned short base;
    kc_index_t index;
    kc_echo_t echo;
    kc_peer_t peer;
    rp2p_t *client;
    kc_publishers_t publishers;
    int rc;

    base = kc_port_base();
    rc = 0;
    if (index_start(&index, (unsigned short)(base + 1U)) != 0) return 1;
    if (echo_start(&echo, RP2P_PROTO_TCP, (unsigned short)(base + 2U)) != 0) return 1;
    memset(&peer, 0, sizeof(peer));
    peer.host = KC_TEST_HOST;
    peer.index_port = (unsigned short)(base + 1U);
    peer.id = "target";
    peer.bind_port = (unsigned short)(base + 2U);
    peer.proto = RP2P_PROTO_TCP;
    if (peer_start(&peer) != 0) return 1;
    kc_sleep_ms(800U);
    memset(&publishers, 0, sizeof(publishers));
    rc += expect_int("open list client", RP2P_OK, rp2p_open(&client));
    rc += expect_int("list publishers", RP2P_OK, rp2p_list_publishers(client,
        KC_TEST_HOST, (unsigned short)(base + 1U), on_publisher, &publishers));
    rc += expect_int("has target", 1, has_publisher(&publishers, "target"));
    rc += expect_int("deregister target", RP2P_OK, rp2p_deregister(client,
        KC_TEST_HOST, (unsigned short)(base + 1U), "target"));
    memset(&publishers, 0, sizeof(publishers));
    rc += expect_int("list after deregister", RP2P_OK, rp2p_list_publishers(client,
        KC_TEST_HOST, (unsigned short)(base + 1U), on_publisher, &publishers));
    rc += expect_int("target removed", 0, has_publisher(&publishers, "target"));
    rp2p_close(client);
    peer_stop(&peer);
    echo_stop(&echo);
    index_stop(&index);
    return rc == 0 ? 0 : 1;
}

/**
 * Verifies TCP tunnel behavior through library publisher and consumer APIs.
 * @return 0 on success, 1 on failure.
 */
static int case_tcp_tunnel(void) {
    unsigned short base;
    kc_index_t index;
    kc_echo_t echo;
    kc_peer_t publisher;
    kc_peer_t consumer;
    char out[64];
    int rc;

    base = (unsigned short)(kc_port_base() + 20U);
    rc = 0;
    if (index_start(&index, (unsigned short)(base + 1U)) != 0) return 1;
    if (echo_start(&echo, RP2P_PROTO_TCP, (unsigned short)(base + 2U)) != 0) return 1;
    memset(&publisher, 0, sizeof(publisher));
    publisher.host = KC_TEST_HOST;
    publisher.index_port = (unsigned short)(base + 1U);
    publisher.id = "target";
    publisher.bind_port = (unsigned short)(base + 2U);
    publisher.proto = RP2P_PROTO_TCP;
    if (peer_start(&publisher) != 0) return 1;
    kc_sleep_ms(800U);
    memset(&consumer, 0, sizeof(consumer));
    consumer.host = KC_TEST_HOST;
    consumer.index_port = (unsigned short)(base + 1U);
    consumer.target = "target";
    consumer.bind_port = (unsigned short)(base + 3U);
    consumer.proto = RP2P_PROTO_TCP;
    if (peer_start(&consumer) != 0) return 1;
    if (!kc_wait_port((unsigned short)(base + 3U), 1)) return 1;
    rc += expect_int("tcp roundtrip", 0, tcp_roundtrip((unsigned short)(base + 3U),
        "ping", out, sizeof(out)));
    rc += expect_string("tcp payload", "ping", out);
    peer_stop(&consumer);
    peer_stop(&publisher);
    echo_stop(&echo);
    index_stop(&index);
    return rc == 0 ? 0 : 1;
}

/**
 * Verifies UDP tunnel behavior through library publisher and consumer APIs.
 * @return 0 on success, 1 on failure.
 */
static int case_udp_tunnel(void) {
    unsigned short base;
    kc_index_t index;
    kc_echo_t echo;
    kc_peer_t publisher;
    kc_peer_t consumer;
    char out[64];
    int rc;

    base = (unsigned short)(kc_port_base() + 40U);
    rc = 0;
    if (index_start(&index, (unsigned short)(base + 1U)) != 0) return 1;
    if (echo_start(&echo, RP2P_PROTO_UDP, (unsigned short)(base + 2U)) != 0) return 1;
    memset(&publisher, 0, sizeof(publisher));
    publisher.host = KC_TEST_HOST;
    publisher.index_port = (unsigned short)(base + 1U);
    publisher.id = "target";
    publisher.bind_port = (unsigned short)(base + 2U);
    publisher.proto = RP2P_PROTO_UDP;
    if (peer_start(&publisher) != 0) return 1;
    kc_sleep_ms(800U);
    memset(&consumer, 0, sizeof(consumer));
    consumer.host = KC_TEST_HOST;
    consumer.index_port = (unsigned short)(base + 1U);
    consumer.target = "target";
    consumer.bind_port = (unsigned short)(base + 3U);
    consumer.proto = RP2P_PROTO_UDP;
    if (peer_start(&consumer) != 0) return 1;
    kc_sleep_ms(800U);
    rc += expect_int("udp roundtrip", 0, udp_roundtrip((unsigned short)(base + 3U),
        "pong", out, sizeof(out)));
    rc += expect_string("udp payload", "pong", out);
    peer_stop(&consumer);
    peer_stop(&publisher);
    echo_stop(&echo);
    index_stop(&index);
    return rc == 0 ? 0 : 1;
}

/**
 * Verifies auth, VIP password precedence, and capacity behavior.
 * @return 0 on success, 1 on failure.
 */
static int case_auth_vip_capacity(void) {
    unsigned short base;
    kc_index_t index;
    kc_echo_t echo_one;
    kc_echo_t echo_two;
    kc_peer_t peer_one;
    kc_peer_t peer_two;
    int rc;

    base = (unsigned short)(kc_port_base() + 60U);
    rc = 0;
    memset(&index, 0, sizeof(index));
    index.port = (unsigned short)(base + 1U);
    if (rp2p_open(&index.ctx) != RP2P_OK) return 1;
    rc += expect_int("index pass", RP2P_OK, rp2p_set_pass(index.ctx, "global"));
    rc += expect_int("index vip", RP2P_OK, rp2p_set_vip(index.ctx, "vip vip-pass",
        NULL, 0));
    rc += expect_int("index seats", RP2P_OK, rp2p_set_seats(index.ctx, 1));
    if (thread_start(&index.thread, index_main, &index) != 0) return 1;
    if (!kc_wait_port(index.port, 1)) return 1;
    if (echo_start(&echo_one, RP2P_PROTO_TCP, (unsigned short)(base + 2U)) != 0)
        return 1;
    memset(&peer_one, 0, sizeof(peer_one));
    peer_one.host = KC_TEST_HOST;
    peer_one.index_port = (unsigned short)(base + 1U);
    peer_one.id = "plain";
    peer_one.bind_port = (unsigned short)(base + 2U);
    peer_one.proto = RP2P_PROTO_TCP;
    peer_one.pass = "global";
    if (peer_start(&peer_one) != 0) return 1;
    kc_sleep_ms(1000U);
    rc += expect_int("nonvip rejected by reserved seat", RP2P_ERROR, peer_one.result);
    peer_stop(&peer_one);
    if (echo_start(&echo_two, RP2P_PROTO_TCP, (unsigned short)(base + 3U)) != 0)
        return 1;
    memset(&peer_two, 0, sizeof(peer_two));
    peer_two.host = KC_TEST_HOST;
    peer_two.index_port = (unsigned short)(base + 1U);
    peer_two.id = "vip";
    peer_two.bind_port = (unsigned short)(base + 3U);
    peer_two.proto = RP2P_PROTO_TCP;
    peer_two.pass = "vip-pass";
    if (peer_start(&peer_two) != 0) return 1;
    kc_sleep_ms(1000U);
    rc += expect_int("vip remains running", 1, peer_two.result == 0 ? 1 : 0);
    peer_stop(&peer_two);
    echo_stop(&echo_two);
    echo_stop(&echo_one);
    index_stop(&index);
    return rc == 0 ? 0 : 1;
}

/**
 * Verifies that stopping one index context leaves another context running.
 * @return 0 on success, 1 on failure.
 */
static int case_multictx_stop(void) {
    unsigned short base;
    kc_index_t first;
    kc_index_t second;
    int rc;

    base = (unsigned short)(kc_port_base() + 80U);
    rc = 0;
    if (index_start(&first, (unsigned short)(base + 1U)) != 0) return 1;
    if (index_start(&second, (unsigned short)(base + 2U)) != 0) return 1;
    rc += expect_int("stop first", RP2P_OK, rp2p_stop(first.ctx));
    rc += expect_int("join first", 0, thread_join(first.thread));
    rc += expect_int("first closed", 1, kc_wait_port(first.port, 0));
    rc += expect_int("second still open", 1, kc_port_open(second.port));
    rc += expect_int("first result", RP2P_OK, first.result);
    rc += expect_int("close first", RP2P_OK, rp2p_close(first.ctx));
    first.ctx = NULL;
    rc += expect_int("stop second", RP2P_OK, rp2p_stop(second.ctx));
    rc += expect_int("join second", 0, thread_join(second.thread));
    rc += expect_int("second result", RP2P_OK, second.result);
    rc += expect_int("close second", RP2P_OK, rp2p_close(second.ctx));
    second.ctx = NULL;
    return rc == 0 ? 0 : 1;
}

/**
 * Runs one librp2p contract test case.
 * @param argc Argument count.
 * @param argv Argument vector.
 * @return 0 on success, 1 or 2 on failure.
 */
int main(int argc, char **argv) {
    int rc;

    if (argc != 2) {
        fprintf(stderr, "test case: expected one argument, got %d\n", argc - 1);
        return 2;
    }
    set_env_value("HOME", ".");
    if (kc_socket_start() != 0) return 1;
    if (strcmp(argv[1], "api") == 0) rc = case_api();
    else if (strcmp(argv[1], "index-catalog") == 0) rc = case_index_catalog();
    else if (strcmp(argv[1], "tcp-tunnel") == 0) rc = case_tcp_tunnel();
    else if (strcmp(argv[1], "udp-tunnel") == 0) rc = case_udp_tunnel();
    else if (strcmp(argv[1], "auth-vip-capacity") == 0) rc = case_auth_vip_capacity();
    else if (strcmp(argv[1], "multictx-stop") == 0) rc = case_multictx_stop();
    else {
        fprintf(stderr, "unknown test case: %s\n", argv[1]);
        rc = 2;
    }
    kc_socket_stop();
    return rc;
}
