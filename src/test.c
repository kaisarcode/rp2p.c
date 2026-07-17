/**
 * rp2p.c - librp2p public API contract tests.
 * Summary: Validates each exported function through one dedicated test case.
 *
 * Author:  KaisarCode
 * Website: https://kaisarcode.com
 * License: https://www.gnu.org/licenses/gpl-3.0.html
 */

#ifndef _WIN32
#define _POSIX_C_SOURCE 200809L
#endif

#include "librp2p.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#ifdef _WIN32
#include <process.h>
#include <winsock2.h>
#include <windows.h>
#else
#include <dirent.h>
#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <arpa/inet.h>
#endif

#define TEST_HOST "127.0.0.1"

#ifdef _WIN32
typedef HANDLE test_thread_t;
typedef SOCKET test_socket_t;
typedef int test_socklen_t;
#define TEST_SOCKET_INVALID INVALID_SOCKET
#else
typedef pthread_t test_thread_t;
typedef int test_socket_t;
typedef socklen_t test_socklen_t;
#define TEST_SOCKET_INVALID -1
#endif

typedef struct {
    rp2p_t *ctx;
    unsigned short port;
    int result;
    test_thread_t thread;
} test_index_t;

typedef struct {
    rp2p_t *ctx;
    const char *host;
    unsigned short index_port;
    const char *id;
    unsigned short bind_port;
    int protocol;
    const char *pass;
    const char *secret;
    int result;
    test_thread_t thread;
} test_publisher_t;

typedef struct {
    rp2p_t *ctx;
    const char *host;
    unsigned short index_port;
    const char *self_id;
    const char *target_id;
    unsigned short bind_port;
    int protocol;
    const char *secret;
    int result;
    test_thread_t thread;
} test_consumer_t;

typedef struct {
    test_socket_t fd;
    unsigned short port;
    volatile int stop;
    test_thread_t thread;
} test_udp_echo_t;

typedef struct {
    test_socket_t fd;
    unsigned short port;
    volatile int stop;
    test_thread_t thread;
} test_tcp_echo_t;

typedef struct {
    char ids[8][RP2P_ID_MAX + 1];
    int count;
} test_publishers_t;

static int signal_count;
static rp2p_t *signal_ctx;
static char test_home_path[512];

/**
 * Returns the current process id as an unsigned long.
 * @return Process id value.
 */
static unsigned long test_pid(void) {
#ifdef _WIN32
    return (unsigned long)_getpid();
#else
    return (unsigned long)getpid();
#endif
}

/**
 * Returns a loopback port base for this process.
 * @return TCP port base.
 */
static unsigned short test_port_base(void) {
    return (unsigned short)(20000UL + (test_pid() % 80UL) * 512UL);
}

/**
 * Sleeps for a bounded number of milliseconds.
 * @param ms Milliseconds to sleep.
 * @return None.
 */
static void test_sleep_ms(unsigned int ms) {
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
 * Sets or clears a process environment variable.
 * @param name Environment variable name.
 * @param value Environment variable value or NULL.
 * @return 0 on success, 1 on failure.
 */
static int test_setenv(const char *name, const char *value) {
#ifdef _WIN32
    return _putenv_s(name, value != NULL ? value : "") == 0 ? 0 : 1;
#else
    if (value == NULL) return unsetenv(name) == 0 ? 0 : 1;
    return setenv(name, value, 1) == 0 ? 0 : 1;
#endif
}

/**
 * Removes one test directory tree.
 * @param path Directory path.
 * @return 0 on success, 1 on failure.
 */
static int test_remove_tree(const char *path) {
#ifdef _WIN32
    WIN32_FIND_DATAA entry;
    char child[512];
    char pattern[512];
    HANDLE search;
    int rc;

    if (snprintf(pattern, sizeof(pattern), "%s\\*", path) < 0 ||
        strlen(pattern) >= sizeof(pattern))
        return 1;
    search = FindFirstFileA(pattern, &entry);
    if (search == INVALID_HANDLE_VALUE)
        return RemoveDirectoryA(path) ? 0 : 1;
    rc = 0;
    do {
        if (strcmp(entry.cFileName, ".") == 0 ||
            strcmp(entry.cFileName, "..") == 0)
            continue;
        if (snprintf(child, sizeof(child), "%s\\%s", path,
            entry.cFileName) < 0 || strlen(child) >= sizeof(child))
        {
            rc = 1;
            continue;
        }
        if (entry.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (test_remove_tree(child) != 0) rc = 1;
        } else if (!DeleteFileA(child)) {
            rc = 1;
        }
    } while (FindNextFileA(search, &entry));
    FindClose(search);
    if (!RemoveDirectoryA(path)) rc = 1;
    return rc;
#else
    struct dirent *entry;
    struct stat st;
    char child[512];
    DIR *dir;
    int rc;

    dir = opendir(path);
    if (!dir) return rmdir(path) == 0 ? 0 : 1;
    rc = 0;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;
        if (snprintf(child, sizeof(child), "%s/%s", path,
            entry->d_name) < 0 || strlen(child) >= sizeof(child))
        {
            rc = 1;
            continue;
        }
        if (lstat(child, &st) != 0) {
            rc = 1;
        } else if (S_ISDIR(st.st_mode)) {
            if (test_remove_tree(child) != 0) rc = 1;
        } else if (unlink(child) != 0) {
            rc = 1;
        }
    }
    closedir(dir);
    if (rmdir(path) != 0) rc = 1;
    return rc;
#endif
}

/**
 * Configures a temporary process-local HOME directory for key files.
 * @return 0 on success, 1 on failure.
 */
static int test_home(void) {
#ifdef _WIN32
    char base[MAX_PATH];
    char path[MAX_PATH];
    DWORD base_len;

    base_len = GetTempPathA(sizeof(base), base);
    if (base_len == 0 || base_len >= sizeof(base)) return 1;
    if (GetTempFileNameA(base, "rpt", 0, path) == 0) return 1;
    if (!DeleteFileA(path) || !CreateDirectoryA(path, NULL)) return 1;
    if (strlen(path) >= sizeof(test_home_path)) {
        RemoveDirectoryA(path);
        return 1;
    }
    strcpy(test_home_path, path);
#else
    const char *base;

    base = getenv("TMPDIR");
    if (!base || !base[0]) base = "/tmp";
    if (snprintf(test_home_path, sizeof(test_home_path),
        "%s/rp2p-test-XXXXXX", base) < 0 ||
        strlen(test_home_path) >= sizeof(test_home_path))
        return 1;
    if (!mkdtemp(test_home_path)) return 1;
#endif
    if (test_setenv("HOME", test_home_path) != 0) {
        test_remove_tree(test_home_path);
        test_home_path[0] = '\0';
        return 1;
    }
    return 0;
}

/**
 * Removes the temporary process-local HOME directory.
 * @return 0 on success, 1 on failure.
 */
static int test_home_cleanup(void) {
    int rc;

    if (!test_home_path[0]) return 0;
    rc = test_remove_tree(test_home_path);
    test_home_path[0] = '\0';
    return rc;
}

/**
 * Starts platform socket state.
 * @return 0 on success, 1 on failure.
 */
static int test_socket_start(void) {
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
static int test_socket_stop(void) {
#ifdef _WIN32
    WSACleanup();
#endif
    return 0;
}

/**
 * Closes a socket.
 * @param fd Socket descriptor.
 * @return 0 on success, non-zero on failure.
 */
static int test_socket_close(test_socket_t fd) {
#ifdef _WIN32
    return closesocket(fd);
#else
    return close(fd);
#endif
}

/**
 * Sets receive timeout on one socket.
 * @param fd Socket descriptor.
 * @param ms Timeout in milliseconds.
 * @return 0 on success.
 */
static int test_socket_timeout(test_socket_t fd, unsigned int ms) {
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
 * Tests whether a loopback TCP port accepts connections.
 * @param port TCP port.
 * @return 1 when open, 0 when closed.
 */
static int test_port_open(unsigned short port) {
    test_socket_t fd;
    struct sockaddr_in addr;
    int rc;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == TEST_SOCKET_INVALID) return 0;
    test_socket_timeout(fd, 250U);
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    rc = connect(fd, (const struct sockaddr *)&addr, sizeof(addr));
    test_socket_close(fd);
    return rc == 0 ? 1 : 0;
}

/**
 * Waits for a TCP port to reach an expected state.
 * @param port TCP port.
 * @param open Expected state.
 * @return 1 when observed, 0 on timeout.
 */
static int test_wait_port(unsigned short port, int open) {
    int i;

    for (i = 0; i < 80; i++) {
        if (test_port_open(port) == open) return 1;
        test_sleep_ms(100U);
    }
    return 0;
}

/**
 * Checks one integer value.
 * @param name Check name.
 * @param expected Expected value.
 * @param actual Actual value.
 * @return 0 on success, 1 on failure.
 */
static int expect_int(const char *name, int expected, int actual) {
    if (expected != actual) {
        printf("[FAIL] %s: expected %d, got %d\n", name, expected, actual);
        return 1;
    }
    printf("[PASS] %s\n", name);
    return 0;
}

/**
 * Checks one true condition.
 * @param name Check name.
 * @param condition Condition value.
 * @return 0 on success, 1 on failure.
 */
static int expect_true(const char *name, int condition) {
    if (!condition) {
        printf("[FAIL] %s\n", name);
        return 1;
    }
    printf("[PASS] %s\n", name);
    return 0;
}

/**
 * Checks one string value.
 * @param name Check name.
 * @param expected Expected string.
 * @param actual Actual string.
 * @return 0 on success, 1 on failure.
 */
static int expect_string(const char *name, const char *expected, const char *actual) {
    if (actual == NULL || strcmp(expected, actual) != 0) {
        printf("[FAIL] %s: expected '%s', got '%s'\n", name, expected,
            actual != NULL ? actual : "NULL");
        return 1;
    }
    printf("[PASS] %s\n", name);
    return 0;
}

/**
 * Records a signal callback invocation.
 * @param ctx Context passed by the library.
 * @return None.
 */
static void test_signal_cb(rp2p_t *ctx) {
    signal_count++;
    signal_ctx = ctx;
}

/**
 * Runs one loopback UDP echo backend until stopped.
 * @param arg Echo backend state.
 * @return None.
 */
static void test_udp_echo_run(void *arg) {
    test_udp_echo_t *echo;
    unsigned char buf[2048];

    echo = (test_udp_echo_t *)arg;
    while (!echo->stop) {
        struct sockaddr_storage from;
        test_socklen_t from_len;
        int n;

        from_len = sizeof(from);
        n = (int)recvfrom(echo->fd, (char *)buf, sizeof(buf), 0,
            (struct sockaddr *)&from, &from_len);
        if (n < 0) continue;
        sendto(echo->fd, (const char *)buf, (size_t)n, 0,
            (const struct sockaddr *)&from, from_len);
    }
}

/**
 * Runs one loopback TCP echo backend until stopped.
 * @param arg Echo backend state.
 * @return None.
 */
static void test_tcp_echo_run(void *arg) {
    test_tcp_echo_t *echo;

    echo = (test_tcp_echo_t *)arg;
    while (!echo->stop) {
        test_socket_t client;
        unsigned char buf[1024];
        int n;

        client = accept(echo->fd, NULL, NULL);
        if (client == TEST_SOCKET_INVALID) continue;
        test_socket_timeout(client, 100U);
        while (!echo->stop) {
            n = (int)recv(client, (char *)buf, sizeof(buf), 0);
            if (n > 0) {
                send(client, (const char *)buf, n, 0);
                continue;
            }
            if (n == 0) break;
        }
        test_socket_close(client);
    }
}

#ifdef _WIN32
/**
 * Runs an index server thread.
 * @param arg Thread argument.
 * @return Thread status.
 */
static DWORD WINAPI test_index_main(void *arg) {
    test_index_t *index;

    index = (test_index_t *)arg;
    index->result = rp2p_serve_index(index->ctx, NULL, index->port);
    return 0;
}

/**
 * Runs a publisher thread.
 * @param arg Thread argument.
 * @return Thread status.
 */
static DWORD WINAPI test_publisher_main(void *arg) {
    test_publisher_t *publisher;

    publisher = (test_publisher_t *)arg;
    rp2p_set_protocol(publisher->ctx, publisher->protocol);
    rp2p_set_port(publisher->ctx, publisher->bind_port);
    if (publisher->pass != NULL) rp2p_set_pass(publisher->ctx, publisher->pass);
    if (publisher->secret != NULL)
        rp2p_set_secret(publisher->ctx, publisher->secret);
    publisher->result = rp2p_wait(publisher->ctx, publisher->host,
        publisher->index_port, publisher->id, publisher->bind_port);
    return 0;
}

/**
 * Runs a consumer thread.
 * @param arg Thread argument.
 * @return Thread status.
 */
static DWORD WINAPI test_consumer_main(void *arg) {
    test_consumer_t *consumer;

    consumer = (test_consumer_t *)arg;
    rp2p_set_protocol(consumer->ctx, consumer->protocol);
    rp2p_set_port(consumer->ctx, consumer->bind_port);
    if (consumer->secret != NULL)
        rp2p_set_secret(consumer->ctx, consumer->secret);
    consumer->result = rp2p_connect(consumer->ctx, consumer->host,
        consumer->index_port, consumer->self_id, consumer->target_id,
        consumer->bind_port);
    return 0;
}

/**
 * Runs a UDP echo backend thread.
 * @param arg Thread argument.
 * @return Thread status.
 */
static DWORD WINAPI test_udp_echo_main(void *arg) {
    test_udp_echo_run(arg);
    return 0;
}

/**
 * Runs a TCP echo backend thread.
 * @param arg Thread argument.
 * @return Thread status.
 */
static DWORD WINAPI test_tcp_echo_main(void *arg) {
    test_tcp_echo_run(arg);
    return 0;
}
#else
/**
 * Runs an index server thread.
 * @param arg Thread argument.
 * @return Thread status.
 */
static void *test_index_main(void *arg) {
    test_index_t *index;

    index = (test_index_t *)arg;
    index->result = rp2p_serve_index(index->ctx, NULL, index->port);
    return NULL;
}

/**
 * Runs a publisher thread.
 * @param arg Thread argument.
 * @return Thread status.
 */
static void *test_publisher_main(void *arg) {
    test_publisher_t *publisher;

    publisher = (test_publisher_t *)arg;
    rp2p_set_protocol(publisher->ctx, publisher->protocol);
    rp2p_set_port(publisher->ctx, publisher->bind_port);
    if (publisher->pass != NULL) rp2p_set_pass(publisher->ctx, publisher->pass);
    if (publisher->secret != NULL)
        rp2p_set_secret(publisher->ctx, publisher->secret);
    publisher->result = rp2p_wait(publisher->ctx, publisher->host,
        publisher->index_port, publisher->id, publisher->bind_port);
    return NULL;
}

/**
 * Runs a consumer thread.
 * @param arg Thread argument.
 * @return NULL.
 */
static void *test_consumer_main(void *arg) {
    test_consumer_t *consumer;

    consumer = (test_consumer_t *)arg;
    rp2p_set_protocol(consumer->ctx, consumer->protocol);
    rp2p_set_port(consumer->ctx, consumer->bind_port);
    if (consumer->secret != NULL)
        rp2p_set_secret(consumer->ctx, consumer->secret);
    consumer->result = rp2p_connect(consumer->ctx, consumer->host,
        consumer->index_port, consumer->self_id, consumer->target_id,
        consumer->bind_port);
    return NULL;
}

/**
 * Runs a UDP echo backend thread.
 * @param arg Thread argument.
 * @return NULL.
 */
static void *test_udp_echo_main(void *arg) {
    test_udp_echo_run(arg);
    return NULL;
}

/**
 * Runs a TCP echo backend thread.
 * @param arg Thread argument.
 * @return NULL.
 */
static void *test_tcp_echo_main(void *arg) {
    test_tcp_echo_run(arg);
    return NULL;
}
#endif

/**
 * Starts one thread.
 * @param thread Output thread handle.
 * @param fn Thread entry point.
 * @param arg Thread argument.
 * @return 0 on success, 1 on failure.
 */
static int test_thread_start(test_thread_t *thread,
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
 * Joins one thread.
 * @param thread Thread handle.
 * @return 0 on success, 1 on failure.
 */
static int test_thread_join(test_thread_t thread) {
#ifdef _WIN32
    if (WaitForSingleObject(thread, 15000U) != WAIT_OBJECT_0) return 1;
    CloseHandle(thread);
    return 0;
#else
    return pthread_join(thread, NULL) == 0 ? 0 : 1;
#endif
}

/**
 * Starts an index server on a port.
 * @param index Index state.
 * @param port TCP port.
 * @return 0 on success, 1 on failure.
 */
static int test_index_start(test_index_t *index, unsigned short port) {
    memset(index, 0, sizeof(*index));
    index->port = port;
    if (rp2p_open(&index->ctx) != RP2P_OK) return 1;
    if (test_thread_start(&index->thread, test_index_main, index) != 0) return 1;
    return test_wait_port(port, 1) ? 0 : 1;
}

/**
 * Stops an index server.
 * @param index Index state.
 * @return 0 on success.
 */
static int test_index_stop(test_index_t *index) {
    if (index->ctx != NULL) rp2p_stop(index->ctx);
    test_thread_join(index->thread);
    if (index->ctx != NULL) rp2p_close(index->ctx);
    index->ctx = NULL;
    return 0;
}

/**
 * Starts a publisher context.
 * @param publisher Publisher state.
 * @param id Publisher id.
 * @param index_port Index control port.
 * @param bind_port Backend port value.
 * @return 0 on success, 1 on failure.
 */
static int test_publisher_start(test_publisher_t *publisher, const char *id,
unsigned short index_port, unsigned short bind_port)
{
    memset(publisher, 0, sizeof(*publisher));
    publisher->host = TEST_HOST;
    publisher->index_port = index_port;
    publisher->id = id;
    publisher->bind_port = bind_port;
    publisher->protocol = RP2P_PROTO_TCP;
    if (rp2p_open(&publisher->ctx) != RP2P_OK) return 1;
    if (test_thread_start(&publisher->thread, test_publisher_main,
        publisher) != 0) return 1;
    test_sleep_ms(800U);
    return 0;
}

/**
 * Stops a publisher context.
 * @param publisher Publisher state.
 * @return 0 on success.
 */
static int test_publisher_stop(test_publisher_t *publisher) {
    if (publisher->ctx != NULL) rp2p_stop(publisher->ctx);
    test_thread_join(publisher->thread);
    if (publisher->ctx != NULL) rp2p_close(publisher->ctx);
    publisher->ctx = NULL;
    return 0;
}

/**
 * Starts a UDP publisher with optional tunnel authentication.
 * @return 0 on success, 1 on failure.
 */
static int test_udp_publisher_start(test_publisher_t *publisher,
    const char *id, unsigned short index_port, unsigned short bind_port,
    const char *secret)
{
    memset(publisher, 0, sizeof(*publisher));
    publisher->host = TEST_HOST;
    publisher->index_port = index_port;
    publisher->id = id;
    publisher->bind_port = bind_port;
    publisher->protocol = RP2P_PROTO_UDP;
    publisher->secret = secret;
    if (rp2p_open(&publisher->ctx) != RP2P_OK) return 1;
    if (test_thread_start(&publisher->thread, test_publisher_main,
        publisher) != 0)
        return 1;
    test_sleep_ms(800U);
    return 0;
}

/**
 * Starts a UDP consumer with optional tunnel authentication.
 * @return 0 on success, 1 on failure.
 */
static int test_udp_consumer_start(test_consumer_t *consumer,
    const char *self_id, const char *target_id, unsigned short index_port,
    unsigned short bind_port, const char *secret)
{
    memset(consumer, 0, sizeof(*consumer));
    consumer->host = TEST_HOST;
    consumer->index_port = index_port;
    consumer->self_id = self_id;
    consumer->target_id = target_id;
    consumer->bind_port = bind_port;
    consumer->protocol = RP2P_PROTO_UDP;
    consumer->secret = secret;
    consumer->result = 999;
    if (rp2p_open(&consumer->ctx) != RP2P_OK) return 1;
    if (test_thread_start(&consumer->thread, test_consumer_main,
        consumer) != 0)
        return 1;
    test_sleep_ms(400U);
    return 0;
}

/**
 * Stops one consumer context.
 * @return 0 on success.
 */
static int test_consumer_stop(test_consumer_t *consumer) {
    if (consumer->ctx != NULL) rp2p_stop(consumer->ctx);
    test_thread_join(consumer->thread);
    if (consumer->ctx != NULL) rp2p_close(consumer->ctx);
    consumer->ctx = NULL;
    return 0;
}

/**
 * Starts one loopback UDP echo backend.
 * @return 0 on success, 1 on failure.
 */
static int test_udp_echo_start(test_udp_echo_t *echo, unsigned short port) {
    struct sockaddr_in addr;

    memset(echo, 0, sizeof(*echo));
    echo->port = port;
    echo->fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (echo->fd == TEST_SOCKET_INVALID) return 1;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(echo->fd, (const struct sockaddr *)&addr, sizeof(addr)) != 0) {
        test_socket_close(echo->fd);
        return 1;
    }
    test_socket_timeout(echo->fd, 100U);
    return test_thread_start(&echo->thread, test_udp_echo_main, echo);
}

/**
 * Stops one loopback UDP echo backend.
 * @return 0 on success.
 */
static int test_udp_echo_stop(test_udp_echo_t *echo) {
    echo->stop = 1;
    test_thread_join(echo->thread);
    test_socket_close(echo->fd);
    echo->fd = TEST_SOCKET_INVALID;
    return 0;
}

/**
 * Starts one loopback TCP echo backend.
 * @return 0 on success, 1 on failure.
 */
static int test_tcp_echo_start(test_tcp_echo_t *echo, unsigned short port) {
    struct sockaddr_in addr;
    int reuse;

    memset(echo, 0, sizeof(*echo));
    echo->port = port;
    echo->fd = socket(AF_INET, SOCK_STREAM, 0);
    if (echo->fd == TEST_SOCKET_INVALID) return 1;
    reuse = 1;
    setsockopt(echo->fd, SOL_SOCKET, SO_REUSEADDR, (const char *)&reuse,
        sizeof(reuse));
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(echo->fd, (const struct sockaddr *)&addr, sizeof(addr)) != 0 ||
        listen(echo->fd, 8) != 0)
    {
        test_socket_close(echo->fd);
        return 1;
    }
    test_socket_timeout(echo->fd, 100U);
    return test_thread_start(&echo->thread, test_tcp_echo_main, echo);
}

/**
 * Stops one loopback TCP echo backend.
 * @return 0 on success.
 */
static int test_tcp_echo_stop(test_tcp_echo_t *echo) {
    echo->stop = 1;
    test_thread_join(echo->thread);
    test_socket_close(echo->fd);
    echo->fd = TEST_SOCKET_INVALID;
    return 0;
}

/**
 * Starts one authenticated TCP publisher context.
 * @return 0 on success, 1 on failure.
 */
static int test_tcp_publisher_start(test_publisher_t *publisher,
    const char *id, unsigned short index_port, unsigned short bind_port,
    const char *secret)
{
    memset(publisher, 0, sizeof(*publisher));
    publisher->host = TEST_HOST;
    publisher->index_port = index_port;
    publisher->id = id;
    publisher->bind_port = bind_port;
    publisher->protocol = RP2P_PROTO_TCP;
    publisher->secret = secret;
    publisher->result = 999;
    if (rp2p_open(&publisher->ctx) != RP2P_OK) return 1;
    if (test_thread_start(&publisher->thread, test_publisher_main,
        publisher) != 0)
        return 1;
    test_sleep_ms(800U);
    return 0;
}

/**
 * Starts one authenticated TCP consumer context.
 * @return 0 on success, 1 on failure.
 */
static int test_tcp_consumer_start(test_consumer_t *consumer,
    const char *self_id, const char *target_id, unsigned short index_port,
    unsigned short bind_port, const char *secret)
{
    memset(consumer, 0, sizeof(*consumer));
    consumer->host = TEST_HOST;
    consumer->index_port = index_port;
    consumer->self_id = self_id;
    consumer->target_id = target_id;
    consumer->bind_port = bind_port;
    consumer->protocol = RP2P_PROTO_TCP;
    consumer->secret = secret;
    consumer->result = 999;
    if (rp2p_open(&consumer->ctx) != RP2P_OK) return 1;
    if (test_thread_start(&consumer->thread, test_consumer_main,
        consumer) != 0)
        return 1;
    test_sleep_ms(800U);
    return 0;
}

/**
 * Sends bytes through one local TCP adapter and waits for their echo.
 * @return Received byte count, or -1 on failure.
 */
static int test_tcp_roundtrip(unsigned short port, const unsigned char *data,
    size_t len)
{
    test_socket_t fd;
    struct sockaddr_in addr;
    unsigned char received[1024];
    unsigned int attempt;
    int n;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    fd = TEST_SOCKET_INVALID;
    for (attempt = 0; attempt < 20U; attempt++) {
        fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd == TEST_SOCKET_INVALID) return -1;
        test_socket_timeout(fd, 3000U);
        if (connect(fd, (const struct sockaddr *)&addr, sizeof(addr)) == 0)
            break;
        test_socket_close(fd);
        fd = TEST_SOCKET_INVALID;
        test_sleep_ms(100U);
    }
    if (fd == TEST_SOCKET_INVALID) return -1;
    if (send(fd, (const char *)data, (int)len, 0) != (int)len) {
        test_socket_close(fd);
        return -1;
    }
    n = (int)recv(fd, (char *)received, sizeof(received), 0);
    test_socket_close(fd);
    if (n != (int)len || memcmp(received, data, len) != 0) return -1;
    return n;
}

/**
 * Sends one UDP datagram and waits for its echo.
 * @return Received length, or -1 on timeout or mismatch.
 */
static int test_udp_roundtrip(unsigned short port, const unsigned char *data,
    size_t len, unsigned int timeout_ms)
{
    test_socket_t fd;
    struct sockaddr_in addr;
    unsigned char received[RP2P_UDP_PAYLOAD_MAX + 1];
    unsigned int attempts;
    unsigned int i;
    int n;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == TEST_SOCKET_INVALID) return -1;
    test_socket_timeout(fd, 500U);
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    attempts = timeout_ms / 500U;
    if (attempts == 0) attempts = 1;
    n = -1;
    for (i = 0; i < attempts; i++) {
        if (sendto(fd, (const char *)data, len, 0,
            (const struct sockaddr *)&addr, sizeof(addr)) < 0)
            continue;
        n = (int)recvfrom(fd, (char *)received, sizeof(received), 0,
            NULL, NULL);
        if (n >= 0) break;
    }
    test_socket_close(fd);
    if (n < 0 || (size_t)n != len) {
        fprintf(stderr, "udp roundtrip length: sent=%lu received=%d\n",
            (unsigned long)len, n);
        return -1;
    }
    if (len > 0 && memcmp(received, data, len) != 0) {
        fprintf(stderr, "udp roundtrip payload mismatch\n");
        return -1;
    }
    return n;
}

/**
 * Sends one UDP datagram without waiting for a response.
 * @return 0 on success, 1 on failure.
 */
static int test_udp_send_only(unsigned short port, const unsigned char *data,
    size_t len)
{
    test_socket_t fd;
    struct sockaddr_in addr;
    int result;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == TEST_SOCKET_INVALID) return 1;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    result = sendto(fd, (const char *)data, len, 0,
        (const struct sockaddr *)&addr, sizeof(addr)) < 0;
    test_socket_close(fd);
    return result;
}

/**
 * Records one publisher id.
 * @param id Publisher id.
 * @param userdata Publisher collection.
 * @return None.
 */
static void test_on_publisher(const char *id, void *userdata) {
    test_publishers_t *publishers;

    publishers = (test_publishers_t *)userdata;
    if (publishers->count >= 8) return;
    strncpy(publishers->ids[publishers->count], id, RP2P_ID_MAX);
    publishers->ids[publishers->count][RP2P_ID_MAX] = '\0';
    publishers->count++;
}

/**
 * Returns whether one publisher id was recorded.
 * @param publishers Publisher collection.
 * @param id Publisher id.
 * @return 1 when present, 0 otherwise.
 */
static int test_has_publisher(test_publishers_t *publishers, const char *id) {
    int i;

    for (i = 0; i < publishers->count; i++) {
        if (strcmp(publishers->ids[i], id) == 0) return 1;
    }
    return 0;
}

/**
 * Tests rp2p_options_default.
 * @return 0 on success, 1 on failure.
 */
static int case_rp2p_options_default(void) {
    rp2p_options_t opts;
    int rc;

    rc = 0;
    opts = rp2p_options_default();
    rc += expect_int("default seats", RP2P_MAX_PEERS, opts.seats);
    rc += expect_int("default pow", 0, opts.pow);
    rc += expect_int("default sweep", 20, opts.sweep);
    rc += expect_true("default vip is NULL", opts.vip == NULL);
    rc += expect_true("default pass is empty", opts.pass[0] == '\0');
    rc += expect_true("default secret is empty", opts.secret[0] == '\0');
    return rc == 0 ? 0 : 1;
}

/**
 * Tests rp2p_options_load_env.
 * @return 0 on success, 1 on failure.
 */
static int case_rp2p_options_load_env(void) {
    rp2p_options_t opts;
    int rc;

    rc = 0;
    opts = rp2p_options_default();
    test_setenv("RP2P_SEATS", "7");
    test_setenv("RP2P_POW", "3");
    test_setenv("RP2P_PASS", "secret");
    test_setenv("RP2P_SECRET", "tunnel-secret");
    test_setenv("RP2P_VIP", "vip vip-pass");
    test_setenv("RP2P_SWEEP", "9");
    test_setenv("RP2P_STUN", "stun:example.com:3478");
    rp2p_options_load_env(&opts);
    rc += expect_int("env seats", 7, opts.seats);
    rc += expect_int("env pow", 3, opts.pow);
    rc += expect_string("env pass", "secret", opts.pass);
    rc += expect_string("env secret", "tunnel-secret", opts.secret);
    rc += expect_string("env vip", "vip vip-pass", opts.vip);
    rc += expect_int("env sweep", 9, opts.sweep);
    rc += expect_string("env stun", "stun:example.com:3478", opts.stun_url);
    rp2p_options_load_env(NULL);
    rp2p_options_free(&opts);
    test_setenv("RP2P_SEATS", NULL);
    test_setenv("RP2P_POW", NULL);
    test_setenv("RP2P_PASS", NULL);
    test_setenv("RP2P_SECRET", NULL);
    test_setenv("RP2P_VIP", NULL);
    test_setenv("RP2P_SWEEP", NULL);
    test_setenv("RP2P_STUN", NULL);
    return rc == 0 ? 0 : 1;
}

/**
 * Tests rp2p_options_load_env strict rejection.
 * Summary: Invalid numeric environment values are ignored and keep defaults.
 * @return 0 on success, 1 on failure.
 */
static int case_rp2p_options_load_env_invalid(void) {
    static const char *invalid[] = {
        "+1", "-1", " 1", "1 ", "1x", "",
        "999999999999999999999999", "65536"
    };
    rp2p_options_t opts;
    int rc;
    size_t i;

    rc = 0;
    for (i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
        opts = rp2p_options_default();
        test_setenv("RP2P_SEATS", invalid[i]);
        test_setenv("RP2P_POW", invalid[i]);
        test_setenv("RP2P_SWEEP", invalid[i]);
        rp2p_options_load_env(&opts);
        rc += expect_int("invalid seats kept default", RP2P_MAX_PEERS,
            opts.seats);
        rc += expect_int("invalid pow kept default", 0, opts.pow);
        rc += expect_int("invalid sweep kept default", 20, opts.sweep);
        rp2p_options_free(&opts);
    }
    opts = rp2p_options_default();
    test_setenv("RP2P_SEATS", "0");
    test_setenv("RP2P_POW", "0");
    test_setenv("RP2P_SWEEP", "0");
    rp2p_options_load_env(&opts);
    rc += expect_int("zero seats accepted", 0, opts.seats);
    rc += expect_int("zero pow accepted", 0, opts.pow);
    rc += expect_int("zero sweep accepted", 0, opts.sweep);
    rp2p_options_free(&opts);
    test_setenv("RP2P_SEATS", NULL);
    test_setenv("RP2P_POW", NULL);
    test_setenv("RP2P_SWEEP", NULL);
    return rc == 0 ? 0 : 1;
}

/**
 * Tests rp2p_options_free.
 * @return 0 on success, 1 on failure.
 */
static int case_rp2p_options_free(void) {
    rp2p_options_t opts;
    int rc;

    rc = 0;
    opts = rp2p_options_default();
    test_setenv("RP2P_VIP", "one pass");
    rp2p_options_load_env(&opts);
    rc += expect_true("vip allocated", opts.vip != NULL);
    rp2p_options_free(&opts);
    rc += expect_true("vip cleared", opts.vip == NULL);
    rp2p_options_free(&opts);
    rp2p_options_free(NULL);
    test_setenv("RP2P_VIP", NULL);
    return rc == 0 ? 0 : 1;
}

/**
 * Tests rp2p_open.
 * @return 0 on success, 1 on failure.
 */
static int case_rp2p_open(void) {
    rp2p_t *ctx;
    int rc;

    rc = 0;
    ctx = NULL;
    rc += expect_int("open NULL", RP2P_ERROR, rp2p_open(NULL));
    rc += expect_int("open context", RP2P_OK, rp2p_open(&ctx));
    rc += expect_true("context is set", ctx != NULL);
    if (ctx != NULL) rp2p_close(ctx);
    return rc == 0 ? 0 : 1;
}

/**
 * Tests rp2p_close.
 * @return 0 on success, 1 on failure.
 */
static int case_rp2p_close(void) {
    rp2p_t *ctx;
    int rc;

    rc = 0;
    rc += expect_int("close NULL", RP2P_ERROR, rp2p_close(NULL));
    rc += expect_int("open context", RP2P_OK, rp2p_open(&ctx));
    rc += expect_int("close context", RP2P_OK, rp2p_close(ctx));
    return rc == 0 ? 0 : 1;
}

/**
 * Tests rp2p_stop.
 * @return 0 on success, 1 on failure.
 */
static int case_rp2p_stop(void) {
    rp2p_t *ctx;
    int rc;

    rc = 0;
    rc += expect_int("stop NULL", RP2P_ERROR, rp2p_stop(NULL));
    rc += expect_int("open context", RP2P_OK, rp2p_open(&ctx));
    rc += expect_int("stop context", RP2P_OK, rp2p_stop(ctx));
    rc += expect_int("stop context twice", RP2P_OK, rp2p_stop(ctx));
    rp2p_close(ctx);
    return rc == 0 ? 0 : 1;
}

/**
 * Tests rp2p_version.
 * @return 0 on success, 1 on failure.
 */
static int case_rp2p_version(void) {
    return expect_true("version is available", rp2p_version() != 0U);
}

/**
 * Tests rp2p_strerror.
 * @return 0 on success, 1 on failure.
 */
static int case_rp2p_strerror(void) {
    int rc;

    rc = 0;
    rc += expect_string("OK text", "OK", rp2p_strerror(RP2P_OK));
    rc += expect_string("ERROR text", "general error", rp2p_strerror(RP2P_ERROR));
    rc += expect_string("ENET text", "network error", rp2p_strerror(RP2P_ENET));
    rc += expect_string("ENOENT text", "peer not found", rp2p_strerror(RP2P_ENOENT));
    rc += expect_string("ETIMEOUT text", "timeout", rp2p_strerror(RP2P_ETIMEOUT));
    rc += expect_string("EFULL text", "peer table full", rp2p_strerror(RP2P_EFULL));
    rc += expect_string("EINVAL text", "invalid argument",
        rp2p_strerror(RP2P_EINVAL));
    rc += expect_string("EPROTO text", "protocol error",
        rp2p_strerror(RP2P_EPROTO));
    rc += expect_string("EAUTH text", "authentication failed",
        rp2p_strerror(RP2P_EAUTH));
    rc += expect_string("EVERSION text", "unsupported protocol version",
        rp2p_strerror(RP2P_EVERSION));
    rc += expect_string("EPUNCH text", "direct connectivity failed",
        rp2p_strerror(RP2P_EPUNCH));
    rc += expect_string("ECRYPTO text", "cryptographic failure",
        rp2p_strerror(RP2P_ECRYPTO));
    rc += expect_string("unknown text", "unknown error", rp2p_strerror(999));
    return rc == 0 ? 0 : 1;
}

/**
 * Tests rp2p_is_valid_id.
 * @return 0 on success, 1 on failure.
 */
static int case_rp2p_is_valid_id(void) {
    int rc;

    rc = 0;
    rc += expect_int("alphanumeric id", 1, rp2p_is_valid_id("abcXYZ123"));
    rc += expect_int("single id", 1, rp2p_is_valid_id("a"));
    rc += expect_int("NULL id", 0, rp2p_is_valid_id(NULL));
    rc += expect_int("empty id", 0, rp2p_is_valid_id(""));
    rc += expect_int("punctuation id", 0, rp2p_is_valid_id("bad:id"));
    rc += expect_int("space id", 0, rp2p_is_valid_id("bad id"));
    rc += expect_int("long id", 0, rp2p_is_valid_id(
        "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz"));
    return rc == 0 ? 0 : 1;
}

/**
 * Tests rp2p_is_valid_pass_token.
 * @return 0 on success, 1 on failure.
 */
static int case_rp2p_is_valid_pass_token(void) {
    int rc;

    rc = 0;
    rc += expect_int("safe pass", 1, rp2p_is_valid_pass_token("a._-+=,:@%/"));
    rc += expect_int("single pass", 1, rp2p_is_valid_pass_token("x"));
    rc += expect_int("NULL pass", 0, rp2p_is_valid_pass_token(NULL));
    rc += expect_int("empty pass", 0, rp2p_is_valid_pass_token(""));
    rc += expect_int("space pass", 0, rp2p_is_valid_pass_token("bad pass"));
    rc += expect_int("unsafe pass", 0, rp2p_is_valid_pass_token("bad`pass"));
    return rc == 0 ? 0 : 1;
}

/**
 * Tests rp2p_serve_index.
 * @return 0 on success, 1 on failure.
 */
static int case_rp2p_serve_index(void) {
    test_index_t index;
    unsigned short port;
    int rc;

    rc = 0;
    port = (unsigned short)(test_port_base() + 1U);
    rc += expect_int("serve NULL", RP2P_EINVAL,
        rp2p_serve_index(NULL, TEST_HOST, port));
    if (test_index_start(&index, port) != 0) return 1;
    rc += expect_true("index accepts TCP", test_port_open(port));
    test_index_stop(&index);
    rc += expect_int("stopped index result", RP2P_OK, index.result);
    rc += expect_true("index port closed", test_wait_port(port, 0));
    return rc == 0 ? 0 : 1;
}

/**
 * Tests rp2p_wait.
 * @return 0 on success, 1 on failure.
 */
static int case_rp2p_wait(void) {
    test_index_t index;
    test_publisher_t publisher;
    rp2p_t *ctx;
    unsigned short base;
    int rc;

    rc = 0;
    base = (unsigned short)(test_port_base() + 20U);
    rc += expect_int("wait NULL", RP2P_EINVAL,
        rp2p_wait(NULL, TEST_HOST, base, "pub", (unsigned short)(base + 1U)));
    rc += expect_int("open context", RP2P_OK, rp2p_open(&ctx));
    rc += expect_int("wait without index", RP2P_ENET,
        rp2p_wait(ctx, TEST_HOST, base, "pub", (unsigned short)(base + 1U)));
    rp2p_close(ctx);
    if (test_index_start(&index, (unsigned short)(base + 2U)) != 0) return 1;
    if (test_publisher_start(&publisher, "waitpub", (unsigned short)(base + 2U),
        (unsigned short)(base + 3U)) != 0) return 1;
    rc += expect_true("publisher remains running", publisher.result == 0);
    test_publisher_stop(&publisher);
    test_index_stop(&index);
    return rc == 0 ? 0 : 1;
}

/**
 * Tests rp2p_connect.
 * @return 0 on success, 1 on failure.
 */
static int case_rp2p_connect(void) {
    test_index_t index;
    rp2p_t *ctx;
    unsigned short base;
    int rc;

    rc = 0;
    base = (unsigned short)(test_port_base() + 40U);
    rc += expect_int("connect NULL", RP2P_EINVAL,
        rp2p_connect(NULL, TEST_HOST, base, "client", "missing",
            (unsigned short)(base + 1U)));
    rc += expect_int("open context", RP2P_OK, rp2p_open(&ctx));
    rp2p_set_port(ctx, (unsigned short)(base + 1U));
    rc += expect_int("connect without index", RP2P_ENET,
        rp2p_connect(ctx, TEST_HOST, base, "client", "missing",
            (unsigned short)(base + 1U)));
    rp2p_close(ctx);
    if (test_index_start(&index, (unsigned short)(base + 2U)) != 0) return 1;
    rc += expect_int("open context", RP2P_OK, rp2p_open(&ctx));
    rp2p_set_port(ctx, (unsigned short)(base + 3U));
    rc += expect_int("connect missing target", RP2P_ENOENT,
        rp2p_connect(ctx, TEST_HOST, (unsigned short)(base + 2U), "client",
            "missing", (unsigned short)(base + 3U)));
    rp2p_close(ctx);
    test_index_stop(&index);
    return rc == 0 ? 0 : 1;
}

/**
 * Runs one public-API UDP tunnel security and payload regression scenario.
 * @return 0 on success, 1 on failure.
 */
static int test_udp_tunnel_case(const char *publisher_secret,
    const char *consumer_secret, int expect_success, int test_limits,
    unsigned short port_offset)
{
    test_index_t index;
    test_publisher_t publisher;
    test_consumer_t consumer;
    test_udp_echo_t echo;
    unsigned char payload[RP2P_UDP_PAYLOAD_MAX + 1];
    unsigned short base;
    unsigned int elapsed;
    int rc;

    rc = 0;
    base = (unsigned short)(test_port_base() + 300U + port_offset);
    memset(payload, 0x5a, sizeof(payload));
    rc += expect_int("start UDP echo", 0,
        test_udp_echo_start(&echo, (unsigned short)(base + 1U)));
    rc += expect_int("start UDP index", 0, test_index_start(&index, base));
    rc += expect_int("start UDP publisher", 0,
        test_udp_publisher_start(&publisher, "udppub", base,
            (unsigned short)(base + 1U), publisher_secret));
    rc += expect_int("start UDP consumer", 0,
        test_udp_consumer_start(&consumer, "udpclient", "udppub", base,
            (unsigned short)(base + 2U), consumer_secret));
    if (rc == 0 && expect_success) {
        int small_result = test_udp_roundtrip(
            (unsigned short)(base + 2U), payload, 3, 3000U);
        rc += expect_int("UDP small datagram", 3, small_result);
        if (small_result < 0)
            fprintf(stderr,
                "consumer result: %d error: %s\npublisher result: %d error: %s\n",
                consumer.result, rp2p_get_error(consumer.ctx),
                publisher.result, rp2p_get_error(publisher.ctx));
        rc += expect_int("UDP empty datagram", 0,
            test_udp_roundtrip((unsigned short)(base + 2U), payload, 0, 3000U));
        if (test_limits) {
            rc += expect_int("UDP maximum datagram", RP2P_UDP_PAYLOAD_MAX,
                test_udp_roundtrip((unsigned short)(base + 2U), payload,
                    RP2P_UDP_PAYLOAD_MAX, 3000U));
            rc += expect_int("send UDP oversized datagram", 0,
                test_udp_send_only((unsigned short)(base + 2U), payload,
                    RP2P_UDP_PAYLOAD_MAX + 1));
            for (elapsed = 0; elapsed < 2000U; elapsed += 50U) {
                if (strstr(rp2p_get_error(consumer.ctx),
                    "exceeds maximum") != NULL)
                    break;
                test_sleep_ms(50U);
            }
            rc += expect_true("UDP oversized datagram rejected",
                rp2p_get_error(consumer.ctx)[0] != '\0');
            rc += expect_true("UDP oversized detail",
                strstr(rp2p_get_error(consumer.ctx), "exceeds maximum") != NULL);
        }
    } else if (rc == 0) {
        rc += expect_int("send UDP mismatch probe", 0,
            test_udp_send_only((unsigned short)(base + 2U), payload, 3));
        for (elapsed = 0; elapsed < 2000U; elapsed += 100U) {
            if (rp2p_get_error(consumer.ctx)[0] != '\0' ||
                rp2p_get_error(publisher.ctx)[0] != '\0')
                break;
            test_sleep_ms(100U);
            test_udp_send_only((unsigned short)(base + 2U), payload, 3);
        }
        rc += expect_true("UDP security mismatch rejected",
            rp2p_get_error(consumer.ctx)[0] != '\0' ||
            rp2p_get_error(publisher.ctx)[0] != '\0');
        rc += expect_true("UDP security mismatch detail",
            rp2p_get_error(consumer.ctx)[0] != '\0' ||
            rp2p_get_error(publisher.ctx)[0] != '\0');
    }
    test_consumer_stop(&consumer);
    test_publisher_stop(&publisher);
    test_index_stop(&index);
    test_udp_echo_stop(&echo);
    return rc == 0 ? 0 : 1;
}

/**
 * Tests plaintext UDP negotiation, empty datagrams, and MTU enforcement.
 * @return 0 on success, 1 on failure.
 */
static int case_rp2p_udp_plain(void) {
    return test_udp_tunnel_case(NULL, NULL, 1, 1, 0);
}

/**
 * Tests authenticated UDP negotiation and encrypted datagrams.
 * @return 0 on success, 1 on failure.
 */
static int case_rp2p_udp_secure(void) {
    return test_udp_tunnel_case("secret", "secret", 1, 1, 10);
}

/**
 * Tests rejection when only the publisher requires UDP security.
 * @return 0 on success, 1 on failure.
 */
static int case_rp2p_udp_secure_publisher(void) {
    return test_udp_tunnel_case("secret", NULL, 0, 0, 20);
}

/**
 * Tests rejection when only the consumer requires UDP security.
 * @return 0 on success, 1 on failure.
 */
static int case_rp2p_udp_secure_consumer(void) {
    return test_udp_tunnel_case(NULL, "secret", 0, 0, 30);
}

/**
 * Tests rejection when UDP peers use different secrets.
 * @return 0 on success, 1 on failure.
 */
static int case_rp2p_udp_secret_mismatch(void) {
    return test_udp_tunnel_case("secret", "other", 0, 0, 40);
}

/**
 * Runs one public-API TCP authentication regression scenario.
 * @return 0 on success, 1 on failure.
 */
static int test_tcp_tunnel_case(const char *publisher_secret,
    const char *consumer_secret, int expect_success,
    unsigned short port_offset)
{
    test_index_t index;
    test_publisher_t publisher;
    test_consumer_t consumer;
    test_tcp_echo_t echo;
    unsigned char payload[] = "authenticated-stream";
    unsigned short base;
    int result;
    int rc;

    rc = 0;
    base = (unsigned short)(test_port_base() + 400U + port_offset);
    rc += expect_int("start TCP echo", 0,
        test_tcp_echo_start(&echo, (unsigned short)(base + 1U)));
    rc += expect_int("start TCP index", 0, test_index_start(&index, base));
    rc += expect_int("start TCP publisher", 0,
        test_tcp_publisher_start(&publisher, "tcppub", base,
            (unsigned short)(base + 1U), publisher_secret));
    rc += expect_int("start TCP consumer", 0,
        test_tcp_consumer_start(&consumer, "tcpclient", "tcppub", base,
            (unsigned short)(base + 2U), consumer_secret));
    result = rc == 0 ? test_tcp_roundtrip((unsigned short)(base + 2U),
        payload, sizeof(payload) - 1) : -1;
    if (expect_success) {
        rc += expect_int("TCP authenticated roundtrip",
            (int)sizeof(payload) - 1, result);
    } else {
        rc += expect_int("TCP secret mismatch rejected", -1, result);
        rp2p_stop(consumer.ctx);
        rp2p_stop(publisher.ctx);
        test_thread_join(consumer.thread);
        test_thread_join(publisher.thread);
        rc += expect_true("TCP secret mismatch detail",
            rp2p_get_error(consumer.ctx)[0] != '\0' ||
            rp2p_get_error(publisher.ctx)[0] != '\0');
        rp2p_close(consumer.ctx);
        rp2p_close(publisher.ctx);
        consumer.ctx = NULL;
        publisher.ctx = NULL;
    }
    if (consumer.ctx != NULL) test_consumer_stop(&consumer);
    if (publisher.ctx != NULL) test_publisher_stop(&publisher);
    test_index_stop(&index);
    test_tcp_echo_stop(&echo);
    return rc == 0 ? 0 : 1;
}

/**
 * Tests authenticated TCP transcript confirmation through the public API.
 * @return 0 on success, 1 on failure.
 */
static int case_rp2p_tcp_secure(void) {
    return test_tcp_tunnel_case("secret", "secret", 1, 0);
}

/**
 * Tests TCP rejection when peer tunnel secrets differ.
 * @return 0 on success, 1 on failure.
 */
static int case_rp2p_tcp_secret_mismatch(void) {
    return test_tcp_tunnel_case("secret", "other", 0, 10);
}

/**
 * Tests rp2p_deregister.
 * @return 0 on success, 1 on failure.
 */
static int case_rp2p_deregister(void) {
    test_index_t index;
    test_publisher_t publisher;
    rp2p_t *client;
    unsigned short base;
    int rc;

    rc = 0;
    base = (unsigned short)(test_port_base() + 60U);
    rc += expect_int("deregister missing key", RP2P_ENOENT,
        rp2p_deregister(NULL, TEST_HOST, base, "absent"));
    if (test_index_start(&index, (unsigned short)(base + 1U)) != 0) return 1;
    if (test_publisher_start(&publisher, "gone", (unsigned short)(base + 1U),
        (unsigned short)(base + 2U)) != 0) return 1;
    rc += expect_int("open client", RP2P_OK, rp2p_open(&client));
    rc += expect_int("deregister publisher", RP2P_OK,
        rp2p_deregister(client, TEST_HOST, (unsigned short)(base + 1U), "gone"));
    rp2p_close(client);
    test_publisher_stop(&publisher);
    test_index_stop(&index);
    return rc == 0 ? 0 : 1;
}

/**
 * Tests rp2p_list_publishers.
 * @return 0 on success, 1 on failure.
 */
static int case_rp2p_list_publishers(void) {
    test_index_t index;
    test_publisher_t publisher;
    test_publishers_t publishers;
    rp2p_t *client;
    unsigned short base;
    int rc;

    rc = 0;
    base = (unsigned short)(test_port_base() + 80U);
    rc += expect_int("list NULL ctx", RP2P_ERROR,
        rp2p_list_publishers(NULL, TEST_HOST, base, test_on_publisher, NULL));
    rc += expect_int("open client", RP2P_OK, rp2p_open(&client));
    rc += expect_int("list NULL host", RP2P_ERROR,
        rp2p_list_publishers(client, NULL, base, test_on_publisher, NULL));
    rc += expect_int("list NULL callback", RP2P_ERROR,
        rp2p_list_publishers(client, TEST_HOST, base, NULL, NULL));
    rc += expect_int("list without index", RP2P_ENET,
        rp2p_list_publishers(client, TEST_HOST, base, test_on_publisher, NULL));
    rp2p_close(client);
    if (test_index_start(&index, (unsigned short)(base + 1U)) != 0) return 1;
    if (test_publisher_start(&publisher, "listed", (unsigned short)(base + 1U),
        (unsigned short)(base + 2U)) != 0) return 1;
    memset(&publishers, 0, sizeof(publishers));
    rc += expect_int("open client", RP2P_OK, rp2p_open(&client));
    rc += expect_int("list publishers", RP2P_OK,
        rp2p_list_publishers(client, TEST_HOST, (unsigned short)(base + 1U),
            test_on_publisher, &publishers));
    rc += expect_true("publisher listed", test_has_publisher(&publishers, "listed"));
    rp2p_close(client);
    test_publisher_stop(&publisher);
    test_index_stop(&index);
    return rc == 0 ? 0 : 1;
}

/**
 * Tests rp2p_on_signal.
 * @return 0 on success, 1 on failure.
 */
static int case_rp2p_on_signal(void) {
    rp2p_t *ctx;
    int rc;

    rc = 0;
    rc += expect_int("on signal NULL ctx", RP2P_ERROR,
        rp2p_on_signal(NULL, 1, test_signal_cb));
    rc += expect_int("open context", RP2P_OK, rp2p_open(&ctx));
    rc += expect_int("register handler", RP2P_OK,
        rp2p_on_signal(ctx, 1, test_signal_cb));
    rc += expect_int("remove handler", RP2P_OK, rp2p_on_signal(ctx, 1, NULL));
    rc += expect_int("remove missing handler", RP2P_ENOENT,
        rp2p_on_signal(ctx, 1, NULL));
    rp2p_close(ctx);
    return rc == 0 ? 0 : 1;
}

/**
 * Tests rp2p_raise_signal.
 * @return 0 on success, 1 on failure.
 */
static int case_rp2p_raise_signal(void) {
    rp2p_t *ctx;
    int rc;

    rc = 0;
    signal_count = 0;
    signal_ctx = NULL;
    rc += expect_int("raise NULL ctx", 0, rp2p_raise_signal(NULL, 1));
    rc += expect_int("open context", RP2P_OK, rp2p_open(&ctx));
    rc += expect_int("raise unhandled", 0, rp2p_raise_signal(ctx, 1));
    rp2p_on_signal(ctx, 1, test_signal_cb);
    rc += expect_int("raise handled", 1, rp2p_raise_signal(ctx, 1));
    rc += expect_int("callback count", 1, signal_count);
    rc += expect_true("callback context", signal_ctx == ctx);
    rp2p_close(ctx);
    return rc == 0 ? 0 : 1;
}

/**
 * Tests rp2p_listen_signals.
 * @return 0 on success, 1 on failure.
 */
static int case_rp2p_listen_signals(void) {
    rp2p_t *ctx;
    int rc;

    rc = 0;
    rc += expect_int("listen signals NULL", RP2P_ERROR, rp2p_listen_signals(NULL));
    rc += expect_int("open context", RP2P_OK, rp2p_open(&ctx));
    rc += expect_int("listen signals context", RP2P_OK, rp2p_listen_signals(ctx));
    rp2p_close(ctx);
    return rc == 0 ? 0 : 1;
}

/**
 * Tests rp2p_listen_signal.
 * @return 0 on success, 1 on failure.
 */
static int case_rp2p_listen_signal(void) {
#ifdef _WIN32
    return expect_int("listen signal ignored context", RP2P_OK,
        rp2p_listen_signal(NULL, SIGINT));
#else
    return expect_int("listen signal ignored context", RP2P_OK,
        rp2p_listen_signal(NULL, SIGUSR1));
#endif
}

/**
 * Tests rp2p_signal_listener.
 * @return 0 on success, 1 on failure.
 */
static int case_rp2p_signal_listener(void) {
    return expect_true("listener returns NULL", rp2p_signal_listener(NULL) == NULL);
}

/**
 * Tests context-owned error detail lifetime and clearing.
 * @return 0 on success, 1 on failure.
 */
static int case_rp2p_get_error(void) {
    rp2p_t *ctx;
    int rc;

    rc = 0;
    rc += expect_string("NULL ctx empty", "", rp2p_get_error(NULL));
    rc += expect_int("open context", RP2P_OK, rp2p_open(&ctx));
    rc += expect_string("cleared default", "", rp2p_get_error(ctx));
    rc += expect_int("invalid protocol category", RP2P_EINVAL,
        rp2p_set_protocol(ctx, 7));
    rc += expect_string("captured detail",
        "protocol must be RP2P_PROTO_TCP or RP2P_PROTO_UDP",
        rp2p_get_error(ctx));
    rc += expect_int("valid protocol", RP2P_OK,
        rp2p_set_protocol(ctx, RP2P_PROTO_TCP));
    rc += expect_string("success clears detail", "", rp2p_get_error(ctx));
    rp2p_close(ctx);
    return rc == 0 ? 0 : 1;
}

/**
 * Tests rp2p_set_seats.
 * @return 0 on success, 1 on failure.
 */
static int case_rp2p_set_seats(void) {
    rp2p_t *ctx;
    int rc;

    rc = 0;
    rc += expect_int("set seats NULL", RP2P_EINVAL, rp2p_set_seats(NULL, 1));
    rc += expect_int("open context", RP2P_OK, rp2p_open(&ctx));
    rc += expect_int("set seats positive", RP2P_OK, rp2p_set_seats(ctx, 2));
    rc += expect_int("set seats negative", RP2P_EINVAL,
        rp2p_set_seats(ctx, -1));
    rp2p_close(ctx);
    return rc == 0 ? 0 : 1;
}

/**
 * Tests rp2p_set_pow.
 * @return 0 on success, 1 on failure.
 */
static int case_rp2p_set_pow(void) {
    rp2p_t *ctx;
    int rc;

    rc = 0;
    rc += expect_int("set pow NULL", RP2P_EINVAL, rp2p_set_pow(NULL, 1));
    rc += expect_int("open context", RP2P_OK, rp2p_open(&ctx));
    rc += expect_int("set pow positive", RP2P_OK, rp2p_set_pow(ctx, 2));
    rc += expect_int("set pow negative", RP2P_EINVAL, rp2p_set_pow(ctx, -1));
    rp2p_close(ctx);
    return rc == 0 ? 0 : 1;
}

/**
 * Tests rp2p_set_port.
 * @return 0 on success, 1 on failure.
 */
static int case_rp2p_set_port(void) {
    rp2p_t *ctx;
    int rc;

    rc = 0;
    rc += expect_int("set port NULL", RP2P_EINVAL, rp2p_set_port(NULL, 1));
    rc += expect_int("open context", RP2P_OK, rp2p_open(&ctx));
    rc += expect_int("set port value", RP2P_OK, rp2p_set_port(ctx, 12345));
    rc += expect_int("set port zero", RP2P_EINVAL, rp2p_set_port(ctx, 0));
    rp2p_close(ctx);
    return rc == 0 ? 0 : 1;
}

/**
 * Tests rp2p_set_protocol.
 * @return 0 on success, 1 on failure.
 */
static int case_rp2p_set_protocol(void) {
    rp2p_t *ctx;
    int rc;

    rc = 0;
    rc += expect_int("set protocol NULL", RP2P_EINVAL,
        rp2p_set_protocol(NULL, RP2P_PROTO_TCP));
    rc += expect_int("open context", RP2P_OK, rp2p_open(&ctx));
    rc += expect_int("set TCP", RP2P_OK, rp2p_set_protocol(ctx, RP2P_PROTO_TCP));
    rc += expect_int("set UDP", RP2P_OK, rp2p_set_protocol(ctx, RP2P_PROTO_UDP));
    rc += expect_int("set invalid protocol", RP2P_EINVAL,
        rp2p_set_protocol(ctx, 99));
    rp2p_close(ctx);
    return rc == 0 ? 0 : 1;
}

/**
 * Tests rp2p_set_pass.
 * @return 0 on success, 1 on failure.
 */
static int case_rp2p_set_pass(void) {
    rp2p_t *ctx;
    int rc;

    rc = 0;
    rc += expect_int("set pass NULL ctx", RP2P_EINVAL,
        rp2p_set_pass(NULL, "x"));
    rc += expect_int("open context", RP2P_OK, rp2p_open(&ctx));
    rc += expect_int("set pass", RP2P_OK, rp2p_set_pass(ctx, "secret"));
    rc += expect_int("clear pass", RP2P_OK, rp2p_set_pass(ctx, ""));
    rc += expect_int("set NULL pass", RP2P_EINVAL, rp2p_set_pass(ctx, NULL));
    rc += expect_int("set unsafe pass", RP2P_EINVAL,
        rp2p_set_pass(ctx, "bad`pass"));
    rp2p_close(ctx);
    return rc == 0 ? 0 : 1;
}

/**
 * Tests rp2p_set_secret.
 * @return 0 on success, 1 on failure.
 */
static int case_rp2p_set_secret(void) {
    rp2p_t *ctx;
    int rc;

    rc = 0;
    rc += expect_int("set secret NULL ctx", RP2P_EINVAL,
        rp2p_set_secret(NULL, "x"));
    rc += expect_int("open context", RP2P_OK, rp2p_open(&ctx));
    rc += expect_int("set secret", RP2P_OK,
        rp2p_set_secret(ctx, "secret"));
    rc += expect_int("clear secret", RP2P_OK, rp2p_set_secret(ctx, ""));
    rc += expect_int("set NULL secret", RP2P_EINVAL,
        rp2p_set_secret(ctx, NULL));
    rc += expect_int("set unsafe secret", RP2P_EINVAL,
        rp2p_set_secret(ctx, "bad`secret"));
    rp2p_close(ctx);
    return rc == 0 ? 0 : 1;
}

/**
 * Tests rp2p_set_vip.
 * @return 0 on success, 1 on failure.
 */
static int case_rp2p_set_vip(void) {
    rp2p_t *ctx;
    char err[128];
    int rc;

    rc = 0;
    rc += expect_int("set vip NULL ctx", RP2P_ERROR,
        rp2p_set_vip(NULL, "vip pass", err, sizeof(err)));
    rc += expect_int("open context", RP2P_OK, rp2p_open(&ctx));
    rc += expect_int("set vip pair", RP2P_OK,
        rp2p_set_vip(ctx, "vip pass", err, sizeof(err)));
    rc += expect_int("clear vip NULL", RP2P_OK,
        rp2p_set_vip(ctx, NULL, err, sizeof(err)));
    rc += expect_int("clear vip empty", RP2P_OK,
        rp2p_set_vip(ctx, "", err, sizeof(err)));
    rc += expect_int("reject odd vip tokens", RP2P_ERROR,
        rp2p_set_vip(ctx, "vip", err, sizeof(err)));
    rc += expect_int("reject bad vip id", RP2P_ERROR,
        rp2p_set_vip(ctx, "bad:id pass", err, sizeof(err)));
    rc += expect_int("reject bad vip pass", RP2P_ERROR,
        rp2p_set_vip(ctx, "vip bad`pass", err, sizeof(err)));
    rc += expect_int("reject duplicate vip", RP2P_ERROR,
        rp2p_set_vip(ctx, "vip pass vip other", err, sizeof(err)));
    rp2p_close(ctx);
    return rc == 0 ? 0 : 1;
}

/**
 * Tests rp2p_set_sweep.
 * @return 0 on success, 1 on failure.
 */
static int case_rp2p_set_sweep(void) {
    rp2p_t *ctx;
    int rc;

    rc = 0;
    rc += expect_int("set sweep NULL", RP2P_EINVAL,
        rp2p_set_sweep(NULL, 1));
    rc += expect_int("open context", RP2P_OK, rp2p_open(&ctx));
    rc += expect_int("set sweep positive", RP2P_OK, rp2p_set_sweep(ctx, 10));
    rc += expect_int("set sweep zero", RP2P_OK, rp2p_set_sweep(ctx, 0));
    rp2p_close(ctx);
    return rc == 0 ? 0 : 1;
}

/**
 * Tests rp2p_set_stun_url.
 * @return 0 on success, 1 on failure.
 */
static int case_rp2p_set_stun_url(void) {
    rp2p_t *ctx;
    int rc;

    rc = 0;
    rc += expect_int("set stun NULL ctx", RP2P_ERROR,
        rp2p_set_stun_url(NULL, "stun:example.com:3478"));
    rc += expect_int("open context", RP2P_OK, rp2p_open(&ctx));
    rc += expect_int("set stun", RP2P_OK,
        rp2p_set_stun_url(ctx, "stun:example.com:3478"));
    rc += expect_int("clear stun", RP2P_OK, rp2p_set_stun_url(ctx, NULL));
    rp2p_close(ctx);
    return rc == 0 ? 0 : 1;
}

/**
 * Dispatches one named test case.
 * @param name Public API function name.
 * @return 0 on success, 1 on failure, 2 for an unknown case.
 */
static int run_case(const char *name) {
    if (strcmp(name, "rp2p_options_default") == 0) return case_rp2p_options_default();
    if (strcmp(name, "rp2p_options_load_env") == 0) return case_rp2p_options_load_env();
    if (strcmp(name, "rp2p_options_load_env_invalid") == 0) return case_rp2p_options_load_env_invalid();
    if (strcmp(name, "rp2p_options_free") == 0) return case_rp2p_options_free();
    if (strcmp(name, "rp2p_open") == 0) return case_rp2p_open();
    if (strcmp(name, "rp2p_close") == 0) return case_rp2p_close();
    if (strcmp(name, "rp2p_stop") == 0) return case_rp2p_stop();
    if (strcmp(name, "rp2p_version") == 0) return case_rp2p_version();
    if (strcmp(name, "rp2p_strerror") == 0) return case_rp2p_strerror();
    if (strcmp(name, "rp2p_is_valid_id") == 0) return case_rp2p_is_valid_id();
    if (strcmp(name, "rp2p_is_valid_pass_token") == 0) return case_rp2p_is_valid_pass_token();
    if (strcmp(name, "rp2p_serve_index") == 0) return case_rp2p_serve_index();
    if (strcmp(name, "rp2p_wait") == 0) return case_rp2p_wait();
    if (strcmp(name, "rp2p_connect") == 0) return case_rp2p_connect();
    if (strcmp(name, "rp2p_udp_plain") == 0) return case_rp2p_udp_plain();
    if (strcmp(name, "rp2p_udp_secure") == 0) return case_rp2p_udp_secure();
    if (strcmp(name, "rp2p_udp_secure_publisher") == 0)
        return case_rp2p_udp_secure_publisher();
    if (strcmp(name, "rp2p_udp_secure_consumer") == 0)
        return case_rp2p_udp_secure_consumer();
    if (strcmp(name, "rp2p_udp_secret_mismatch") == 0)
        return case_rp2p_udp_secret_mismatch();
    if (strcmp(name, "rp2p_tcp_secure") == 0) return case_rp2p_tcp_secure();
    if (strcmp(name, "rp2p_tcp_secret_mismatch") == 0)
        return case_rp2p_tcp_secret_mismatch();
    if (strcmp(name, "rp2p_deregister") == 0) return case_rp2p_deregister();
    if (strcmp(name, "rp2p_list_publishers") == 0) return case_rp2p_list_publishers();
    if (strcmp(name, "rp2p_on_signal") == 0) return case_rp2p_on_signal();
    if (strcmp(name, "rp2p_raise_signal") == 0) return case_rp2p_raise_signal();
    if (strcmp(name, "rp2p_listen_signals") == 0) return case_rp2p_listen_signals();
    if (strcmp(name, "rp2p_listen_signal") == 0) return case_rp2p_listen_signal();
    if (strcmp(name, "rp2p_signal_listener") == 0) return case_rp2p_signal_listener();
    if (strcmp(name, "rp2p_get_error") == 0) return case_rp2p_get_error();
    if (strcmp(name, "rp2p_set_seats") == 0) return case_rp2p_set_seats();
    if (strcmp(name, "rp2p_set_pow") == 0) return case_rp2p_set_pow();
    if (strcmp(name, "rp2p_set_port") == 0) return case_rp2p_set_port();
    if (strcmp(name, "rp2p_set_protocol") == 0) return case_rp2p_set_protocol();
    if (strcmp(name, "rp2p_set_pass") == 0) return case_rp2p_set_pass();
    if (strcmp(name, "rp2p_set_secret") == 0) return case_rp2p_set_secret();
    if (strcmp(name, "rp2p_set_vip") == 0) return case_rp2p_set_vip();
    if (strcmp(name, "rp2p_set_sweep") == 0) return case_rp2p_set_sweep();
    if (strcmp(name, "rp2p_set_stun_url") == 0) return case_rp2p_set_stun_url();
    fprintf(stderr, "unknown test case: %s\n", name);
    return 2;
}

/**
 * Runs one public API contract test case.
 * @param argc Argument count.
 * @param argv Argument vector.
 * @return 0 on success, non-zero on failure.
 */
int main(int argc, char **argv) {
    int rc;

    if (argc != 2) {
        fprintf(stderr, "expected one test case argument\n");
        return 2;
    }
    if (test_home() != 0) return 1;
    if (test_socket_start() != 0) {
        test_home_cleanup();
        return 1;
    }
    rc = run_case(argv[1]);
    test_socket_stop();
    if (test_home_cleanup() != 0 && rc == 0) rc = 1;
    return rc;
}
