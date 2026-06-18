/**
 * p2p.c - KaisarCode P2P.
 * Summary: P2P tunnel CLI - idx, set, del, con.
 *
 * Author:  KaisarCode
 * Website: https://kaisarcode.com
 * License: https://www.gnu.org/licenses/gpl-3.0.html
 */

#ifndef _WIN32
#define _POSIX_C_SOURCE 200809L
#endif

#include "p2p.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <errno.h>

#ifdef _WIN32
#  include <process.h>
#  include <windows.h>
#else
#  include <unistd.h>
#include <sys/stat.h>
#endif

extern volatile sig_atomic_t kc_p2p_stop_requested;

/**
 * Signal callback for graceful shutdown.
 * Summary: Sets the global stop flag so loops exit.
 * @param ctx Open context (unused).
 * @return None.
 */
static void kc_p2p_signal_cb(kc_p2p_t *ctx) {
    (void)ctx;
    kc_p2p_stop_requested = 1;
}

/**
 * Parses host:port from a string.
 * Summary: Splits on last colon, uses KC_P2P_PORT_DEFAULT if no colon.
 * @param text     Input address string.
 * @param host     Output host buffer.
 * @param host_sz  Output host buffer capacity.
 * @param port     Output port.
 * @return 0 on success, 1 on failure.
 */
static int parse_addr(const char *text, char *host, size_t host_sz,
    unsigned short *port)
{
    const char *colon;
    char *end;
    unsigned long val;
    size_t n;

    if (!text || !text[0] || !host || host_sz == 0 || !port) return 1;
    colon = strrchr(text, ':');
    *port = KC_P2P_PORT_DEFAULT;
    if (!colon) {
        n = strlen(text);
        if (n == 0 || n >= host_sz) return 1;
        memcpy(host, text, n + 1);
        return 0;
    }
    if (colon == text || colon[1] == '\0') return 1;
    n = (size_t)(colon - text);
    if (n == 0 || n >= host_sz) return 1;
    memcpy(host, text, n);
    host[n] = '\0';
    val = strtoul(colon + 1, &end, 10);
    if (*end != '\0' || val > 65535) return 1;
    *port = (unsigned short)val;
    return 0;
}

/**
 * Parses hostname@index:port spec string.
 * Summary: Splits on '@', parses the index part as addr:port.
 * @param spec     Input spec string (hostname@addr:port).
 * @param hostname Output hostname buffer.
 * @param hn_sz    Output hostname buffer capacity.
 * @param idx_addr Output index address buffer.
 * @param ia_sz    Output index address buffer capacity.
 * @param idx_port Output index port.
 * @return 0 on success, 1 on failure.
 */
static int parse_hostspec(const char *spec, char *hostname, size_t hn_sz,
    char *idx_addr, size_t ia_sz, unsigned short *idx_port)
{
    const char *at;
    size_t n;

    if (!spec || !spec[0]) return 1;
    at = strrchr(spec, '@');
    if (!at || at == spec) return 1;

    n = (size_t)(at - spec);
    if (n == 0 || n >= hn_sz) return 1;
    memcpy(hostname, spec, n);
    hostname[n] = '\0';

    *idx_port = KC_P2P_PORT_DEFAULT;
    return parse_addr(at + 1, idx_addr, ia_sz, idx_port);
}

/**
 * Prints usage information.
 * Summary: Shows available commands and options.
 * @param name Program executable name.
 * @return None.
 */
static void print_help(const char *name) {
    printf("Usage: %s <command> [options]\n", name);
    printf("\n");
    printf("Commands:\n");
    printf("  idx <port> [--max <N>] [--pow <N>] Start index server on TCP control port\n");
    printf("  set <host>@<index[:port]> --tcp <port> [--sweep <n>] [--stun <url>]\n");
    printf("  set <host>@<index[:port]> --udp <port> [--sweep <n>] [--stun <url>]\n");
    printf("  del <host>@<index[:port]> Deregister from index\n");
    printf("  con <host>@<index[:port]> --tcp <port> [--sweep <n>] [--stun <url>]\n");
    printf("  con <host>@<index[:port]> --udp <port> [--sweep <n>] [--stun <url>]\n");
    printf("\n");
    printf("Environment:\n");
    printf("  P2P_INDEX              Parsed internally, CLI still needs explicit index args\n");
    printf("  P2P_POW                PoW bits for index registration\n");
    printf("  P2P_PASS               Optional shared password for REGISTER/set protection\n");
    printf("  P2P_VIP                Reserved seat passwords as '<id> <pass> ...'\n");
    printf("  P2P_SWEEP              UDP port sweep range used during punch fallback\n");
    printf("  P2P_STUN               Optional STUN URL (stun:host:port)\n");
    printf("  IDs may use only A-Z a-z 0-9\n");
    printf("  Passwords may use A-Z a-z 0-9 . _ - + = , : @ %% /\n");
}

/**
 * Program entry point.
 * Summary: Dispatches subcommands (idx, set, del, con).
 * @param argc Argument count.
 * @param argv Argument vector.
 * @return 0 on success, 1 on error.
 */
int main(int argc, char **argv) {
    kc_p2p_t *ctx;
    int ret;

    if (argc < 2) { print_help(argv[0]); return 1; }
    if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) { print_help(argv[0]); return 0; }
    if (strcmp(argv[1], "-v") == 0 || strcmp(argv[1], "--version") == 0) {
        printf("p2p build %llu\n",
            (unsigned long long)kc_p2p_version());
        return 0;
    }

    if (strcmp(argv[1], "idx") == 0) {
        kc_p2p_options_t opts;
        unsigned short port;
        char *end;
        char vip_err[256];
        int max_peers;
        int max_peers_set;
        int pow_bits;
        int exit_code;

        opts = kc_p2p_options_default();
        kc_p2p_options_load_env(&opts);
        max_peers = opts.seats;
        max_peers_set = getenv("P2P_SEATS") != NULL;
        pow_bits = opts.pow;

        if (argc < 3) {
            fprintf(stderr, "p2p: usage: %s idx <port>\n", argv[0]);
            kc_p2p_options_free(&opts);
            return 1;
        }
        port = (unsigned short)strtoul(argv[2], &end, 10);
        if (*end != '\0' || port == 0) {
            fprintf(stderr, "p2p: invalid port '%s'\n", argv[2]);
            kc_p2p_options_free(&opts);
            return 1;
        }

        for (int i = 3; i < argc; i++) {
            if (strcmp(argv[i], "--max") == 0) {
                if (i + 1 >= argc) { fprintf(stderr, "p2p: --max requires an argument\n"); kc_p2p_options_free(&opts); return 1; }
                max_peers = atoi(argv[++i]);
                max_peers_set = 1;
            } else if (strcmp(argv[i], "--pow") == 0) {
                if (i + 1 >= argc) { fprintf(stderr, "p2p: --pow requires an argument\n"); kc_p2p_options_free(&opts); return 1; }
                pow_bits = atoi(argv[++i]);
            } else { fprintf(stderr, "p2p: unknown option '%s'\n", argv[i]); kc_p2p_options_free(&opts); return 1; }
        }

        if (kc_p2p_open(&ctx) != KC_P2P_OK) {
            fprintf(stderr, "p2p: failed to create context\n");
            kc_p2p_options_free(&opts);
            return 1;
        }
        if (kc_p2p_set_pass(ctx, opts.pass) != KC_P2P_OK) {
            fprintf(stderr, "p2p: invalid P2P_PASS characters\n");
            kc_p2p_close(ctx);
            kc_p2p_options_free(&opts);
            return 1;
        }
        if (max_peers_set) kc_p2p_set_seats(ctx, max_peers);
        kc_p2p_set_pow(ctx, pow_bits);
        vip_err[0] = '\0';
        if (kc_p2p_set_vip(ctx, opts.vip, vip_err, sizeof(vip_err)) != KC_P2P_OK) {
            fprintf(stderr, "p2p: %s\n", vip_err[0] ? vip_err : "invalid P2P_VIP");
            kc_p2p_close(ctx);
            kc_p2p_options_free(&opts);
            return 1;
        }

        kc_p2p_on_signal(ctx, SIGINT, kc_p2p_signal_cb);
        kc_p2p_on_signal(ctx, SIGTERM, kc_p2p_signal_cb);
        kc_p2p_listen_signals(ctx);
        kc_p2p_listen_signal(ctx, SIGINT);
        kc_p2p_listen_signal(ctx, SIGTERM);

        ret = kc_p2p_serve_index(ctx, "0.0.0.0", port);
        fprintf(stderr, "p2p: index exited: %s\n", kc_p2p_strerror(ret));
        exit_code = ret == KC_P2P_OK ? 0 : 1;
        kc_p2p_close(ctx);
        kc_p2p_options_free(&opts);
        return exit_code;

    } else if (strcmp(argv[1], "set") == 0) {
        kc_p2p_options_t opts;
        char host[KC_P2P_ID_MAX + 1];
        char idx_host[256];
        unsigned short idx_port;
        unsigned short service_port = 0;
        int proto = 0;

        opts = kc_p2p_options_default();
        kc_p2p_options_load_env(&opts);

        if (argc < 3) { fprintf(stderr, "p2p: usage: %s set <host>@<index[:port]>\n", argv[0]); kc_p2p_options_free(&opts); return 1; }
        if (parse_hostspec(argv[2], host, sizeof(host), idx_host, sizeof(idx_host), &idx_port) != 0) {
            fprintf(stderr, "p2p: invalid spec '%s' (expected host@index:port)\n", argv[2]); kc_p2p_options_free(&opts); return 1;
        }
        if (!kc_p2p_is_valid_id(host)) {
            fprintf(stderr, "p2p: invalid host id '%s'\n", host);
            kc_p2p_options_free(&opts);
            return 1;
        }

        for (int i = 3; i < argc; i++) {
            if (strcmp(argv[i], "--tcp") == 0) {
                if (proto != 0) { fprintf(stderr, "p2p: choose only one of --tcp or --udp\n"); kc_p2p_options_free(&opts); return 1; }
                if (i + 1 >= argc) { fprintf(stderr, "p2p: --tcp requires a port\n"); kc_p2p_options_free(&opts); return 1; }
                proto = KC_P2P_PROTO_TCP;
                service_port = (unsigned short)atoi(argv[++i]);
            } else if (strcmp(argv[i], "--udp") == 0) {
                if (proto != 0) { fprintf(stderr, "p2p: choose only one of --tcp or --udp\n"); kc_p2p_options_free(&opts); return 1; }
                if (i + 1 >= argc) { fprintf(stderr, "p2p: --udp requires a port\n"); kc_p2p_options_free(&opts); return 1; }
                proto = KC_P2P_PROTO_UDP;
                service_port = (unsigned short)atoi(argv[++i]);
            } else if (strcmp(argv[i], "--sweep") == 0) {
                if (i + 1 >= argc) { fprintf(stderr, "p2p: --sweep requires a number\n"); kc_p2p_options_free(&opts); return 1; }
                opts.sweep = atoi(argv[++i]);
            } else if (strcmp(argv[i], "--stun") == 0) {
                if (i + 1 >= argc) { fprintf(stderr, "p2p: --stun requires a URL\n"); kc_p2p_options_free(&opts); return 1; }
                strncpy(opts.stun_url, argv[++i], sizeof(opts.stun_url) - 1);
                opts.stun_url[sizeof(opts.stun_url) - 1] = '\0';
            } else { fprintf(stderr, "p2p: unknown option '%s'\n", argv[i]); kc_p2p_options_free(&opts); return 1; }
        }

        if (proto == 0 || service_port == 0) { fprintf(stderr, "p2p: set requires --tcp <port> or --udp <port>\n"); kc_p2p_options_free(&opts); return 1; }

        if (kc_p2p_open(&ctx) != KC_P2P_OK) { fprintf(stderr, "p2p: failed to create context\n"); kc_p2p_options_free(&opts); return 1; }
        if (kc_p2p_set_pass(ctx, opts.pass) != KC_P2P_OK) {
            fprintf(stderr, "p2p: invalid P2P_PASS characters\n");
            kc_p2p_close(ctx);
            kc_p2p_options_free(&opts);
            return 1;
        }
        kc_p2p_set_protocol(ctx, proto);
        kc_p2p_set_port(ctx, service_port);
        kc_p2p_set_sweep(ctx, opts.sweep);
        kc_p2p_set_stun_url(ctx, opts.stun_url[0] ? opts.stun_url : NULL);

        fprintf(stderr, "p2p: waiting for connections...\n");

        kc_p2p_on_signal(ctx, SIGINT, kc_p2p_signal_cb);
        kc_p2p_on_signal(ctx, SIGTERM, kc_p2p_signal_cb);
        kc_p2p_listen_signals(ctx);
        kc_p2p_listen_signal(ctx, SIGINT);
        kc_p2p_listen_signal(ctx, SIGTERM);

        ret = kc_p2p_wait(ctx, idx_host, idx_port, host, 0);
        if (ret != KC_P2P_OK)
            fprintf(stderr, "p2p: set exited: %s\n", kc_p2p_strerror(ret));

        kc_p2p_close(ctx);
        kc_p2p_options_free(&opts);
        return ret == KC_P2P_OK ? 0 : 1;

    } else if (strcmp(argv[1], "del") == 0) {
        char host[KC_P2P_ID_MAX + 1];
        char idx_host[256];
        unsigned short idx_port;

        if (argc < 3) { fprintf(stderr, "p2p: usage: %s del <host>@<index[:port]>\n", argv[0]); return 1; }
        if (parse_hostspec(argv[2], host, sizeof(host), idx_host, sizeof(idx_host), &idx_port) != 0) {
            fprintf(stderr, "p2p: invalid spec '%s' (expected host@index:port)\n", argv[2]); return 1;
        }
        if (!kc_p2p_is_valid_id(host)) {
            fprintf(stderr, "p2p: invalid host id '%s'\n", host);
            return 1;
        }

        if (kc_p2p_open(&ctx) != KC_P2P_OK) { fprintf(stderr, "p2p: failed to create context\n"); return 1; }
        ret = kc_p2p_deregister(ctx, idx_host, idx_port, host);
        if (ret != KC_P2P_OK) {
            fprintf(stderr, "p2p: deregister failed: %s\n", kc_p2p_strerror(ret));
            kc_p2p_close(ctx);
            return 1;
        }
        kc_p2p_close(ctx);
        return 0;

    } else if (strcmp(argv[1], "con") == 0) {
        kc_p2p_options_t opts;
        char host[KC_P2P_ID_MAX + 1];
        char idx_host[256];
        unsigned short idx_port;
        unsigned short listen_port = 0;
        char self_id[32];
        int proto = 0;

        opts = kc_p2p_options_default();
        kc_p2p_options_load_env(&opts);

        if (argc < 3) { fprintf(stderr, "p2p: usage: %s con <host>@<index[:port]>\n", argv[0]); kc_p2p_options_free(&opts); return 1; }
        if (parse_hostspec(argv[2], host, sizeof(host), idx_host, sizeof(idx_host), &idx_port) != 0) {
            fprintf(stderr, "p2p: invalid spec '%s' (expected host@index:port)\n", argv[2]); kc_p2p_options_free(&opts); return 1;
        }
        if (!kc_p2p_is_valid_id(host)) {
            fprintf(stderr, "p2p: invalid host id '%s'\n", host);
            kc_p2p_options_free(&opts);
            return 1;
        }

        for (int i = 3; i < argc; i++) {
            if (strcmp(argv[i], "--tcp") == 0) {
                if (proto != 0) { fprintf(stderr, "p2p: choose only one of --tcp or --udp\n"); kc_p2p_options_free(&opts); return 1; }
                if (i + 1 >= argc) { fprintf(stderr, "p2p: --tcp requires a port\n"); kc_p2p_options_free(&opts); return 1; }
                proto = KC_P2P_PROTO_TCP;
                listen_port = (unsigned short)atoi(argv[++i]);
            } else if (strcmp(argv[i], "--udp") == 0) {
                if (proto != 0) { fprintf(stderr, "p2p: choose only one of --tcp or --udp\n"); kc_p2p_options_free(&opts); return 1; }
                if (i + 1 >= argc) { fprintf(stderr, "p2p: --udp requires a port\n"); kc_p2p_options_free(&opts); return 1; }
                proto = KC_P2P_PROTO_UDP;
                listen_port = (unsigned short)atoi(argv[++i]);
            } else if (strcmp(argv[i], "--sweep") == 0) {
                if (i + 1 >= argc) { fprintf(stderr, "p2p: --sweep requires a number\n"); kc_p2p_options_free(&opts); return 1; }
                opts.sweep = atoi(argv[++i]);
            } else if (strcmp(argv[i], "--stun") == 0) {
                if (i + 1 >= argc) { fprintf(stderr, "p2p: --stun requires a URL\n"); kc_p2p_options_free(&opts); return 1; }
                strncpy(opts.stun_url, argv[++i], sizeof(opts.stun_url) - 1);
                opts.stun_url[sizeof(opts.stun_url) - 1] = '\0';
            } else { fprintf(stderr, "p2p: unknown option '%s'\n", argv[i]); kc_p2p_options_free(&opts); return 1; }
        }

        if (proto == 0 || listen_port == 0) { fprintf(stderr, "p2p: con requires --tcp <port> or --udp <port>\n"); kc_p2p_options_free(&opts); return 1; }

        snprintf(self_id, sizeof(self_id), "c-%d", (int)getpid());

        if (kc_p2p_open(&ctx) != KC_P2P_OK) { fprintf(stderr, "p2p: failed to create context\n"); kc_p2p_options_free(&opts); return 1; }
        kc_p2p_set_protocol(ctx, proto);
        kc_p2p_set_port(ctx, listen_port);
        kc_p2p_set_sweep(ctx, opts.sweep);
        kc_p2p_set_stun_url(ctx, opts.stun_url[0] ? opts.stun_url : NULL);

        kc_p2p_on_signal(ctx, SIGINT, kc_p2p_signal_cb);
        kc_p2p_on_signal(ctx, SIGTERM, kc_p2p_signal_cb);
        kc_p2p_listen_signals(ctx);
        kc_p2p_listen_signal(ctx, SIGINT);
        kc_p2p_listen_signal(ctx, SIGTERM);

        ret = kc_p2p_connect(ctx, idx_host, idx_port, self_id, host, 0);
        if (ret != KC_P2P_OK)
            fprintf(stderr, "p2p: connect failed: %s\n", kc_p2p_strerror(ret));

        kc_p2p_close(ctx);
        kc_p2p_options_free(&opts);
        return ret == KC_P2P_OK ? 0 : 1;

    } else {
        fprintf(stderr, "p2p: unknown command '%s'\n", argv[1]);
        fprintf(stderr, "p2p: try '%s --help'\n", argv[0]);
        return 1;
    }
}
