/**
 * hpm.h - HolePunchMan.
 * Summary: Public API for TCP rendezvous control and direct peer UDP transport.
 *
 * Author:  KaisarCode
 * Website: https://kaisarcode.com
 * License: https://www.gnu.org/licenses/gpl-3.0.html
 */

#ifndef KC_HPM_H
#define KC_HPM_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct kc_hpm kc_hpm_t;

#define KC_HPM_OK          0
#define KC_HPM_ERROR      -1
#define KC_HPM_ENET       -2
#define KC_HPM_ENOENT     -3
#define KC_HPM_ETIMEOUT   -4
#define KC_HPM_EFULL      -5

#define KC_HPM_MAX_PEERS     1024
#define KC_HPM_ID_MAX         63
#define KC_HPM_ADDR_MAX       47
#define KC_HPM_BUF          4096
#define KC_HPM_PORT_DEFAULT  9876
#define KC_HPM_BIND_PORT_DEFAULT 9876
#define KC_HPM_HEARTBEAT_S     15
#define KC_HPM_KEY_SZ          16
#define KC_HPM_KEY_STR_SZ      33
#define KC_HPM_PASS_MAX       255

#define KC_HPM_PROTO_TCP 1
#define KC_HPM_PROTO_UDP 2

#define KC_HPM_STUN_MAGIC 0x2112A442
#define KC_HPM_STUN_ATTR_MAPPED_ADDR     0x0001
#define KC_HPM_STUN_ATTR_XOR_MAPPED_ADDR 0x0020
#define KC_HPM_STUN_BINDING      0x0001
#define KC_HPM_STUN_BINDING_RESP 0x0101

typedef struct kc_hpm_options {
    int seats;
    int pow;
    char pass[KC_HPM_PASS_MAX + 1];
    char *vip;
    char index_host[256];
    unsigned short index_port;
    char bind_addr[256];
    unsigned short bind_port;
    int sweep;
    char stun_url[256];
} kc_hpm_options_t;

typedef struct {
    char id[KC_HPM_ID_MAX + 1];
    char key[KC_HPM_KEY_STR_SZ];
    time_t last_seen;
} kc_hpm_peer_t;

typedef enum {
    KC_HPM_CAND_HOST = 1,
    KC_HPM_CAND_LAN,
    KC_HPM_CAND_PUBLIC,
    KC_HPM_CAND_SRFLX,
    KC_HPM_CAND_PRFLX,
    KC_HPM_CAND_PREDICTED,
    KC_HPM_CAND_PROXY
} kc_hpm_candidate_type_t;

typedef struct {
    kc_hpm_candidate_type_t type;
    char addr[KC_HPM_ADDR_MAX + 1];
    unsigned short port;
    unsigned int priority;
} kc_hpm_candidate_t;

typedef void (*signal_callback_t)(kc_hpm_t *ctx);
typedef void (*kc_hpm_signal_callback_t)(kc_hpm_t *ctx);

typedef void (*kc_hpm_peer_cb)(const char *id, const char *addr,
    unsigned short port, void *userdata);

typedef struct {
    int sig;
    kc_hpm_signal_callback_t cb;
} kc_hpm_signal_entry_t;

kc_hpm_options_t kc_hpm_options_default(void);
void kc_hpm_options_load_env(kc_hpm_options_t *opts);
void kc_hpm_options_free(kc_hpm_options_t *opts);
int kc_hpm_open(kc_hpm_t **out);
int kc_hpm_close(kc_hpm_t *ctx);
const char *kc_hpm_strerror(int code);
int kc_hpm_is_valid_id(const char *id);
int kc_hpm_is_valid_pass_token(const char *pass);

/**
 * INDEX SERVER
 * Binds a TCP socket and enters a blocking loop handling
 * REGISTER / DEREGISTER / LIST / LOOKUP / PUNCH_REQ2.
 * Never returns on success.
 * @return Negative error code on setup failure.
 */
int kc_hpm_serve_index(
kc_hpm_t *ctx,
const char *host,
unsigned short port
);

/**
 * CLIENT: Publish a local service through the rendezvous index.
 * Connects to the index over TCP, REGISTERs, and waits for PUNCH_CALL2
 * requests over the same TCP connection. Creates one backend session
 * per connecting client.
 * @return KC_HPM_OK on clean exit, or a negative error code.
 */
int kc_hpm_wait(
kc_hpm_t *ctx,
const char *index_host,
unsigned short index_port,
const char *self_id,
unsigned short bind_port
);

/**
 * CLIENT: Expose a remote service on a local port.
 * Uses TCP for LOOKUP + PUNCH_REQ2 to the index. For TCP data relay,
 * creates a local TCP listener and uses a direct peer UDP path for the
 * encrypted reliable stream. For UDP data relay, creates a UDP socket
 * and hole-punches directly to the publisher.
 * @return KC_HPM_OK on clean exit, or a negative error code.
 */
int kc_hpm_connect(
kc_hpm_t *ctx,
const char *index_host,
unsigned short index_port,
const char *self_id,
const char *target_id,
unsigned short bind_port
);

/**
 * CLIENT: Deregister from an index server over TCP.
 * Used by `hpm del` and internally on shutdown.
 * @return KC_HPM_OK on success, or a negative error code.
 */
int kc_hpm_deregister(
kc_hpm_t *ctx,
const char *index_host,
unsigned short index_port,
const char *id
);

int kc_hpm_on_signal(
kc_hpm_t *ctx,
int sig,
kc_hpm_signal_callback_t cb
);

int kc_hpm_raise_signal(
kc_hpm_t *ctx,
int sig
);

int kc_hpm_listen_signals(kc_hpm_t *ctx);

int kc_hpm_listen_signal(
kc_hpm_t *ctx,
int sig
);

void *kc_hpm_signal_listener(void *arg);

int kc_hpm_set_seats(kc_hpm_t *ctx, int seats);
int kc_hpm_set_pow(kc_hpm_t *ctx, int bits);
int kc_hpm_set_port(kc_hpm_t *ctx, unsigned short port);
int kc_hpm_set_protocol(kc_hpm_t *ctx, int proto);
int kc_hpm_set_pass(kc_hpm_t *ctx, const char *pass);
int kc_hpm_set_vip(
kc_hpm_t *ctx,
const char *vip,
char *err,
size_t err_cap
);
int kc_hpm_set_sweep(
kc_hpm_t *ctx,
int sweep
);

int kc_hpm_set_stun_url(
    kc_hpm_t *ctx,
    const char *url
);

#ifdef __cplusplus
}
#endif

#endif
