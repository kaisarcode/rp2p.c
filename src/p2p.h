/**
 * p2p.h - KaisarCode P2P.
 * Summary: Public API for TCP rendezvous control and direct peer UDP transport.
 *
 * Author:  KaisarCode
 * Website: https://kaisarcode.com
 * License: https://www.gnu.org/licenses/gpl-3.0.html
 */

#ifndef KC_P2P_H
#define KC_P2P_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct kc_p2p kc_p2p_t;

#define KC_P2P_OK          0
#define KC_P2P_ERROR      -1
#define KC_P2P_ENET       -2
#define KC_P2P_ENOENT     -3
#define KC_P2P_ETIMEOUT   -4
#define KC_P2P_EFULL      -5

#define KC_P2P_MAX_PEERS     1024
#define KC_P2P_ID_MAX         63
#define KC_P2P_ADDR_MAX       47
#define KC_P2P_BUF          4096
#define KC_P2P_PORT_DEFAULT  9876
#define KC_P2P_BIND_PORT_DEFAULT 9876
#define KC_P2P_HEARTBEAT_S     15
#define KC_P2P_KEY_SZ          16
#define KC_P2P_KEY_STR_SZ      33
#define KC_P2P_PASS_MAX       255

#define KC_P2P_PROTO_TCP 1
#define KC_P2P_PROTO_UDP 2

#define KC_P2P_STUN_MAGIC 0x2112A442
#define KC_P2P_STUN_ATTR_MAPPED_ADDR     0x0001
#define KC_P2P_STUN_ATTR_XOR_MAPPED_ADDR 0x0020
#define KC_P2P_STUN_BINDING      0x0001
#define KC_P2P_STUN_BINDING_RESP 0x0101

typedef struct kc_p2p_options {
    int seats;
    int pow;
    char pass[KC_P2P_PASS_MAX + 1];
    char *vip;
    char index_host[256];
    unsigned short index_port;
    char bind_addr[256];
    unsigned short bind_port;
    int sweep;
    char stun_url[256];
} kc_p2p_options_t;

typedef struct {
    char id[KC_P2P_ID_MAX + 1];
    char key[KC_P2P_KEY_STR_SZ];
    time_t last_seen;
} kc_p2p_peer_t;

typedef enum {
    KC_P2P_CAND_HOST = 1,
    KC_P2P_CAND_LAN,
    KC_P2P_CAND_PUBLIC,
    KC_P2P_CAND_SRFLX,
    KC_P2P_CAND_PRFLX,
    KC_P2P_CAND_PREDICTED,
    KC_P2P_CAND_PROXY
} kc_p2p_candidate_type_t;

typedef struct {
    kc_p2p_candidate_type_t type;
    char addr[KC_P2P_ADDR_MAX + 1];
    unsigned short port;
    unsigned int priority;
} kc_p2p_candidate_t;

typedef void (*signal_callback_t)(kc_p2p_t *ctx);
typedef void (*kc_p2p_signal_callback_t)(kc_p2p_t *ctx);

typedef void (*kc_p2p_peer_cb)(const char *id, const char *addr,
    unsigned short port, void *userdata);

typedef struct {
    int sig;
    kc_p2p_signal_callback_t cb;
} kc_p2p_signal_entry_t;

kc_p2p_options_t kc_p2p_options_default(void);
void kc_p2p_options_load_env(kc_p2p_options_t *opts);
void kc_p2p_options_free(kc_p2p_options_t *opts);
int kc_p2p_open(kc_p2p_t **out);
int kc_p2p_close(kc_p2p_t *ctx);

/**
 * Returns the build version generated at compile time.
 * @return Unix timestamp for the current build.
 */
uint64_t kc_p2p_version(void);

const char *kc_p2p_strerror(int code);
int kc_p2p_is_valid_id(const char *id);
int kc_p2p_is_valid_pass_token(const char *pass);

/**
 * INDEX SERVER
 * Binds a TCP socket and enters a blocking loop handling
 * REGISTER / DEREGISTER / LIST / LOOKUP / PUNCH_REQ2.
 * Never returns on success.
 * @return Negative error code on setup failure.
 */
int kc_p2p_serve_index(
kc_p2p_t *ctx,
const char *host,
unsigned short port
);

/**
 * CLIENT: Publish a local service through the rendezvous index.
 * Connects to the index over TCP, REGISTERs, and waits for PUNCH_CALL2
 * requests over the same TCP connection. Creates one backend session
 * per connecting client.
 * @return KC_P2P_OK on clean exit, or a negative error code.
 */
int kc_p2p_wait(
kc_p2p_t *ctx,
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
 * @return KC_P2P_OK on clean exit, or a negative error code.
 */
int kc_p2p_connect(
kc_p2p_t *ctx,
const char *index_host,
unsigned short index_port,
const char *self_id,
const char *target_id,
unsigned short bind_port
);

/**
 * CLIENT: Deregister from an index server over TCP.
 * Used by `p2p del` and internally on shutdown.
 * @return KC_P2P_OK on success, or a negative error code.
 */
int kc_p2p_deregister(
kc_p2p_t *ctx,
const char *index_host,
unsigned short index_port,
const char *id
);

int kc_p2p_on_signal(
kc_p2p_t *ctx,
int sig,
kc_p2p_signal_callback_t cb
);

int kc_p2p_raise_signal(
kc_p2p_t *ctx,
int sig
);

int kc_p2p_listen_signals(kc_p2p_t *ctx);

int kc_p2p_listen_signal(
kc_p2p_t *ctx,
int sig
);

void *kc_p2p_signal_listener(void *arg);

int kc_p2p_set_seats(kc_p2p_t *ctx, int seats);
int kc_p2p_set_pow(kc_p2p_t *ctx, int bits);
int kc_p2p_set_port(kc_p2p_t *ctx, unsigned short port);
int kc_p2p_set_protocol(kc_p2p_t *ctx, int proto);
int kc_p2p_set_pass(kc_p2p_t *ctx, const char *pass);
int kc_p2p_set_vip(
kc_p2p_t *ctx,
const char *vip,
char *err,
size_t err_cap
);
int kc_p2p_set_sweep(
kc_p2p_t *ctx,
int sweep
);

int kc_p2p_set_stun_url(
    kc_p2p_t *ctx,
    const char *url
);

#ifdef __cplusplus
}
#endif

#endif
