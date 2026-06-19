/**
 * rp2p.h - RedP2P.
 * Summary: Public API for TCP rendezvous control and direct peer UDP transport.
 *
 * Author:  KaisarCode
 * Website: https://kaisarcode.com
 * License: https://www.gnu.org/licenses/gpl-3.0.html
 */

#ifndef RP2P_H
#define RP2P_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct rp2p rp2p_t;

#define RP2P_OK          0
#define RP2P_ERROR      -1
#define RP2P_ENET       -2
#define RP2P_ENOENT     -3
#define RP2P_ETIMEOUT   -4
#define RP2P_EFULL      -5

#define RP2P_MAX_PEERS     1024
#define RP2P_ID_MAX         63
#define RP2P_ADDR_MAX       47
#define RP2P_BUF          4096
#define RP2P_PORT_DEFAULT  9876
#define RP2P_BIND_PORT_DEFAULT 9876
#define RP2P_HEARTBEAT_S     15
#define RP2P_KEY_SZ          16
#define RP2P_KEY_STR_SZ      33
#define RP2P_PASS_MAX       255

#define RP2P_PROTO_TCP 1
#define RP2P_PROTO_UDP 2

#define RP2P_STUN_MAGIC 0x2112A442
#define RP2P_STUN_ATTR_MAPPED_ADDR     0x0001
#define RP2P_STUN_ATTR_XOR_MAPPED_ADDR 0x0020
#define RP2P_STUN_BINDING      0x0001
#define RP2P_STUN_BINDING_RESP 0x0101

typedef struct rp2p_options {
    int seats;
    int pow;
    char pass[RP2P_PASS_MAX + 1];
    char *vip;
    char index_host[256];
    unsigned short index_port;
    char bind_addr[256];
    unsigned short bind_port;
    int sweep;
    char stun_url[256];
} rp2p_options_t;

typedef struct {
    char id[RP2P_ID_MAX + 1];
    char key[RP2P_KEY_STR_SZ];
    time_t last_seen;
} rp2p_peer_t;

/**
 * Candidate transport class.
 * Summary: Ranks direct candidates before public or observed candidates.
 */
typedef enum {
    RP2P_CAND_HOST = 1,
    RP2P_CAND_LAN,
    RP2P_CAND_PUBLIC,
    RP2P_CAND_SRFLX,
    RP2P_CAND_PRFLX,
    RP2P_CAND_PREDICTED,
    RP2P_CAND_PROXY
} rp2p_candidate_type_t;

/**
 * Candidate endpoint exchanged through the TCP rendezvous control channel.
 * Summary: The priority is local-only and is recomputed after parsing.
 */
typedef struct {
    rp2p_candidate_type_t type;
    char addr[RP2P_ADDR_MAX + 1];
    unsigned short port;
    unsigned int priority;
} rp2p_candidate_t;

typedef void (*signal_callback_t)(rp2p_t *ctx);
typedef void (*rp2p_signal_callback_t)(rp2p_t *ctx);

typedef void (*rp2p_peer_cb)(const char *id, const char *addr,
    unsigned short port, void *userdata);

typedef struct {
    int sig;
    rp2p_signal_callback_t cb;
} rp2p_signal_entry_t;

rp2p_options_t rp2p_options_default(void);
void rp2p_options_load_env(rp2p_options_t *opts);
void rp2p_options_free(rp2p_options_t *opts);
int rp2p_open(rp2p_t **out);
int rp2p_close(rp2p_t *ctx);

/**
 * Returns the build version generated at compile time.
 * @return Unix timestamp for the current build.
 */
uint64_t rp2p_version(void);

const char *rp2p_strerror(int code);
int rp2p_is_valid_id(const char *id);
int rp2p_is_valid_pass_token(const char *pass);

/**
 * INDEX SERVER
 * Binds a TCP socket and enters a blocking loop handling
 * REGISTER / DEREGISTER / LIST / LOOKUP / PUNCH_REQ2.
 * Never returns on success.
 * @return Negative error code on setup failure.
 */
int rp2p_serve_index(
rp2p_t *ctx,
const char *host,
unsigned short port
);

/**
 * CLIENT: Publish a local service through the rendezvous index.
 * Connects to the index over TCP, REGISTERs, and waits for PUNCH_CALL2
 * requests over the same TCP connection. Creates one backend session
 * per connecting client.
 * @return RP2P_OK on clean exit, or a negative error code.
 */
int rp2p_wait(
rp2p_t *ctx,
const char *index_host,
unsigned short index_port,
const char *self_id,
unsigned short bind_port
);

/**
 * CLIENT: Expose a remote service on a local port.
 * Uses TCP for LOOKUP + PUNCH_REQ2 to the index. For TCP stream forwarding
 * over direct UDP, creates a local TCP listener and uses a direct peer UDP
 * path for the encrypted reliable stream. For UDP datagram forwarding, creates
 * a UDP socket and hole-punches directly to the publisher.
 * @return RP2P_OK on clean exit, or a negative error code.
 */
int rp2p_connect(
rp2p_t *ctx,
const char *index_host,
unsigned short index_port,
const char *self_id,
const char *target_id,
unsigned short bind_port
);

/**
 * CLIENT: Deregister from an index server over TCP.
 * Used by `rp2p del` and internally on shutdown.
 * @return RP2P_OK on success, or a negative error code.
 */
int rp2p_deregister(
rp2p_t *ctx,
const char *index_host,
unsigned short index_port,
const char *id
);

int rp2p_on_signal(
rp2p_t *ctx,
int sig,
rp2p_signal_callback_t cb
);

int rp2p_raise_signal(
rp2p_t *ctx,
int sig
);

int rp2p_listen_signals(rp2p_t *ctx);

int rp2p_listen_signal(
rp2p_t *ctx,
int sig
);

void *rp2p_signal_listener(void *arg);

int rp2p_set_seats(rp2p_t *ctx, int seats);
int rp2p_set_pow(rp2p_t *ctx, int bits);
int rp2p_set_port(rp2p_t *ctx, unsigned short port);
int rp2p_set_protocol(rp2p_t *ctx, int proto);
int rp2p_set_pass(rp2p_t *ctx, const char *pass);
int rp2p_set_vip(
rp2p_t *ctx,
const char *vip,
char *err,
size_t err_cap
);
int rp2p_set_sweep(
rp2p_t *ctx,
int sweep
);

int rp2p_set_stun_url(
    rp2p_t *ctx,
    const char *url
);

#ifdef __cplusplus
}
#endif

#endif
