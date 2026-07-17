/**
 * librp2p.c - RedP2P.
 * Summary: Core shared library. TCP rendezvous control and direct peer transport.
 *
 * Author:  KaisarCode
 * Website: https://kaisarcode.com
 * License: https://www.gnu.org/licenses/gpl-3.0.html
 */

#ifndef _WIN32
#define _POSIX_C_SOURCE 200809L
#endif

#include "librp2p.h"
#include "monocypher.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdatomic.h>

#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#  endif
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  include <io.h>
#  include <direct.h>
#  include <windows.h>
#  include <bcrypt.h>
#  include <process.h>
#  ifndef read
#  define read(fd,buf,sz)  _read(fd,buf,sz)
#  endif
#  ifndef write
#  define write(fd,buf,sz) _write(fd,buf,sz)
#  endif
typedef SOCKET rp2p_fd_t;
#  define RP2P_FD_INVALID  INVALID_SOCKET
#  define RP2P_FD_CLOSE(f) closesocket(f)
#  define RP2P_ISERR(f)    ((f) == INVALID_SOCKET)
#  define RP2P_LASTERR()   ((int)WSAGetLastError())
#  define RP2P_EWOULD      WSAEWOULDBLOCK
#else
#  include <sys/select.h>
#  include <sys/socket.h>
#  include <sys/time.h>
#  include <netdb.h>
#  include <netinet/in.h>
#  include <arpa/inet.h>
#  include <unistd.h>
#  include <fcntl.h>
#  include <sys/wait.h>
#  include <sys/stat.h>
#  include <pthread.h>
#  include <sys/types.h>
typedef int rp2p_fd_t;
#  define RP2P_FD_INVALID  (-1)
#  define RP2P_FD_CLOSE(f) close(f)
#  define RP2P_ISERR(f)    ((f) < 0)
#  define RP2P_LASTERR()   errno
#  define RP2P_EWOULD      EAGAIN
#  define INVALID_SOCKET     (-1)
#  define SOCKET_ERROR       (-1)
#endif

#define RP2P_SWEEP_MAX   1024
#define RP2P_POW_MAX      32
#define RP2P_PORT_MIN      1
#define RP2P_PORT_MAX      65535
#define RP2P_POW_CHALLENGE_TTL_S 120

/**
 * Parses one strict unsigned decimal integer.
 * Summary: Rejects NULL, empty, leading/trailing garbage, signs, and overflow.
 * @param text    Input text to parse.
 * @param min     Inclusive lower bound.
 * @param max     Inclusive upper bound.
 * @param out     Output parsed value.
 * @return 1 on valid parse within bounds, 0 otherwise.
 */
static int rp2p_parse_u(const char *text, long min, long max, long *out) {
    char *end;
    long val;

    if (!text || !text[0] || !out) return 0;
    errno = 0;
    val = strtol(text, &end, 10);
    if (errno != 0) return 0;
    if (*end != '\0') return 0;
    if (val < min || val > max) return 0;
    *out = val;
    return 1;
}

/**
 * Parses one strict environment numeric option.
 * Summary: Applies the same validation as CLI parsing.
 * @param text    Input text to parse.
 * @param min     Inclusive lower bound.
 * @param max     Inclusive upper bound.
 * @param out     Output parsed value.
 * @return 1 on valid parse within bounds, 0 otherwise.
 */
static int rp2p_parse_env(const char *text, long min, long max, long *out) {
    if (!text || text[0] == '\0') return 0;
    return rp2p_parse_u(text, min, max, out);
}

#define RP2P_ETIMEOUT_SEC     15
#define RP2P_HALFCLOSE_S       2
#define RP2P_DISCONNECT_S     10
#define RP2P_KEEPALIVE_S       3
#define RP2P_PUNCH_ATTEMPTS   10
#define RP2P_PUNCH_INTERVAL_MS 200
#define RP2P_CANDIDATES_MAX       16
#define RP2P_MAX_PENDING_PUNCHES  32
#define RP2P_POW_CHALLENGES_MAX 256
#define RP2P_STREAM_MAGIC      0x48535452u
#define RP2P_STREAM_VERSION    1u
#define RP2P_STREAM_SESSION_ID_SZ 16
#define RP2P_STREAM_HELLO_NONCE_SZ 16
#define RP2P_STREAM_HELLO_BASE_SZ 72
#define RP2P_STREAM_HELLO_TAG_SZ 16
#define RP2P_STREAM_KEY_SZ     32
#define RP2P_STREAM_TAG_SZ     16
#define RP2P_STREAM_NONCE_SZ   24
#define RP2P_STREAM_MAX_PAYLOAD 1024
#define RP2P_STREAM_MAX_FRAME  1400
#define RP2P_STREAM_SEND_WINDOW 64
#define RP2P_STREAM_RECV_WINDOW 64
#define RP2P_STREAM_RTO_MS     700
#define RP2P_STREAM_RTO_MIN_MS 200
#define RP2P_STREAM_RTO_MAX_MS 5000
#define RP2P_STREAM_ACK_MS     120
#define RP2P_STREAM_HELLO_MS   500
#define RP2P_STREAM_IDLE_MS    20000
#define RP2P_STREAM_MAX_RETRIES 12
#define RP2P_STREAM_RTO_BACKOFF_SHIFT 4
#define RP2P_STREAM_MAX_BURST          16
#define RP2P_STREAM_HEADER_SZ         44
#define RP2P_LINK_MTU                 1500
#define RP2P_IPV4_UDP_OVERHEAD        (20 + 8)
#define RP2P_IPV6_UDP_OVERHEAD        (40 + 8)
#define RP2P_MAX_DATAGRAM_V4          (RP2P_LINK_MTU - RP2P_IPV4_UDP_OVERHEAD)
#define RP2P_MAX_DATAGRAM_V6          (RP2P_LINK_MTU - RP2P_IPV6_UDP_OVERHEAD)
#define RP2P_PUNCH_DIRECT_ROUNDS 3
#define RP2P_PUNCH_DIRECT_WAIT_MS 500
#define RP2P_PUNCH_SWEEP_WAIT_MS 20
#define RP2P_PUNCH_TOTAL_MS 4000
#define RP2P_CTRL_LINE_MAX     1024
#define RP2P_CTRL_FIELD_MAX     256
#define RP2P_CTRL_SESSION_MAX    63
#define RP2P_CTRTOK_HELLO        "RP2P_CTRTOK_HELLO RP2P/1"
#define RP2P_CTRTOK_HELLO_OK     "RP2P_CTRTOK_HELLO_OK"
#define RP2P_CTRTOK_ERROR_VERSION_MISMATCH "RP2P_CTRTOK_ERROR:version mismatch"

#define RP2P_CTRTOK_REGISTER     "RP2P_CTRTOK_REGISTER:"
#define RP2P_CTRTOK_DEREGISTER   "RP2P_CTRTOK_DEREGISTER:"
#define RP2P_CTRTOK_LOOKUP       "RP2P_CTRTOK_LOOKUP:"
#define RP2P_CTRTOK_LIST_PUBLISHERS "RP2P_CTRTOK_LIST_PUBLISHERS"
#define RP2P_CTRTOK_PUBLISHER    "RP2P_CTRTOK_PUBLISHER:"
#define RP2P_CTRTOK_END          "RP2P_CTRTOK_END"
#define RP2P_CTRTOK_CHALLENGE    "RP2P_CTRTOK_CHALLENGE:"
#define RP2P_CTRTOK_OK           "RP2P_CTRTOK_OK"
#define RP2P_CTRTOK_OK_KEY       "RP2P_CTRTOK_OK:RP2P_CTRTOK_KEY:"
#define RP2P_CTRTOK_SOLUTION     "RP2P_CTRTOK_SOLUTION:"
#define RP2P_CTRTOK_PROOF        "RP2P_CTRTOK_PROOF:"
#define RP2P_CTRTOK_KEY          "RP2P_CTRTOK_KEY:"
#define RP2P_CTRTOK_AUTH_FAILED  "RP2P_CTRTOK_AUTH_FAILED"
#define RP2P_CTRTOK_NOT_FOUND    "RP2P_CTRTOK_NOT_FOUND"
#define RP2P_CTRTOK_PUNCH_REQ2   "RP2P_CTRTOK_PUNCH_REQ2:"
#define RP2P_CTRTOK_PUNCH_ACK2   "RP2P_CTRTOK_PUNCH_ACK2:"
#define RP2P_CTRTOK_PUNCH_CALL2  "RP2P_CTRTOK_PUNCH_CALL2:"
#define RP2P_CTRTOK_PUNCH_OK2    "RP2P_CTRTOK_PUNCH_OK2:"
#define RP2P_CTRTOK_CAND         "RP2P_CTRTOK_CAND:"
#define RP2P_CTRTOK_PUNCH        "RP2P_CTRTOK_PUNCH:"
#define RP2P_CTRTOK_PUNCH_SERVER "RP2P_CTRTOK_PUNCH:server"
#define RP2P_CTRTOK_PUNCH_PING   "RP2P_CTRTOK_PUNCH_PING:"
#define RP2P_CTRTOK_PUNCH_PONG   "RP2P_CTRTOK_PUNCH_PONG:"
#define RP2P_CTRTOK_KA           "RP2P_CTRTOK_KA:"

#define RP2P_CTRCMD_REGISTER     "RP2P_CTRTOK_REGISTER"
#define RP2P_CTRCMD_DEREGISTER   "RP2P_CTRTOK_DEREGISTER"
#define RP2P_CTRCMD_LOOKUP       "RP2P_CTRTOK_LOOKUP"
#define RP2P_CTRCMD_LIST_PUBLISHERS "RP2P_CTRTOK_LIST_PUBLISHERS"
#define RP2P_CTRCMD_PUNCH_REQ2   "RP2P_CTRTOK_PUNCH_REQ2"
#define RP2P_CTRCMD_PUNCH_ACK2   "RP2P_CTRTOK_PUNCH_ACK2"

#define RP2P_CTRTOK_ERROR_MALFORMED "RP2P_CTRTOK_ERROR:malformed"
#define RP2P_CTRTOK_ERROR_INVALID_ID "RP2P_CTRTOK_ERROR:invalid id"
#define RP2P_CTRTOK_ERROR_PEER_TABLE_FULL "RP2P_CTRTOK_ERROR:peer table full"
#define RP2P_CTRTOK_ERROR_NOT_REGISTERED "RP2P_CTRTOK_ERROR:not registered"
#define RP2P_CTRTOK_ERROR_BUSY "RP2P_CTRTOK_ERROR:busy"
#define RP2P_CTRTOK_ERROR_RANDOM "RP2P_CTRTOK_ERROR:random"
#define RP2P_CTRTOK_ERROR_OFFLINE "RP2P_CTRTOK_ERROR:offline"
#define RP2P_CTRTOK_ERROR_INVALID_KEY "RP2P_CTRTOK_ERROR:invalid key"
#define RP2P_CTRTOK_ERROR_UNKNOWN_COMMAND "RP2P_CTRTOK_ERROR:unknown command"

#define RP2P_STREAM_TYPE_HELLO     1u
#define RP2P_STREAM_TYPE_HELLO_ACK 2u
#define RP2P_STREAM_TYPE_DATA      3u
#define RP2P_STREAM_TYPE_ACK       4u
#define RP2P_STREAM_TYPE_SACK      5u
#define RP2P_STREAM_TYPE_FIN       6u
#define RP2P_STREAM_TYPE_FIN_ACK   7u
#define RP2P_STREAM_TYPE_RESET     8u
#define RP2P_STREAM_TYPE_PING      9u
#define RP2P_STREAM_TYPE_PONG      10u

#define RP2P_STREAM_DIR_C2S    1u
#define RP2P_STREAM_DIR_S2C    2u
#define RP2P_UDP_MAGIC         0x50445552u
#define RP2P_UDP_VERSION       1u
#define RP2P_UDP_HEADER_SZ     24
#define RP2P_UDP_TAG_SZ        16

typedef struct {
    uint8_t type;
    uint8_t direction;
    uint32_t seq;
    uint32_t ack;
    uint16_t window;
    uint16_t payload_len;
    uint32_t gap_start;
    uint32_t gap_end;
    unsigned char session_id[RP2P_STREAM_SESSION_ID_SZ];
} rp2p_stream_header_t;

typedef struct {
    int used;
    uint8_t type;
    uint32_t seq;
    int attempts;
    uint64_t last_tx_ms;
    size_t frame_len;
    unsigned char frame[RP2P_STREAM_MAX_FRAME];
} rp2p_stream_send_slot_t;

#ifndef RP2P_BUILD_VERSION
#define RP2P_BUILD_VERSION 0
#endif

_Static_assert(RP2P_STREAM_HEADER_SZ + RP2P_STREAM_TAG_SZ + RP2P_STREAM_MAX_PAYLOAD <= RP2P_STREAM_MAX_FRAME,
    "Stream frame cannot fit header, tag, and max payload");
_Static_assert(RP2P_STREAM_MAX_FRAME <= RP2P_MAX_DATAGRAM_V4,
    "Stream frame exceeds IPv4 datagram limit");
_Static_assert(RP2P_STREAM_MAX_FRAME <= RP2P_MAX_DATAGRAM_V6,
    "Stream frame exceeds IPv6 datagram limit");

/**
 * Returns the build version generated at compile time.
 * @return Unix timestamp for the current build.
 */
uint64_t rp2p_version(void) {
    return (uint64_t)RP2P_BUILD_VERSION;
}

typedef struct {
    int used;
    uint8_t type;
    uint32_t seq;
    uint16_t len;
    unsigned char data[RP2P_STREAM_MAX_PAYLOAD];
} rp2p_stream_recv_slot_t;

typedef struct {
    int ready;
    int authenticated;
    unsigned char local_secret[32];
    unsigned char local_public[32];
    unsigned char peer_public[32];
    unsigned char local_nonce[RP2P_STREAM_HELLO_NONCE_SZ];
    unsigned char peer_nonce[RP2P_STREAM_HELLO_NONCE_SZ];
    unsigned char tx_key[RP2P_STREAM_KEY_SZ];
    unsigned char rx_key[RP2P_STREAM_KEY_SZ];
    unsigned char psk[RP2P_STREAM_KEY_SZ];
} rp2p_stream_crypto_t;

typedef struct {
    uint32_t next_seq;
    int fin_sent;
    int fin_acked;
    int local_eof;
    rp2p_stream_send_slot_t slots[RP2P_STREAM_SEND_WINDOW];
} rp2p_stream_outbound_t;

typedef struct {
    uint32_t next_expected;
    int remote_fin;
    int remote_fin_acked;
    rp2p_stream_recv_slot_t slots[RP2P_STREAM_RECV_WINDOW];
} rp2p_stream_inbound_t;

typedef struct {
    int enabled;
    int initiator;
    int ready;
    int hello_sent;
    int hello_acked;
    int reset_sent;
    int reset_received;
    int close_notified;
    uint8_t tx_direction;
    uint8_t rx_direction;
    uint32_t ctrl_seq;
    unsigned char session_id[RP2P_STREAM_SESSION_ID_SZ];
    char session_hex[RP2P_STREAM_SESSION_ID_SZ * 2 + 1];
    rp2p_stream_crypto_t crypto;
    rp2p_stream_outbound_t out;
    rp2p_stream_inbound_t in;
    uint64_t last_rx_ms;
    uint64_t last_tx_ms;
    uint64_t last_ack_ms;
    uint64_t last_hello_ms;
    uint64_t srtt_ms;
    uint64_t rttvar_ms;
    uint64_t rto_ms;
} rp2p_stream_state_t;

typedef struct {
    int enabled;
    uint8_t tx_direction;
    uint8_t rx_direction;
    unsigned char key[32];
    unsigned char session_id[8];
    uint64_t tx_seq;
    uint64_t rx_max;
    uint64_t rx_window;
} rp2p_udp_crypto_t;

typedef struct {
    int used;
    unsigned char session_id[RP2P_STREAM_SESSION_ID_SZ];
    uint32_t seq;
} rp2p_stream_drop_record_t;

typedef struct {
    int used;
    size_t len;
    unsigned char frame[RP2P_STREAM_MAX_FRAME];
} rp2p_stream_pending_frame_t;

static rp2p_t **g_signal_ctx_list = NULL;
static int g_signal_ctx_cap = 0;
static int g_signal_ctx_count = 0;
#ifdef _WIN32
static SRWLOCK g_signal_mutex = SRWLOCK_INIT;
#else
static pthread_mutex_t g_signal_mutex = PTHREAD_MUTEX_INITIALIZER;
#endif
static volatile sig_atomic_t g_signal_pending_no = 0;
static volatile sig_atomic_t g_signal_pending = 0;

static int rp2p_is_stop_requested(rp2p_t *ctx);
static int rp2p_fdset_add(rp2p_fd_t fd, fd_set *set, int *maxfd);

typedef struct {
    uint32_t state[8];
    uint64_t count;
    unsigned char buf[64];
} rp2p_sha256_t;

static const uint32_t rp2p_sha256_k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

#define RP2P_SHA256_ROR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define RP2P_SHA256_CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define RP2P_SHA256_MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define RP2P_SHA256_S0(x) (RP2P_SHA256_ROR(x, 2) ^ RP2P_SHA256_ROR(x, 13) ^ RP2P_SHA256_ROR(x, 22))
#define RP2P_SHA256_S1(x) (RP2P_SHA256_ROR(x, 6) ^ RP2P_SHA256_ROR(x, 11) ^ RP2P_SHA256_ROR(x, 25))
#define RP2P_SHA256_s0(x) (RP2P_SHA256_ROR(x, 7) ^ RP2P_SHA256_ROR(x, 18) ^ ((x) >> 3))
#define RP2P_SHA256_s1(x) (RP2P_SHA256_ROR(x, 17) ^ RP2P_SHA256_ROR(x, 19) ^ ((x) >> 10))

/**
 * Sha256 transform.
 * @return Status code.
 */
static void rp2p_sha256_transform(uint32_t state[8], const unsigned char block[64]) {
    uint32_t W[64], a, b, c, d, e, f, g, h, T1, T2;
    int t;
    for (t = 0; t < 16; t++)
        W[t] = ((uint32_t)block[t*4]) << 24 |
            ((uint32_t)block[t*4+1]) << 16 |
            ((uint32_t)block[t*4+2]) << 8 |
            block[t*4+3];
    for (t = 16; t < 64; t++)
        W[t] = RP2P_SHA256_s1(W[t-2]) + W[t-7] + RP2P_SHA256_s0(W[t-15]) + W[t-16];
    a = state[0]; b = state[1]; c = state[2]; d = state[3];
    e = state[4]; f = state[5]; g = state[6]; h = state[7];
    for (t = 0; t < 64; t++) {
        T1 = h + RP2P_SHA256_S1(e) + RP2P_SHA256_CH(e, f, g) + rp2p_sha256_k[t] + W[t];
        T2 = RP2P_SHA256_S0(a) + RP2P_SHA256_MAJ(a, b, c);
        h = g; g = f; f = e; e = d + T1; d = c; c = b; b = a; a = T1 + T2;
    }
    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

/**
 * Sha256 init.
 * @return Status code.
 */
static void rp2p_sha256_init(rp2p_sha256_t *ctx) {
    ctx->state[0] = 0x6a09e667; ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372; ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f; ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab; ctx->state[7] = 0x5be0cd19;
    ctx->count = 0;
}

/**
 * Sha256 update.
 * @return Status code.
 */
static void rp2p_sha256_update(rp2p_sha256_t *ctx, const unsigned char *data, size_t len) {
    size_t i;
    for (i = 0; i < len; i++) {
        ctx->buf[ctx->count & 63] = data[i];
        ctx->count++;
        if ((ctx->count & 63) == 0)
            rp2p_sha256_transform(ctx->state, ctx->buf);
    }
}

/**
 * Sha256 final.
 * @return Status code.
 */
static void rp2p_sha256_final(rp2p_sha256_t *ctx, unsigned char hash[32]) {
    uint64_t bits = ctx->count * 8;
    int idx = (int)(ctx->count & 63);
    ctx->buf[idx++] = 0x80;
    if (idx > 56) {
        while (idx < 64) ctx->buf[idx++] = 0;
        rp2p_sha256_transform(ctx->state, ctx->buf);
        idx = 0;
    }
    while (idx < 56) ctx->buf[idx++] = 0;
    ctx->buf[56] = (unsigned char)(bits >> 56);
    ctx->buf[57] = (unsigned char)(bits >> 48);
    ctx->buf[58] = (unsigned char)(bits >> 40);
    ctx->buf[59] = (unsigned char)(bits >> 32);
    ctx->buf[60] = (unsigned char)(bits >> 24);
    ctx->buf[61] = (unsigned char)(bits >> 16);
    ctx->buf[62] = (unsigned char)(bits >> 8);
    ctx->buf[63] = (unsigned char)(bits);
    rp2p_sha256_transform(ctx->state, ctx->buf);
    memcpy(hash, ctx->state, 32);
}

typedef struct {
    char nonce_hex[17];
    char id[RP2P_ID_MAX + 1];
    struct sockaddr_storage addr;
    uint64_t issued_at;
    uint64_t expires_at;
} rp2p_pow_challenge_t;

/**
 * Computes one HMAC-SHA256 digest.
 * @param key     Shared password material.
 * @param msg     Input message bytes.
 * @param msg_len Input message length.
 * @param hash    Output digest buffer.
 * @return None.
 */
static void rp2p_hmac_sha256(const char *key, const unsigned char *msg,
    size_t msg_len, unsigned char hash[32])
{
    rp2p_sha256_t ctx;
    unsigned char key_block[64];
    unsigned char ipad[64];
    unsigned char opad[64];
    unsigned char inner[32];
    size_t key_len;
    size_t i;

    memset(key_block, 0, sizeof(key_block));
    key_len = key ? strlen(key) : 0;
    if (key_len > sizeof(key_block)) {
        rp2p_sha256_init(&ctx);
        rp2p_sha256_update(&ctx, (const unsigned char *)key, key_len);
        rp2p_sha256_final(&ctx, key_block);
    } else if (key_len > 0) {
        memcpy(key_block, key, key_len);
    }
    for (i = 0; i < sizeof(key_block); i++) {
        ipad[i] = (unsigned char)(key_block[i] ^ 0x36);
        opad[i] = (unsigned char)(key_block[i] ^ 0x5c);
    }
    rp2p_sha256_init(&ctx);
    rp2p_sha256_update(&ctx, ipad, sizeof(ipad));
    rp2p_sha256_update(&ctx, msg, msg_len);
    rp2p_sha256_final(&ctx, inner);
    rp2p_sha256_init(&ctx);
    rp2p_sha256_update(&ctx, opad, sizeof(opad));
    rp2p_sha256_update(&ctx, inner, sizeof(inner));
    rp2p_sha256_final(&ctx, hash);
}

/**
 * Computes one register proof digest.
 * @param pass         Shared password material.
 * @param nonce_hex    Challenge nonce in hex.
 * @param id           Service identifier.
 * @param solution_hex Candidate solution in hex.
 * @param hash         Output digest buffer.
 * @return None.
 */
static void rp2p_hash_register_once(const char *pass, const char *nonce_hex,
    const char *id, const char *solution_hex, unsigned char hash[32])
{
    unsigned char msg[RP2P_ID_MAX + 33];
    size_t nonce_len;
    size_t id_len;
    size_t solution_len;
    size_t pos;

    nonce_len = strlen(nonce_hex);
    id_len = strlen(id);
    solution_len = strlen(solution_hex);
    pos = 0;
    if (nonce_len > sizeof(msg) - pos) nonce_len = sizeof(msg) - pos;
    memcpy(msg + pos, nonce_hex, nonce_len);
    pos += nonce_len;
    if (id_len > sizeof(msg) - pos) id_len = sizeof(msg) - pos;
    memcpy(msg + pos, id, id_len);
    pos += id_len;
    if (solution_len > sizeof(msg) - pos) solution_len = sizeof(msg) - pos;
    memcpy(msg + pos, solution_hex, solution_len);
    pos += solution_len;
    rp2p_hmac_sha256(pass ? pass : "", msg, pos, hash);
}

/**
 * Encodes a digest as lowercase hex.
 * @param hash     Input digest bytes.
 * @param hash_len Digest length in bytes.
 * @param out      Output hex buffer.
 * @param out_cap  Output buffer capacity.
 * @return 1 on success, 0 on failure.
 */
static int rp2p_hex_encode(const unsigned char *hash, size_t hash_len,
    char *out, size_t out_cap)
{
    static const char hex[] = "0123456789abcdef";
    size_t i;

    if (!hash || !out || out_cap < hash_len * 2 + 1) return 0;
    for (i = 0; i < hash_len; i++) {
        out[i * 2] = hex[(hash[i] >> 4) & 0x0f];
        out[i * 2 + 1] = hex[hash[i] & 0x0f];
    }
    out[hash_len * 2] = '\0';
    return 1;
}

/**
 * Counts leading zero bits in one digest.
 * @param hash Input digest bytes.
 * @return Count of leading zero bits.
 */
static int rp2p_count_leading_zero_bits(const unsigned char hash[32]);

/**
 * Solves one register proof challenge.
 * @param pass         Shared password material.
 * @param nonce_hex    Challenge nonce in hex.
 * @param id           Service identifier.
 * @param bits         Difficulty target.
 * @param solution_hex Output solution buffer.
 * @param sol_cap      Output solution capacity.
 * @param proof_hex    Output proof buffer.
 * @param proof_cap    Output proof capacity.
 * @return 1 on success, 0 on failure.
 */
static int rp2p_solve_register_pow(rp2p_t *ctx, const char *pass, const char *nonce_hex,
    const char *id, int bits, char *solution_hex, size_t sol_cap,
    char *proof_hex, size_t proof_cap)
{
    uint32_t counter;
    unsigned char hash[32];
    char buf[17];

    if (sol_cap < sizeof(buf) || proof_cap < 65) return 0;
    counter = 0;
    for (;;) {
        snprintf(buf, sizeof(buf), "%08x", counter);
        rp2p_hash_register_once(pass, nonce_hex, id, buf, hash);
        if (rp2p_count_leading_zero_bits(hash) >= bits) {
            memcpy(solution_hex, buf, sizeof(buf));
            return rp2p_hex_encode(hash, sizeof(hash), proof_hex, proof_cap);
        }
        counter++;
        if (counter == 0) break;
        if ((counter & 0xfffff) == 0 && rp2p_is_stop_requested(ctx)) break;
    }
    return 0;
}

/**
 * Verifies one register proof challenge.
 * @param pass         Shared password material.
 * @param nonce_hex    Challenge nonce in hex.
 * @param id           Service identifier.
 * @param solution_hex Candidate solution in hex.
 * @param proof_hex    Candidate proof in hex.
 * @param bits         Difficulty target.
 * @return 1 on success, 0 on failure.
 */
static int rp2p_verify_register_pow(const char *pass, const char *nonce_hex,
    const char *id, const char *solution_hex, const char *proof_hex, int bits)
{
    unsigned char hash[32];
    char expected[65];
    int diff, k;

    if (!proof_hex || strlen(proof_hex) != 64) return 0;
    rp2p_hash_register_once(pass, nonce_hex, id, solution_hex, hash);
    if (!rp2p_hex_encode(hash, sizeof(hash), expected, sizeof(expected))) return 0;
    diff = 0;
    for (k = 0; k < 64; k++)
        diff |= (proof_hex[k] ^ expected[k]);
    if (diff != 0) return 0;
    return rp2p_count_leading_zero_bits(hash) >= bits;
}

/**
 * Counts leading zero bits in one digest.
 * @param hash Input digest bytes.
 * @return Count of leading zero bits.
 */
static int rp2p_count_leading_zero_bits(const unsigned char hash[32]) {
    int total = 0, i;
    for (i = 0; i < 32; i++) {
        if (hash[i] == 0) {
            total += 8;
        } else {
            unsigned char b = hash[i];
            int j;
            for (j = 0; j < 8; j++) {
                if ((b & 0x80) == 0) total++;
                else break;
                b <<= 1;
            }
            break;
        }
    }
    return total;
}

typedef struct {
    rp2p_fd_t fd;
    char buf[RP2P_BUF];
    int buf_len;
    char id[RP2P_ID_MAX + 1];
    int registered;
    int hello_ok;
} rp2p_tcp_conn_t;

typedef struct {
    char id[RP2P_ID_MAX + 1];
    char pass[RP2P_PASS_MAX + 1];
} rp2p_vip_entry_t;

typedef struct {
    int sig;
    rp2p_signal_callback_t cb;
} rp2p_signal_entry_t;

/**
 * Pending punch.
 * Summary: Tracks a two-round punch request awaiting ACK2 from publisher.
 */
typedef struct {
    char self_id[RP2P_ID_MAX + 1];
    char target_id[RP2P_ID_MAX + 1];
    char sess_id[64];
    rp2p_fd_t consumer_fd;
    uint64_t ts;
} rp2p_pending_punch_t;

struct rp2p {
    rp2p_signal_entry_t *signal_entries;
    int signal_count;
    int signal_capacity;
    rp2p_peer_t *peers;
    int n_peers;
    int peers_alloc;
    int n_peers_cap;
    int nonvip_cap;
    rp2p_tcp_conn_t *conns;
    int n_conns;
    int conns_cap;
    rp2p_vip_entry_t *vips;
    int n_vips;
    int vips_cap;
    char key[RP2P_KEY_STR_SZ];
    char pass[RP2P_PASS_MAX + 1];
    char secret[RP2P_SECRET_MAX + 1];
    int pow_bits;
    unsigned short bind_port;
    int explicit_port;
    int proto;
    int sweep;
    rp2p_pow_challenge_t pow_challenges[RP2P_POW_CHALLENGES_MAX];
    int n_pow_challenges;
#ifdef _WIN32
    CRITICAL_SECTION mutex;
#else
    pthread_mutex_t mutex;
#endif
    char stun_url[512];
    char err_buf[256];
    int fault_drop_counter;
    int fault_reorder_counter;
    rp2p_stream_drop_record_t fault_dropped[256];
    rp2p_stream_drop_record_t fault_delayed[256];
    rp2p_stream_pending_frame_t fault_pending;
    rp2p_pending_punch_t pending_punches[RP2P_MAX_PENDING_PUNCHES];
    int n_pending_punches;
    _Atomic int stop_requested;
};

/**
 * Returns whether one context requested stop.
 * @param ctx Context to inspect.
 * @return 1 when stop was requested, 0 otherwise.
 */
static int rp2p_is_stop_requested(rp2p_t *ctx) {
    return ctx && atomic_load(&ctx->stop_requested);
}

typedef struct rp2p_udp_consumer_session {
    rp2p_fd_t fd;
    rp2p_fd_t tcp_fd;
    struct sockaddr_storage client_addr;
    struct sockaddr_storage peer_addr;
    uint64_t last_rx;
    uint64_t last_ka;
    int active;
    int is_tcp;
    rp2p_stream_state_t stream;
    rp2p_udp_crypto_t udp_crypto;
} rp2p_udp_consumer_session_t;

typedef struct rp2p_udp_server_session {
    rp2p_fd_t backend_fd;
    rp2p_fd_t tcp_fd;
    struct sockaddr_storage peer_addr;
    uint64_t last_rx;
    uint64_t last_ka;
    int active;
    int is_tcp;
    rp2p_stream_state_t stream;
    rp2p_udp_crypto_t udp_crypto;
} rp2p_udp_server_session_t;

#ifdef _WIN32
typedef HANDLE rp2p_thread_t;
#define RP2P_THREAD_RET unsigned __stdcall
#else
typedef pthread_t rp2p_thread_t;
#define RP2P_THREAD_RET void *
#endif

static int rp2p_sock_read(rp2p_fd_t fd, char *buf, int len);
static int rp2p_write_all(rp2p_fd_t fd, const char *buf, int len);
static void rp2p_shutdown_write(rp2p_fd_t fd);
static socklen_t rp2p_sockaddr_len(const struct sockaddr_storage *addr);
static int rp2p_candidate_sockaddr(const rp2p_candidate_t *candidate,
    struct sockaddr_storage *out);
static int rp2p_is_space(char ch);
static char *rp2p_trim(char *text);
static int rp2p_find_vip(rp2p_t *ctx, const char *id);
static int rp2p_add_vip(rp2p_t *ctx, const char *id, const char *pass,
    char *err, size_t err_cap);
static const char *rp2p_get_register_pass(rp2p_t *ctx, const char *id);
static uint32_t rp2p_load_u32_le(const unsigned char *p);

/**
 * Reports whether detailed stream logs are enabled.
 * @return 1 when stream debug logging is enabled, 0 otherwise.
 */
static int rp2p_stream_debug_enabled(void) {
    const char *env;

    env = getenv("RP2P_DEBUG_STREAM");
    return env && env[0] != '\0' && strcmp(env, "0") != 0;
}

/**
 * Emits one conditional debug log line for stream internals.
 * @return None.
 */
static void rp2p_stream_log(const char *fmt, ...) {
    va_list ap;

    if (!rp2p_stream_debug_enabled()) return;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}

/**
 * Returns the configured debug drop cadence for TCP stream DATA frames.
 * @return Drop cadence, or 0 when disabled.
 */
static int rp2p_stream_debug_drop_every(void) {
    const char *env;
    long every;

    env = getenv("RP2P_DEBUG_STREAM_DROP_EVERY");
    if (!rp2p_parse_u(env, 1, 1000000, &every)) return 0;
    return (int)every;
}

/**
 * Returns the configured debug reorder cadence for TCP DATA frames.
 * @return Reorder cadence, or 0 when disabled.
 */
static int rp2p_stream_debug_reorder_every(void) {
    const char *env;
    long every;

    env = getenv("RP2P_DEBUG_STREAM_REORDER_EVERY");
    if (!rp2p_parse_u(env, 1, 1000000, &every)) return 0;
    return (int)every;
}

/**
 * Decides whether to drop one outgoing DATA frame once for testing.
 * @return 1 when the frame should be dropped, 0 otherwise.
 */
static int rp2p_stream_should_drop_once(rp2p_t *ctx,
    const unsigned char *buf, size_t len)
{
    int every;
    uint8_t type;
    uint32_t seq;
    int i;
    int free_slot;

    every = rp2p_stream_debug_drop_every();
    if (every <= 0 || len < 44) return 0;
    if (rp2p_load_u32_le(buf) != RP2P_STREAM_MAGIC) return 0;
    if (buf[4] != RP2P_STREAM_VERSION) return 0;
    type = buf[5];
    if (type != RP2P_STREAM_TYPE_DATA) return 0;
    seq = rp2p_load_u32_le(buf + 24);
    free_slot = -1;
    for (i = 0; i < 256; i++) {
        if (!ctx->fault_dropped[i].used) {
            if (free_slot < 0) free_slot = i;
            continue;
        }
        if (ctx->fault_dropped[i].seq == seq &&
            memcmp(ctx->fault_dropped[i].session_id, buf + 8,
                RP2P_STREAM_SESSION_ID_SZ) == 0)
            return 0;
    }
    ctx->fault_drop_counter++;
    if ((ctx->fault_drop_counter % every) != 0) return 0;
    if (free_slot < 0) free_slot = ctx->fault_drop_counter % 256;
    ctx->fault_dropped[free_slot].used = 1;
    ctx->fault_dropped[free_slot].seq = seq;
    memcpy(ctx->fault_dropped[free_slot].session_id, buf + 8,
        RP2P_STREAM_SESSION_ID_SZ);
    rp2p_stream_log("rp2p: stream drop-test seq=%u\n", (unsigned)seq);
    return 1;
}

/**
 * Decides whether to delay one DATA frame for reordering tests.
 * @return 1 when the frame should be delayed, 0 otherwise.
 */
static int rp2p_stream_should_reorder_once(rp2p_t *ctx,
    const unsigned char *buf, size_t len)
{
    int every;
    uint8_t type;
    uint32_t seq;
    int i;
    int free_slot;

    every = rp2p_stream_debug_reorder_every();
    if (every <= 0 || len < 44) return 0;
    if (rp2p_load_u32_le(buf) != RP2P_STREAM_MAGIC) return 0;
    if (buf[4] != RP2P_STREAM_VERSION) return 0;
    type = buf[5];
    if (type != RP2P_STREAM_TYPE_DATA) return 0;
    seq = rp2p_load_u32_le(buf + 24);
    free_slot = -1;
    for (i = 0; i < 256; i++) {
        if (!ctx->fault_delayed[i].used) {
            if (free_slot < 0) free_slot = i;
            continue;
        }
        if (ctx->fault_delayed[i].seq == seq &&
            memcmp(ctx->fault_delayed[i].session_id, buf + 8,
                RP2P_STREAM_SESSION_ID_SZ) == 0)
            return 0;
    }
    ctx->fault_reorder_counter++;
    if ((ctx->fault_reorder_counter % every) != 0) return 0;
    if (free_slot < 0) free_slot = ctx->fault_reorder_counter % 256;
    ctx->fault_delayed[free_slot].used = 1;
    ctx->fault_delayed[free_slot].seq = seq;
    memcpy(ctx->fault_delayed[free_slot].session_id, buf + 8,
        RP2P_STREAM_SESSION_ID_SZ);
    rp2p_stream_log("rp2p: stream reorder-test seq=%u\n", (unsigned)seq);
    return 1;
}

/**
 * Lock.
 * @return Status code.
 */
static void rp2p_lock(rp2p_t *ctx) {
#ifdef _WIN32
    EnterCriticalSection(&ctx->mutex);
#else
    pthread_mutex_lock(&ctx->mutex);
#endif
}

/**
 * Unlock.
 * @return Status code.
 */
static void rp2p_unlock(rp2p_t *ctx) {
#ifdef _WIN32
    LeaveCriticalSection(&ctx->mutex);
#else
    pthread_mutex_unlock(&ctx->mutex);
#endif
}

/**
 * Lock global signal state.
 * @return None.
 */
static void rp2p_global_lock(void) {
#ifdef _WIN32
    AcquireSRWLockExclusive(&g_signal_mutex);
#else
    pthread_mutex_lock(&g_signal_mutex);
#endif
}

/**
 * Unlock global signal state.
 * @return None.
 */
static void rp2p_global_unlock(void) {
#ifdef _WIN32
    ReleaseSRWLockExclusive(&g_signal_mutex);
#else
    pthread_mutex_unlock(&g_signal_mutex);
#endif
}

/**
 * Loads one little-endian u16.
 * @return Decoded value.
 */
static uint16_t rp2p_load_u16_le(const unsigned char *p) {
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

/**
 * Loads one little-endian u32.
 * @return Decoded value.
 */
static uint32_t rp2p_load_u32_le(const unsigned char *p) {
    return (uint32_t)p[0] |
        ((uint32_t)p[1] << 8) |
        ((uint32_t)p[2] << 16) |
        ((uint32_t)p[3] << 24);
}

/**
 * Loads one little-endian u64.
 * @return Decoded value.
 */
static uint64_t rp2p_load_u64_le(const unsigned char *p) {
    uint64_t value;
    int i;

    value = 0;
    for (i = 7; i >= 0; i--) value = (value << 8) | p[i];
    return value;
}

/**
 * Stores one little-endian u16.
 * @return None.
 */
static void rp2p_store_u16_le(unsigned char *p, uint16_t v) {
    p[0] = (unsigned char)(v & 0xffu);
    p[1] = (unsigned char)((v >> 8) & 0xffu);
}

/**
 * Stores one little-endian u32.
 * @return None.
 */
static void rp2p_store_u32_le(unsigned char *p, uint32_t v) {
    p[0] = (unsigned char)(v & 0xffu);
    p[1] = (unsigned char)((v >> 8) & 0xffu);
    p[2] = (unsigned char)((v >> 16) & 0xffu);
    p[3] = (unsigned char)((v >> 24) & 0xffu);
}

/**
 * Stores one little-endian u64.
 * @return None.
 */
static void rp2p_store_u64_le(unsigned char *p, uint64_t value) {
    int i;

    for (i = 0; i < 8; i++) {
        p[i] = (unsigned char)(value & 0xffu);
        value >>= 8;
    }
}

/**
 * Returns a millisecond timestamp.
 * @return Monotonic-ish timestamp in milliseconds.
 */
static uint64_t rp2p_now_ms(void) {
#ifdef _WIN32
    return (uint64_t)GetTickCount64();
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)(ts.tv_nsec / 1000000);
#endif
}

/**
 * Returns a second timestamp.
 * Summary: Used for elapsed-time logic to avoid wall-clock jumps.
 * @return Monotonic-ish timestamp in seconds.
 */
static uint64_t rp2p_now_s(void) {
    return rp2p_now_ms() / 1000;
}

#ifdef RP2P_TEST_RANDOM
static unsigned char rp2p_test_random_bytes[256];
static size_t rp2p_test_random_len;
static size_t rp2p_test_random_pos;
static int rp2p_test_random_fail;
#endif

/**
 * Fills a buffer with secure random bytes.
 * @return 0 on success, -1 on error.
 */
static int rp2p_fill_random(unsigned char *buf, size_t len) {
#ifdef RP2P_TEST_RANDOM
    if (rp2p_test_random_fail) return -1;
    if (rp2p_test_random_len > 0) {
        size_t i;
        for (i = 0; i < len; i++) {
            buf[i] = rp2p_test_random_bytes[rp2p_test_random_pos %
                rp2p_test_random_len];
            rp2p_test_random_pos++;
        }
        return 0;
    }
#endif
#ifdef _WIN32
    return BCryptGenRandom(NULL, (PUCHAR)buf, (ULONG)len,
        BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0 ? 0 : -1;
#else
    size_t off = 0;
    int fd;
    ssize_t n;

    fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return -1;
    while (off < len) {
        n = read(fd, buf + off, len - off);
        if (n <= 0) {
            close(fd);
            return -1;
        }
        off += (size_t)n;
    }
    close(fd);
    return 0;
#endif
}

#ifdef RP2P_TEST_RANDOM
/**
 * Configures deterministic random bytes for test builds.
 * @param bytes Byte stream to repeat.
 * @param len   Byte stream length.
 * @return None.
 */
void rp2p_test_random_set(const unsigned char *bytes, size_t len) {
    if (!bytes || len == 0) {
        rp2p_test_random_len = 0;
        rp2p_test_random_pos = 0;
        return;
    }
    if (len > sizeof(rp2p_test_random_bytes))
        len = sizeof(rp2p_test_random_bytes);
    memcpy(rp2p_test_random_bytes, bytes, len);
    rp2p_test_random_len = len;
    rp2p_test_random_pos = 0;
    rp2p_test_random_fail = 0;
}

/**
 * Configures random-source failure for test builds.
 * @param fail Non-zero forces failure.
 * @return None.
 */
void rp2p_test_random_set_fail(int fail) {
    rp2p_test_random_fail = fail ? 1 : 0;
}
#endif

/**
 * Decodes one hex nibble.
 * @return Nibble value, or -1 on error.
 */
static int rp2p_hex_decode_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/**
 * Decodes a fixed-size hex string.
 * @return 1 on success, 0 on error.
 */
static int rp2p_hex_decode(const char *hex, unsigned char *out, size_t out_len) {
    size_t i;

    if (!hex || !out) return 0;
    for (i = 0; i < out_len; i++) {
        int hi = rp2p_hex_decode_nibble(hex[i * 2]);
        int lo = rp2p_hex_decode_nibble(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return 0;
        out[i] = (unsigned char)((hi << 4) | lo);
    }
    return 1;
}

/**
 * Generates one secure stream session identifier.
 * @return 1 on success, 0 on error.
 */
static int rp2p_stream_make_session_id(unsigned char out[RP2P_STREAM_SESSION_ID_SZ],
    char hex[RP2P_STREAM_SESSION_ID_SZ * 2 + 1])
{
    if (rp2p_fill_random(out, RP2P_STREAM_SESSION_ID_SZ) != 0) return 0;
    return rp2p_hex_encode(out, RP2P_STREAM_SESSION_ID_SZ, hex,
        RP2P_STREAM_SESSION_ID_SZ * 2 + 1);
}

/**
 * Builds one AEAD nonce from session direction and sequence.
 * @return None.
 */
static void rp2p_stream_nonce(unsigned char nonce[RP2P_STREAM_NONCE_SZ],
    const unsigned char session_id[RP2P_STREAM_SESSION_ID_SZ],
    uint8_t direction, uint32_t seq)
{
    memset(nonce, 0, RP2P_STREAM_NONCE_SZ);
    memcpy(nonce, session_id, RP2P_STREAM_SESSION_ID_SZ);
    nonce[16] = direction;
    rp2p_store_u32_le(nonce + 20, seq);
}

/**
 * Reports the currently advertised receive window.
 * @return Available receive slots.
 */
static uint16_t rp2p_stream_advertised_window(const rp2p_stream_state_t *st) {
    int used = 0;
    int i;

    for (i = 0; i < RP2P_STREAM_RECV_WINDOW; i++) {
        if (st->in.slots[i].used) used++;
    }
    if (used >= RP2P_STREAM_RECV_WINDOW) return 0;
    return (uint16_t)(RP2P_STREAM_RECV_WINDOW - used);
}

/**
 * Initializes one TCP stream state block.
 * @return None.
 */
static void rp2p_stream_init(rp2p_stream_state_t *st, int initiator,
    const unsigned char session_id[RP2P_STREAM_SESSION_ID_SZ],
    const char *session_hex, const char *secret)
{
    memset(st, 0, sizeof(*st));
    st->enabled = 1;
    st->initiator = initiator;
    st->tx_direction = initiator ? RP2P_STREAM_DIR_C2S : RP2P_STREAM_DIR_S2C;
    st->rx_direction = initiator ? RP2P_STREAM_DIR_S2C : RP2P_STREAM_DIR_C2S;
    st->ctrl_seq = 1;
    memcpy(st->session_id, session_id, RP2P_STREAM_SESSION_ID_SZ);
    if (session_hex) {
        memcpy(st->session_hex, session_hex,
            RP2P_STREAM_SESSION_ID_SZ * 2);
        st->session_hex[RP2P_STREAM_SESSION_ID_SZ * 2] = '\0';
    }
    st->out.next_seq = 1;
    st->in.next_expected = 1;
    st->last_rx_ms = rp2p_now_ms();
    st->last_tx_ms = st->last_rx_ms;
    st->last_ack_ms = st->last_rx_ms;
    st->last_hello_ms = 0;
    st->rto_ms = RP2P_STREAM_RTO_MS;
    if (secret && secret[0]) {
        crypto_blake2b(st->crypto.psk, sizeof(st->crypto.psk),
            (const unsigned char *)secret, strlen(secret));
        st->crypto.authenticated = 1;
    }
}

/**
 * Sends one raw packet over the selected transport.
 * @return 0 on success, -1 on error.
 */
static int rp2p_stream_send_raw(rp2p_t *ctx, rp2p_fd_t fd,
    const struct sockaddr_storage *peer_addr, const unsigned char *buf, size_t len)
{
    socklen_t peer_len;

    if (!ctx) return -1;
    if (len > RP2P_STREAM_MAX_FRAME) return -1;
    peer_len = rp2p_sockaddr_len(peer_addr);
    if (peer_len == 0) return -1;

    if (rp2p_stream_should_drop_once(ctx, buf, len)) return 0;
    if (!ctx->fault_pending.used &&
        rp2p_stream_should_reorder_once(ctx, buf, len))
    {
        ctx->fault_pending.used = 1;
        ctx->fault_pending.len = len;
        memcpy(ctx->fault_pending.frame, buf, len);
        return 0;
    }
    if (sendto(fd, (const char *)buf, len, 0,
        (const struct sockaddr *)peer_addr, peer_len) < 0)
        return -1;
    if (ctx->fault_pending.used) {
        if (sendto(fd, (const char *)ctx->fault_pending.frame,
            ctx->fault_pending.len, 0,
            (const struct sockaddr *)peer_addr, peer_len) < 0)
            return -1;
        ctx->fault_pending.used = 0;
    }
    return 0;
}

/**
 * Builds transcript input for session key derivation.
 * @return None.
 */
static void rp2p_stream_build_kdf_input(unsigned char *buf, size_t *len,
    const rp2p_stream_state_t *st)
{
    const unsigned char *init_pub;
    const unsigned char *resp_pub;
    const unsigned char *init_nonce;
    const unsigned char *resp_nonce;

    init_pub = st->initiator ? st->crypto.local_public : st->crypto.peer_public;
    resp_pub = st->initiator ? st->crypto.peer_public : st->crypto.local_public;
    init_nonce = st->initiator ? st->crypto.local_nonce : st->crypto.peer_nonce;
    resp_nonce = st->initiator ? st->crypto.peer_nonce : st->crypto.local_nonce;

    memcpy(buf, st->session_id, RP2P_STREAM_SESSION_ID_SZ);
    memcpy(buf + 16, init_pub, 32);
    memcpy(buf + 48, resp_pub, 32);
    memcpy(buf + 80, init_nonce, RP2P_STREAM_HELLO_NONCE_SZ);
    memcpy(buf + 96, resp_nonce, RP2P_STREAM_HELLO_NONCE_SZ);
    *len = 112;
}

/**
 * Derives one directional key from shared secret material.
 * @return None.
 */
static void rp2p_stream_derive_key(unsigned char out[32], const unsigned char shared[32],
    const unsigned char *kdf, size_t kdf_len, const char *label)
{
    unsigned char msg[160];
    size_t label_len = strlen(label);

    memcpy(msg, kdf, kdf_len);
    memcpy(msg + kdf_len, label, label_len);
    crypto_blake2b_keyed(out, 32, shared, 32, msg, kdf_len + label_len);
    crypto_wipe(msg, sizeof(msg));
}

/**
 * Completes stream key derivation when peer material arrives.
 * @return 1 when ready, 0 when peer material is incomplete.
 */
static int rp2p_stream_crypto_ready(rp2p_stream_state_t *st) {
    unsigned char shared[32];
    unsigned char raw_shared[32];
    unsigned char kdf[112];
    size_t kdf_len;

    if (st->crypto.ready) return 1;
    if (st->crypto.peer_public[0] == 0 &&
        memcmp(st->crypto.peer_public, (unsigned char[32]){0}, 32) == 0)
        return 0;
    if (crypto_verify32(st->crypto.local_public, st->crypto.peer_public) == 0)
        return 0;
    crypto_x25519(raw_shared, st->crypto.local_secret,
        st->crypto.peer_public);
    if (memcmp(raw_shared, (unsigned char[32]){0}, sizeof(raw_shared)) == 0) {
        crypto_wipe(raw_shared, sizeof(raw_shared));
        return 0;
    }
    if (st->crypto.authenticated) {
        crypto_blake2b_keyed(shared, sizeof(shared), st->crypto.psk,
            sizeof(st->crypto.psk), raw_shared, sizeof(raw_shared));
    } else {
        memcpy(shared, raw_shared, sizeof(shared));
    }
    rp2p_stream_build_kdf_input(kdf, &kdf_len, st);
    if (st->initiator) {
        rp2p_stream_derive_key(st->crypto.tx_key, shared, kdf, kdf_len, "c2s");
        rp2p_stream_derive_key(st->crypto.rx_key, shared, kdf, kdf_len, "s2c");
    } else {
        rp2p_stream_derive_key(st->crypto.tx_key, shared, kdf, kdf_len, "s2c");
        rp2p_stream_derive_key(st->crypto.rx_key, shared, kdf, kdf_len, "c2s");
    }
    st->crypto.ready = 1;
    st->ready = 1;
    rp2p_stream_log("rp2p: tcp session %s stream ready\n", st->session_hex);
    crypto_wipe(shared, sizeof(shared));
    crypto_wipe(raw_shared, sizeof(raw_shared));
    crypto_wipe(kdf, sizeof(kdf));
    return 1;
}

/**
 * Generates local ephemeral keys and hello nonce.
 * @return 1 on success, 0 on error.
 */
static int rp2p_stream_crypto_init(rp2p_stream_state_t *st) {
    if (rp2p_fill_random(st->crypto.local_secret, 32) != 0) return 0;
    if (rp2p_fill_random(st->crypto.local_nonce,
        RP2P_STREAM_HELLO_NONCE_SZ) != 0) return 0;
    crypto_x25519_public_key(st->crypto.local_public, st->crypto.local_secret);
    return 1;
}

/**
 * Counts currently unacknowledged reliable frames.
 * @return In-flight frame count.
 */
static int rp2p_stream_inflight(const rp2p_stream_state_t *st) {
    int i;
    int n = 0;
    for (i = 0; i < RP2P_STREAM_SEND_WINDOW; i++) {
        if (st->out.slots[i].used) n++;
    }
    return n;
}

/**
 * Reports whether the local TCP side may queue more data.
 * @return 1 when more data may be read, 0 otherwise.
 */
static int rp2p_stream_can_send_data(const rp2p_stream_state_t *st) {
    return st->ready && !st->out.local_eof &&
        rp2p_stream_inflight(st) < RP2P_STREAM_SEND_WINDOW;
}

/**
 * Packs one plaintext hello frame.
 * @return Encoded byte length.
 */
static size_t rp2p_stream_pack_hello(uint8_t type, const rp2p_stream_state_t *st,
    unsigned char *out)
{
    unsigned char tag[RP2P_STREAM_HELLO_TAG_SZ];

    rp2p_store_u32_le(out, RP2P_STREAM_MAGIC);
    out[4] = RP2P_STREAM_VERSION;
    out[5] = type;
    out[6] = st->tx_direction;
    out[7] = st->crypto.authenticated ? 1 : 0;
    memcpy(out + 8, st->session_id, RP2P_STREAM_SESSION_ID_SZ);
    memcpy(out + 24, st->crypto.local_public, 32);
    memcpy(out + 56, st->crypto.local_nonce, RP2P_STREAM_HELLO_NONCE_SZ);
    if (!st->crypto.authenticated) return RP2P_STREAM_HELLO_BASE_SZ;
    crypto_blake2b_keyed(tag, sizeof(tag), st->crypto.psk,
        sizeof(st->crypto.psk), out, RP2P_STREAM_HELLO_BASE_SZ);
    memcpy(out + RP2P_STREAM_HELLO_BASE_SZ, tag, sizeof(tag));
    crypto_wipe(tag, sizeof(tag));
    return RP2P_STREAM_HELLO_BASE_SZ + RP2P_STREAM_HELLO_TAG_SZ;
}

/**
 * Parses one plaintext hello frame.
 * @return 1 on success, 0 on mismatch.
 */
static int rp2p_stream_unpack_hello(const rp2p_stream_state_t *st,
    const unsigned char *buf, size_t len,
    uint8_t *type, uint8_t *direction,
    unsigned char session_id[RP2P_STREAM_SESSION_ID_SZ],
    unsigned char peer_public[32],
    unsigned char peer_nonce[RP2P_STREAM_HELLO_NONCE_SZ])
{
    unsigned char tag[RP2P_STREAM_HELLO_TAG_SZ];
    int has_auth;

    if (len < RP2P_STREAM_HELLO_BASE_SZ) return 0;
    if (rp2p_load_u32_le(buf) != RP2P_STREAM_MAGIC) return 0;
    if (buf[4] != RP2P_STREAM_VERSION) return 0;
    if ((buf[7] & ~1u) != 0) return 0;
    has_auth = (buf[7] & 1) != 0;
    if (has_auth != st->crypto.authenticated) return 0;
    if (has_auth) {
        if (len != RP2P_STREAM_HELLO_BASE_SZ + RP2P_STREAM_HELLO_TAG_SZ)
            return 0;
        crypto_blake2b_keyed(tag, sizeof(tag), st->crypto.psk,
            sizeof(st->crypto.psk), buf, RP2P_STREAM_HELLO_BASE_SZ);
        if (crypto_verify16(tag,
            buf + RP2P_STREAM_HELLO_BASE_SZ) != 0)
        {
            crypto_wipe(tag, sizeof(tag));
            return 0;
        }
        crypto_wipe(tag, sizeof(tag));
    } else if (len != RP2P_STREAM_HELLO_BASE_SZ) {
        return 0;
    }
    *type = buf[5];
    *direction = buf[6];
    memcpy(session_id, buf + 8, RP2P_STREAM_SESSION_ID_SZ);
    memcpy(peer_public, buf + 24, 32);
    memcpy(peer_nonce, buf + 56, RP2P_STREAM_HELLO_NONCE_SZ);
    return 1;
}

/**
 * Encodes one authenticated stream header.
 * @return Encoded header length.
 */
static size_t rp2p_stream_pack_header(const rp2p_stream_header_t *hdr,
    unsigned char *out)
{
    rp2p_store_u32_le(out, RP2P_STREAM_MAGIC);
    out[4] = RP2P_STREAM_VERSION;
    out[5] = hdr->type;
    out[6] = hdr->direction;
    out[7] = 0;
    memcpy(out + 8, hdr->session_id, RP2P_STREAM_SESSION_ID_SZ);
    rp2p_store_u32_le(out + 24, hdr->seq);
    rp2p_store_u32_le(out + 28, hdr->ack);
    rp2p_store_u16_le(out + 32, hdr->window);
    rp2p_store_u16_le(out + 34, hdr->payload_len);
    rp2p_store_u32_le(out + 36, hdr->gap_start);
    rp2p_store_u32_le(out + 40, hdr->gap_end);
    return 44;
}

/**
 * Parses one authenticated stream header.
 * @return 1 on success, 0 on error.
 */
static int rp2p_stream_unpack_header(const unsigned char *buf, size_t len,
    rp2p_stream_header_t *hdr)
{
    if (len < 60) return 0;
    if (rp2p_load_u32_le(buf) != RP2P_STREAM_MAGIC) return 0;
    if (buf[4] != RP2P_STREAM_VERSION) return 0;
    if (buf[7] != 0) return 0;
    hdr->type = buf[5];
    hdr->direction = buf[6];
    memcpy(hdr->session_id, buf + 8, RP2P_STREAM_SESSION_ID_SZ);
    hdr->seq = rp2p_load_u32_le(buf + 24);
    hdr->ack = rp2p_load_u32_le(buf + 28);
    hdr->window = rp2p_load_u16_le(buf + 32);
    hdr->payload_len = rp2p_load_u16_le(buf + 34);
    hdr->gap_start = rp2p_load_u32_le(buf + 36);
    hdr->gap_end = rp2p_load_u32_le(buf + 40);
    if (hdr->type < RP2P_STREAM_TYPE_DATA ||
        hdr->type > RP2P_STREAM_TYPE_PONG || hdr->seq == 0)
        return 0;
    if ((size_t)(60 + hdr->payload_len) > len) return 0;
    return 1;
}

/**
 * Encrypts one post-handshake stream packet.
 * @return 1 on success, 0 on error.
 */
static int rp2p_stream_encrypt_packet(rp2p_stream_state_t *st,
    const rp2p_stream_header_t *hdr, const unsigned char *plain,
    size_t plain_len, unsigned char *out, size_t *out_len)
{
    unsigned char nonce[RP2P_STREAM_NONCE_SZ];
    size_t ad_len = rp2p_stream_pack_header(hdr, out);
    unsigned char *mac = out + ad_len;
    unsigned char *cipher = out + ad_len + RP2P_STREAM_TAG_SZ;

    if (ad_len + RP2P_STREAM_TAG_SZ + plain_len > RP2P_STREAM_MAX_FRAME)
        return 0;
    rp2p_stream_nonce(nonce, hdr->session_id, hdr->direction, hdr->seq);
    crypto_aead_lock(cipher, mac, st->crypto.tx_key, nonce, out, ad_len,
        plain, plain_len);
    *out_len = ad_len + RP2P_STREAM_TAG_SZ + plain_len;
    return 1;
}

/**
 * Authenticates and decrypts one post-handshake stream packet.
 * @return 1 on success, 0 on authentication failure.
 */
static int rp2p_stream_decrypt_packet(rp2p_stream_state_t *st,
    const rp2p_stream_header_t *hdr, const unsigned char *buf,
    unsigned char *plain)
{
    unsigned char nonce[RP2P_STREAM_NONCE_SZ];
    size_t ad_len = 44;
    const unsigned char *mac = buf + ad_len;
    const unsigned char *cipher = buf + ad_len + RP2P_STREAM_TAG_SZ;

    rp2p_stream_nonce(nonce, hdr->session_id, hdr->direction, hdr->seq);
    return crypto_aead_unlock(plain, mac, st->crypto.rx_key, nonce, buf,
        ad_len, cipher, hdr->payload_len) == 0;
}

/**
 * Initializes raw UDP authentication state for one rendezvous session.
 * @return 1 on success, 0 on invalid input.
 */
static int rp2p_udp_crypto_init(rp2p_udp_crypto_t *state,
    const char *secret, const char *session_token, int initiator)
{
    unsigned char secret_key[32];
    unsigned char material[RP2P_CTRL_SESSION_MAX + 16];
    size_t token_len;

    memset(state, 0, sizeof(*state));
    if (!secret || !secret[0]) return 1;
    if (!session_token) return 0;
    token_len = strlen(session_token);
    if (token_len == 0 || token_len > RP2P_CTRL_SESSION_MAX) return 0;
    memcpy(material, "rp2p-udp-v1:", 12);
    memcpy(material + 12, session_token, token_len);
    crypto_blake2b(secret_key, sizeof(secret_key),
        (const unsigned char *)secret, strlen(secret));
    crypto_blake2b_keyed(state->key, sizeof(state->key), secret_key,
        sizeof(secret_key), material, 12 + token_len);
    crypto_blake2b(state->session_id, sizeof(state->session_id), material,
        12 + token_len);
    state->enabled = 1;
    state->tx_direction = initiator ? RP2P_STREAM_DIR_C2S :
        RP2P_STREAM_DIR_S2C;
    state->rx_direction = initiator ? RP2P_STREAM_DIR_S2C :
        RP2P_STREAM_DIR_C2S;
    state->tx_seq = 1;
    crypto_wipe(secret_key, sizeof(secret_key));
    crypto_wipe(material, sizeof(material));
    return 1;
}

/**
 * Builds one raw UDP AEAD nonce.
 * @return None.
 */
static void rp2p_udp_nonce(unsigned char nonce[24],
    const rp2p_udp_crypto_t *state, uint8_t direction, uint64_t seq)
{
    memset(nonce, 0, 24);
    memcpy(nonce, state->session_id, sizeof(state->session_id));
    nonce[8] = direction;
    rp2p_store_u64_le(nonce + 16, seq);
}

/**
 * Records one authenticated sequence in the replay window.
 * @return 1 for a new sequence, 0 for stale or duplicate input.
 */
static int rp2p_udp_replay_accept(rp2p_udp_crypto_t *state, uint64_t seq) {
    uint64_t delta;

    if (seq == 0) return 0;
    if (seq > state->rx_max) {
        delta = seq - state->rx_max;
        state->rx_window = delta >= 64 ? 1 :
            (state->rx_window << delta) | 1;
        state->rx_max = seq;
        return 1;
    }
    delta = state->rx_max - seq;
    if (delta >= 64 || (state->rx_window & ((uint64_t)1 << delta)) != 0)
        return 0;
    state->rx_window |= (uint64_t)1 << delta;
    return 1;
}

/**
 * Encrypts one raw UDP payload when tunnel security is enabled.
 * @return Encoded length, or zero on overflow.
 */
static size_t rp2p_udp_encrypt(rp2p_udp_crypto_t *state,
    const unsigned char *plain, size_t plain_len, unsigned char *out,
    size_t out_cap)
{
    unsigned char nonce[24];
    uint64_t seq;

    if (!state->enabled) {
        if (plain_len > out_cap) return 0;
        memcpy(out, plain, plain_len);
        return plain_len;
    }
    if (out_cap < RP2P_UDP_HEADER_SZ + RP2P_UDP_TAG_SZ ||
        plain_len > out_cap - RP2P_UDP_HEADER_SZ - RP2P_UDP_TAG_SZ)
        return 0;
    if (state->tx_seq == 0) return 0;
    seq = state->tx_seq++;
    rp2p_store_u32_le(out, RP2P_UDP_MAGIC);
    out[4] = RP2P_UDP_VERSION;
    out[5] = state->tx_direction;
    out[6] = 0;
    out[7] = 0;
    memcpy(out + 8, state->session_id, sizeof(state->session_id));
    rp2p_store_u64_le(out + 16, seq);
    rp2p_udp_nonce(nonce, state, state->tx_direction, seq);
    crypto_aead_lock(out + RP2P_UDP_HEADER_SZ + RP2P_UDP_TAG_SZ,
        out + RP2P_UDP_HEADER_SZ, state->key, nonce, out,
        RP2P_UDP_HEADER_SZ, plain, plain_len);
    return RP2P_UDP_HEADER_SZ + RP2P_UDP_TAG_SZ + plain_len;
}

/**
 * Authenticates and decrypts one raw UDP payload with replay rejection.
 * @return Plaintext length, or zero on malformed, stale, or forged input.
 */
static size_t rp2p_udp_decrypt(rp2p_udp_crypto_t *state,
    const unsigned char *packet, size_t packet_len, unsigned char *plain,
    size_t plain_cap)
{
    unsigned char nonce[24];
    size_t plain_len;
    uint64_t seq;

    if (!state->enabled) {
        if (packet_len > plain_cap) return 0;
        memcpy(plain, packet, packet_len);
        return packet_len;
    }
    if (packet_len < RP2P_UDP_HEADER_SZ + RP2P_UDP_TAG_SZ) return 0;
    if (rp2p_load_u32_le(packet) != RP2P_UDP_MAGIC ||
        packet[4] != RP2P_UDP_VERSION ||
        packet[5] != state->rx_direction || packet[6] != 0 || packet[7] != 0)
        return 0;
    if (memcmp(packet + 8, state->session_id,
        sizeof(state->session_id)) != 0)
        return 0;
    plain_len = packet_len - RP2P_UDP_HEADER_SZ - RP2P_UDP_TAG_SZ;
    if (plain_len > plain_cap) return 0;
    seq = rp2p_load_u64_le(packet + 16);
    rp2p_udp_nonce(nonce, state, state->rx_direction, seq);
    if (crypto_aead_unlock(plain, packet + RP2P_UDP_HEADER_SZ, state->key,
        nonce, packet, RP2P_UDP_HEADER_SZ,
        packet + RP2P_UDP_HEADER_SZ + RP2P_UDP_TAG_SZ, plain_len) != 0)
        return 0;
    if (!rp2p_udp_replay_accept(state, seq)) {
        crypto_wipe(plain, plain_len);
        return 0;
    }
    return plain_len;
}

/**
 * Finds one receive slot by sequence number.
 * @return Matching slot, or NULL.
 */
static rp2p_stream_recv_slot_t *rp2p_stream_find_recv_slot(
    rp2p_stream_state_t *st, uint32_t seq)
{
    int i;
    for (i = 0; i < RP2P_STREAM_RECV_WINDOW; i++) {
        if (st->in.slots[i].used && st->in.slots[i].seq == seq)
            return &st->in.slots[i];
    }
    return NULL;
}

/**
 * Allocates one free receive slot.
 * @return Free slot, or NULL.
 */
static rp2p_stream_recv_slot_t *rp2p_stream_alloc_recv_slot(
    rp2p_stream_state_t *st)
{
    int i;
    for (i = 0; i < RP2P_STREAM_RECV_WINDOW; i++) {
        if (!st->in.slots[i].used) return &st->in.slots[i];
    }
    return NULL;
}

/**
 * Allocates one free resend slot.
 * @return Free slot, or NULL.
 */
static rp2p_stream_send_slot_t *rp2p_stream_alloc_send_slot(
    rp2p_stream_state_t *st)
{
    int i;
    for (i = 0; i < RP2P_STREAM_SEND_WINDOW; i++) {
        if (!st->out.slots[i].used) return &st->out.slots[i];
    }
    return NULL;
}

/**
 * Drops all resend slots covered by a cumulative ACK.
 * @return None.
 */
static void rp2p_stream_ack_until(rp2p_stream_state_t *st, uint32_t ack) {
    uint64_t now;
    int i;
    int sampled;

    now = rp2p_now_ms();
    sampled = 0;
    for (i = 0; i < RP2P_STREAM_SEND_WINDOW; i++) {
        if (st->out.slots[i].used && st->out.slots[i].seq <= ack) {
            if (!sampled && st->out.slots[i].attempts == 1 &&
                now >= st->out.slots[i].last_tx_ms)
            {
                uint64_t sample = now - st->out.slots[i].last_tx_ms;
                uint64_t delta;

                if (sample == 0) sample = 1;
                if (st->srtt_ms == 0) {
                    st->srtt_ms = sample;
                    st->rttvar_ms = sample / 2;
                } else {
                    delta = st->srtt_ms > sample ? st->srtt_ms - sample :
                        sample - st->srtt_ms;
                    st->rttvar_ms = (3 * st->rttvar_ms + delta) / 4;
                    st->srtt_ms = (7 * st->srtt_ms + sample) / 8;
                }
                st->rto_ms = st->srtt_ms + 4 * st->rttvar_ms;
                if (st->rto_ms < RP2P_STREAM_RTO_MIN_MS)
                    st->rto_ms = RP2P_STREAM_RTO_MIN_MS;
                if (st->rto_ms > RP2P_STREAM_RTO_MAX_MS)
                    st->rto_ms = RP2P_STREAM_RTO_MAX_MS;
                sampled = 1;
            }
            if (st->out.slots[i].type == RP2P_STREAM_TYPE_FIN)
                st->out.fin_acked = 1;
            st->out.slots[i].used = 0;
        }
    }
}

/**
 * Sends one encrypted control frame.
 * @return 0 on success, -1 on error.
 */
static int rp2p_stream_send_control(rp2p_t *ctx, rp2p_fd_t fd,
    const struct sockaddr_storage *peer_addr,
    rp2p_stream_state_t *st, uint8_t type, uint32_t seq,
    uint32_t gap_start, uint32_t gap_end)
{
    rp2p_stream_header_t hdr;
    unsigned char frame[RP2P_STREAM_MAX_FRAME];
    size_t frame_len;

    memset(&hdr, 0, sizeof(hdr));
    hdr.type = type;
    hdr.direction = st->tx_direction;
    hdr.seq = seq ? seq : st->ctrl_seq++;
    hdr.ack = st->in.next_expected ? st->in.next_expected - 1 : 0;
    hdr.window = rp2p_stream_advertised_window(st);
    hdr.payload_len = 0;
    hdr.gap_start = gap_start;
    hdr.gap_end = gap_end;
    memcpy(hdr.session_id, st->session_id, RP2P_STREAM_SESSION_ID_SZ);

    if (!rp2p_stream_encrypt_packet(st, &hdr, NULL, 0, frame, &frame_len))
        return -1;
    if (rp2p_stream_send_raw(ctx, fd, peer_addr, frame, frame_len) != 0)
        return -1;
    st->last_tx_ms = rp2p_now_ms();
    st->last_ack_ms = st->last_tx_ms;
    return 0;
}

/**
 * Sends one plaintext hello or hello-ack frame.
 * @return 0 on success, -1 on error.
 */
static int rp2p_stream_send_hello(rp2p_t *ctx, rp2p_fd_t fd,
    const struct sockaddr_storage *peer_addr,
    rp2p_stream_state_t *st, uint8_t type)
{
    unsigned char frame[96];
    size_t frame_len;

    frame_len = rp2p_stream_pack_hello(type, st, frame);
    if (rp2p_stream_send_raw(ctx, fd, peer_addr, frame, frame_len) != 0)
        return -1;
    st->hello_sent = 1;
    st->last_hello_ms = rp2p_now_ms();
    st->last_tx_ms = st->last_hello_ms;
    return 0;
}

/**
 * Queues and transmits one reliable DATA or FIN frame.
 * @return 0 on success, -1 on error.
 */
static int rp2p_stream_queue_reliable(rp2p_t *ctx, rp2p_fd_t fd,
    const struct sockaddr_storage *peer_addr,
    rp2p_stream_state_t *st, uint8_t type,
    const unsigned char *plain, size_t plain_len)
{
    rp2p_stream_send_slot_t *slot;
    rp2p_stream_header_t hdr;
    size_t frame_len;

    if (plain_len > RP2P_STREAM_MAX_PAYLOAD) return -1;
    slot = rp2p_stream_alloc_send_slot(st);
    if (!slot) return -1;

    memset(&hdr, 0, sizeof(hdr));
    hdr.type = type;
    hdr.direction = st->tx_direction;
    hdr.seq = st->out.next_seq++;
    hdr.ack = st->in.next_expected ? st->in.next_expected - 1 : 0;
    hdr.window = rp2p_stream_advertised_window(st);
    hdr.payload_len = (uint16_t)plain_len;
    memcpy(hdr.session_id, st->session_id, RP2P_STREAM_SESSION_ID_SZ);

    if (!rp2p_stream_encrypt_packet(st, &hdr, plain, plain_len,
        slot->frame, &frame_len))
        return -1;
    slot->used = 1;
    slot->type = type;
    slot->seq = hdr.seq;
    slot->attempts = 1;
    slot->frame_len = frame_len;
    slot->last_tx_ms = rp2p_now_ms();

    if (rp2p_stream_send_raw(ctx, fd, peer_addr, slot->frame,
        slot->frame_len) != 0) {
        slot->used = 0;
        return -1;
    }
    st->last_tx_ms = slot->last_tx_ms;
    if (type == RP2P_STREAM_TYPE_FIN) st->out.fin_sent = 1;
    return 0;
}

/**
 * Delivers newly contiguous inbound data to the local TCP socket.
 * @return 0 on success, -1 on error.
 */
static int rp2p_stream_flush_contiguous(rp2p_stream_state_t *st,
    rp2p_fd_t tcp_fd)
{
    for (;;) {
        rp2p_stream_recv_slot_t *slot =
            rp2p_stream_find_recv_slot(st, st->in.next_expected);
        if (!slot) break;
        if (slot->type == RP2P_STREAM_TYPE_FIN) {
            st->in.remote_fin = 1;
            st->in.next_expected++;
            slot->used = 0;
            rp2p_shutdown_write(tcp_fd);
            continue;
        }
        if (slot->len > 0 && rp2p_write_all(tcp_fd,
            (const char *)slot->data, slot->len) != 0)
            return -1;
        st->in.next_expected++;
        slot->used = 0;
    }
    return 0;
}

/**
 * Stores one inbound DATA or FIN frame in the receive window.
 * @return 0 on success, -1 on overflow.
 */
static int rp2p_stream_store_inbound(rp2p_stream_state_t *st,
    uint8_t type, uint32_t seq, const unsigned char *plain, size_t plain_len)
{
    rp2p_stream_recv_slot_t *slot;

    if (seq < st->in.next_expected) return 0;
    if (rp2p_stream_find_recv_slot(st, seq)) return 0;
    slot = rp2p_stream_alloc_recv_slot(st);
    if (!slot) return -1;
    slot->used = 1;
    slot->type = type;
    slot->seq = seq;
    slot->len = (uint16_t)plain_len;
    if (plain_len > 0) memcpy(slot->data, plain, plain_len);
    return 0;
}

/**
 * Retransmits a requested missing range.
 * @return 0 on success, -1 on transport error.
 */
static int rp2p_stream_note_sack(rp2p_t *ctx, rp2p_fd_t fd,
    const struct sockaddr_storage *peer_addr,
    rp2p_stream_state_t *st, uint32_t gap_start, uint32_t gap_end)
{
    int i;

    if (gap_start == 0 || gap_end < gap_start) return 0;
    if (gap_start >= st->out.next_seq) return 0;

    for (i = 0; i < RP2P_STREAM_SEND_WINDOW; i++) {
        rp2p_stream_send_slot_t *slot = &st->out.slots[i];
        if (!slot->used) continue;
        if (slot->seq < gap_start || slot->seq > gap_end) continue;
        if (slot->attempts >= RP2P_STREAM_MAX_RETRIES) continue;

        if (rp2p_stream_send_raw(ctx, fd, peer_addr, slot->frame,
            slot->frame_len) == 0) {
            slot->attempts++;
            slot->last_tx_ms = rp2p_now_ms();
            st->last_tx_ms = slot->last_tx_ms;
        }
    }
    return 0;
}

/**
 * Processes one inbound stream packet.
 * @return 0 on success, -1 on session failure.
 */
static int rp2p_stream_process_packet(rp2p_t *ctx, rp2p_fd_t fd,
    const struct sockaddr_storage *peer_addr,
    rp2p_stream_state_t *st, rp2p_fd_t tcp_fd,
    const unsigned char *buf, size_t len)
{
    rp2p_stream_header_t hdr;
    unsigned char plain[RP2P_STREAM_MAX_PAYLOAD];
    uint8_t hello_type;
    uint8_t hello_dir;
    unsigned char hello_sid[RP2P_STREAM_SESSION_ID_SZ];
    unsigned char hello_pub[32];
    unsigned char hello_nonce[RP2P_STREAM_HELLO_NONCE_SZ];

    if (rp2p_stream_unpack_hello(st, buf, len, &hello_type, &hello_dir,
        hello_sid, hello_pub, hello_nonce))
    {
        if ((hello_type == RP2P_STREAM_TYPE_HELLO ||
            hello_type == RP2P_STREAM_TYPE_HELLO_ACK) &&
            hello_dir == st->rx_direction &&
            memcmp(hello_sid, st->session_id, RP2P_STREAM_SESSION_ID_SZ) == 0)
        {
            memcpy(st->crypto.peer_public, hello_pub, 32);
            memcpy(st->crypto.peer_nonce, hello_nonce,
                RP2P_STREAM_HELLO_NONCE_SZ);
            st->hello_acked = (hello_type == RP2P_STREAM_TYPE_HELLO_ACK);
            st->last_rx_ms = rp2p_now_ms();
            rp2p_stream_log("rp2p: stream selected endpoint %s\n",
                st->session_hex);
            rp2p_stream_crypto_ready(st);
            if (hello_type == RP2P_STREAM_TYPE_HELLO) {
                if (rp2p_stream_send_hello(ctx, fd, peer_addr, st,
                    RP2P_STREAM_TYPE_HELLO_ACK) != 0)
                    return -1;
            }
            return 0;
        }
    }

    if (!rp2p_stream_unpack_header(buf, len, &hdr)) return 0;
    if (memcmp(hdr.session_id, st->session_id, RP2P_STREAM_SESSION_ID_SZ) != 0)
        return 0;
    if (!st->ready) return 0;
    if (hdr.direction != st->rx_direction) return 0;

    if (hdr.payload_len > RP2P_STREAM_MAX_PAYLOAD) return 0;
    if (len != 44 + RP2P_STREAM_TAG_SZ + (size_t)hdr.payload_len) return 0;
    if (hdr.type != RP2P_STREAM_TYPE_DATA && hdr.payload_len != 0) return 0;

    if (!rp2p_stream_decrypt_packet(st, &hdr, buf, plain)) return -1;

    st->last_rx_ms = rp2p_now_ms();
    rp2p_stream_ack_until(st, hdr.ack);

    if (hdr.type == RP2P_STREAM_TYPE_SACK) {
        if (hdr.gap_start != 0 && hdr.gap_end >= hdr.gap_start)
            return rp2p_stream_note_sack(ctx, fd, peer_addr, st,
                hdr.gap_start, hdr.gap_end);
        return 0;
    }
    if (hdr.type == RP2P_STREAM_TYPE_ACK || hdr.type == RP2P_STREAM_TYPE_PONG)
        return 0;
    if (hdr.type == RP2P_STREAM_TYPE_RESET) {
        st->reset_received = 1;
        return -1;
    }
    if (hdr.type == RP2P_STREAM_TYPE_PING) {
        return rp2p_stream_send_control(ctx, fd, peer_addr, st,
            RP2P_STREAM_TYPE_PONG, 0, 0, 0);
    }
    if (hdr.type != RP2P_STREAM_TYPE_DATA && hdr.type != RP2P_STREAM_TYPE_FIN)
        return 0;

    rp2p_stream_log("rp2p: stream rx seq=%u len=%u\n", (unsigned)hdr.seq,
        (unsigned)hdr.payload_len);

    if (hdr.seq > st->in.next_expected) {
        rp2p_stream_log("rp2p: stream gap detected expected=%u got=%u\n",
            (unsigned)st->in.next_expected, (unsigned)hdr.seq);
        if (rp2p_stream_store_inbound(st, hdr.type, hdr.seq, plain,
            hdr.payload_len) != 0)
            return -1;
        return rp2p_stream_send_control(ctx, fd, peer_addr, st,
            RP2P_STREAM_TYPE_SACK, 0,
            st->in.next_expected, hdr.seq - 1);
    }
    if (hdr.seq < st->in.next_expected) {
        return rp2p_stream_send_control(ctx, fd, peer_addr, st,
            RP2P_STREAM_TYPE_ACK, 0, 0, 0);
    }

    if (rp2p_stream_store_inbound(st, hdr.type, hdr.seq, plain,
        hdr.payload_len) != 0)
        return -1;
    if (rp2p_stream_flush_contiguous(st, tcp_fd) != 0) return -1;
    if (hdr.type == RP2P_STREAM_TYPE_FIN) {
        if (rp2p_stream_send_control(ctx, fd, peer_addr, st,
            RP2P_STREAM_TYPE_FIN_ACK, 0,
            0, 0) != 0)
            return -1;
        st->in.remote_fin_acked = 1;
    } else if (rp2p_now_ms() - st->last_ack_ms >= RP2P_STREAM_ACK_MS) {
        if (rp2p_stream_send_control(ctx, fd, peer_addr, st,
            RP2P_STREAM_TYPE_ACK, 0,
            0, 0) != 0)
            return -1;
    }
    return 0;
}

/**
 * Reads one local TCP chunk and queues it for reliable transport.
 * @return 0 on success, -1 on session failure.
 */
static int rp2p_stream_pump_tcp(rp2p_t *ctx, rp2p_fd_t fd,
    const struct sockaddr_storage *peer_addr,
    rp2p_stream_state_t *st, rp2p_fd_t tcp_fd)
{
    unsigned char buf[RP2P_STREAM_MAX_PAYLOAD];
    int n;

    if (!rp2p_stream_can_send_data(st)) return 0;
    {
        int has_rexmit = 0, j;
        for (j = 0; j < RP2P_STREAM_SEND_WINDOW; j++) {
            if (st->out.slots[j].used && st->out.slots[j].attempts > 2) {
                has_rexmit = 1;
                break;
            }
        }
        if (has_rexmit && rp2p_stream_inflight(st) >= RP2P_STREAM_SEND_WINDOW / 2)
            return 0;
    }
    n = rp2p_sock_read(tcp_fd, (char *)buf, (int)sizeof(buf));
    if (n < 0) {
        if (RP2P_LASTERR() == RP2P_EWOULD) return 0;
        return -1;
    }
    if (n == 0) {
        st->out.local_eof = 1;
        if (!st->out.fin_sent)
            return rp2p_stream_queue_reliable(ctx, fd, peer_addr, st,
                RP2P_STREAM_TYPE_FIN,
                NULL, 0);
        return 0;
    }
    rp2p_stream_log("rp2p: stream tx seq=%u len=%d\n",
        (unsigned)st->out.next_seq, n);
    return rp2p_stream_queue_reliable(ctx, fd, peer_addr, st,
        RP2P_STREAM_TYPE_DATA, buf,
        (size_t)n);
}

/**
 * Advances timers, handshakes, ACKs, and retransmissions.
 * @return 0 on success, -1 on timeout or transport error.
 */
static int rp2p_stream_tick(rp2p_t *ctx, rp2p_fd_t fd,
    const struct sockaddr_storage *peer_addr,
    rp2p_stream_state_t *st)
{
    uint64_t now = rp2p_now_ms();
    int i;
    int burst = 0;

    if (!st->enabled) return 0;
    if (!st->hello_sent || (!st->ready && now - st->last_hello_ms >= RP2P_STREAM_HELLO_MS)) {
        return rp2p_stream_send_hello(ctx, fd, peer_addr, st,
            RP2P_STREAM_TYPE_HELLO);
    }

    for (i = 0; i < RP2P_STREAM_SEND_WINDOW && burst < RP2P_STREAM_MAX_BURST; i++) {
        rp2p_stream_send_slot_t *slot = &st->out.slots[i];
        if (!slot->used) continue;
        {
            int shift = slot->attempts > 1 ? slot->attempts - 2 : 0;
            unsigned int backoff;
            if (shift > RP2P_STREAM_RTO_BACKOFF_SHIFT)
                shift = RP2P_STREAM_RTO_BACKOFF_SHIFT;
            backoff = 1u << shift;
            if (now - slot->last_tx_ms < st->rto_ms * backoff)
                continue;
        }
        if (slot->attempts >= RP2P_STREAM_MAX_RETRIES) {
            rp2p_stream_log("rp2p: stream retransmit exhausted seq=%u\n",
                (unsigned)slot->seq);
            return -1;
        }
        rp2p_stream_log("rp2p: stream retransmit seq=%u attempt=%d\n",
            (unsigned)slot->seq, slot->attempts + 1);
        if (rp2p_stream_send_raw(ctx, fd, peer_addr, slot->frame,
            slot->frame_len) != 0)
            return -1;
        slot->attempts++;
        slot->last_tx_ms = now;
        st->last_tx_ms = now;
        burst++;
    }

    if (st->ready && now - st->last_ack_ms >= RP2P_STREAM_ACK_MS) {
        if (rp2p_stream_send_control(ctx, fd, peer_addr, st,
            RP2P_STREAM_TYPE_ACK, 0,
            0, 0) != 0)
            return -1;
    }
    if (st->ready && now - st->last_rx_ms >= RP2P_STREAM_IDLE_MS)
        return -1;
    if (st->ready && st->out.fin_acked && !st->in.remote_fin) {
        if (now - st->last_tx_ms >= (uint64_t)RP2P_HALFCLOSE_S * 1000u)
            return -1;
    }
    if (st->ready && st->in.remote_fin_acked && !st->out.local_eof) {
        if (now - st->last_rx_ms >= (uint64_t)RP2P_HALFCLOSE_S * 1000u)
            return -1;
    }
    return 0;
}

/**
 * Reports whether one TCP stream is fully closed on both sides.
 * @return 1 when the stream may be cleaned up, 0 otherwise.
 */
static int rp2p_stream_is_done(const rp2p_stream_state_t *st) {
    return st->out.local_eof && st->out.fin_acked && st->in.remote_fin &&
        rp2p_stream_inflight(st) == 0;
}

/**
 * Wipes all per-session stream material.
 * @return None.
 */
static void rp2p_stream_wipe(rp2p_stream_state_t *st) {
    crypto_wipe(st, sizeof(*st));
}

/**
 * Closes one publisher-side UDP session and wipes TCP stream state.
 * @return None.
 */
static void rp2p_server_session_close(rp2p_udp_server_session_t *sess) {
    if (!sess) return;
    if (sess->backend_fd != RP2P_FD_INVALID) {
        RP2P_FD_CLOSE(sess->backend_fd);
        sess->backend_fd = RP2P_FD_INVALID;
    }
    if (sess->tcp_fd != RP2P_FD_INVALID) {
        RP2P_FD_CLOSE(sess->tcp_fd);
        sess->tcp_fd = RP2P_FD_INVALID;
    }
    if (sess->is_tcp) rp2p_stream_wipe(&sess->stream);
    if (!sess->is_tcp) crypto_wipe(&sess->udp_crypto,
        sizeof(sess->udp_crypto));
    sess->active = 0;
}

/**
 * Closes one consumer-side UDP session and wipes TCP stream state.
 * @return None.
 */
static void rp2p_consumer_session_close(rp2p_udp_consumer_session_t *sess) {
    if (!sess) return;
    if (sess->tcp_fd != RP2P_FD_INVALID) {
        RP2P_FD_CLOSE(sess->tcp_fd);
        sess->tcp_fd = RP2P_FD_INVALID;
    }
    if (!RP2P_ISERR(sess->fd)) {
        RP2P_FD_CLOSE(sess->fd);
        sess->fd = RP2P_FD_INVALID;
    }
    if (sess->is_tcp) rp2p_stream_wipe(&sess->stream);
    if (!sess->is_tcp) crypto_wipe(&sess->udp_crypto,
        sizeof(sess->udp_crypto));
    sess->active = 0;
}

/**
 * Signal handler.
 * Summary: Async-signal-safe. Records only the pending signal number; the
 *          actual callback dispatch happens in the main loops via
 *          rp2p_dispatch_pending_signals.
 * @return None.
 */
static void rp2p_signal_handler(int sig) {
    g_signal_pending_no = (sig_atomic_t)sig;
    g_signal_pending = 1;
}

/**
 * Dispatches one pending signal to all registered contexts.
 * Summary: Must be called only from non-async-signal context.
 * @return None.
 */
static void rp2p_dispatch_pending_signals(void) {
    int i;
    int sig;
    if (!g_signal_pending) return;
    sig = (int)g_signal_pending_no;
    g_signal_pending = 0;
    for (i = 0; i < g_signal_ctx_count; i++) {
        if (g_signal_ctx_list[i])
            rp2p_raise_signal(g_signal_ctx_list[i], sig);
    }
}

/**
 * On signal.
 * @return 0 on success, -1 on error.
 */
int rp2p_on_signal(
    rp2p_t *ctx,
    int sig,
    rp2p_signal_callback_t cb)
{
    rp2p_signal_entry_t *new_entries;
    int i;

    if (!ctx) return RP2P_ERROR;

    if (!cb) {
        for (i = 0; i < ctx->signal_count; i++) {
            if (ctx->signal_entries[i].sig == sig) {
                ctx->signal_entries[i] =
                    ctx->signal_entries[ctx->signal_count - 1];
                ctx->signal_count--;
                return RP2P_OK;
            }
        }
        return RP2P_ENOENT;
    }

    if (ctx->signal_count >= ctx->signal_capacity) {
        int new_cap = ctx->signal_capacity
                    ? ctx->signal_capacity * 2
                    : 4;
        new_entries = (rp2p_signal_entry_t *)realloc(
            ctx->signal_entries,
            (size_t)new_cap * sizeof(rp2p_signal_entry_t));
        if (!new_entries) return RP2P_ERROR;
        ctx->signal_entries = new_entries;
        ctx->signal_capacity = new_cap;
    }

    ctx->signal_entries[ctx->signal_count].sig = sig;
    ctx->signal_entries[ctx->signal_count].cb = cb;
    ctx->signal_count++;
    return RP2P_OK;
}

/**
 * Raise signal.
 * @return 0 on success, -1 on error.
 */
int rp2p_raise_signal(rp2p_t *ctx, int sig) {
    int i;
    int count = 0;
    if (!ctx) return 0;
    for (i = 0; i < ctx->signal_count; i++) {
        if (ctx->signal_entries[i].sig == sig) {
            ctx->signal_entries[i].cb(ctx);
            count++;
        }
    }
    return count;
}

/**
 * Listen signals.
 * @return 0 on success, -1 on error.
 */
int rp2p_listen_signals(rp2p_t *ctx) {
    rp2p_t **new_list;
    if (!ctx) return RP2P_ERROR;
    rp2p_global_lock();
    if (g_signal_ctx_count >= g_signal_ctx_cap) {
        int new_cap = g_signal_ctx_cap ? g_signal_ctx_cap * 2 : 4;
        new_list = (rp2p_t **)realloc(
            g_signal_ctx_list,
            (size_t)new_cap * sizeof(rp2p_t *));
        if (!new_list) { rp2p_global_unlock(); return RP2P_ERROR; }
        g_signal_ctx_list = new_list;
        g_signal_ctx_cap = new_cap;
    }
    g_signal_ctx_list[g_signal_ctx_count++] = ctx;
    rp2p_global_unlock();
    return RP2P_OK;
}

/**
 * Listen signal.
 * @return 0 on success, -1 on error.
 */
int rp2p_listen_signal(rp2p_t *ctx, int sig_id) {
    (void)ctx;
    signal(sig_id, rp2p_signal_handler);
    return RP2P_OK;
}

/**
 * Signal listener thread entry point.
 * @return NULL.
 */
void *rp2p_signal_listener(void *arg) {
    (void)arg;
    return NULL;
}

#ifdef _WIN32

/**
 * Platform init.
 * @return 0 on success, -1 on error.
 */
int rp2p_platform_init(void) {
    WSADATA w;
    return WSAStartup(MAKEWORD(2, 2), &w) == 0 ? 0 : -1;
}

/**
 * Platform cleanup.
 * @return None.
 */
void rp2p_platform_cleanup(void) { WSACleanup(); }

#else

/**
 * Platform init.
 * @return 0 on success, -1 on error.
 */
int rp2p_platform_init(void) { return 0; }

/**
 * Platform cleanup.
 * @return None.
 */
void rp2p_platform_cleanup(void) {}

#endif

/**
 * Set nonblock.
 * @return 0 on success, -1 on error.
 */
int rp2p_set_nonblock(rp2p_fd_t fd) {
#ifdef _WIN32
    u_long mode = 1;
    return ioctlsocket(fd, FIONBIO, &mode) == 0 ? 0 : -1;
#else
    int flags = fcntl(fd, F_GETFL, 0);
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
#endif
}

/**
 * Set block.
 * @return 0 on success, -1 on error.
 */
int rp2p_set_block(rp2p_fd_t fd) {
#ifdef _WIN32
    u_long mode = 0;
    return ioctlsocket(fd, FIONBIO, &mode) == 0 ? 0 : -1;
#else
    int flags = fcntl(fd, F_GETFL, 0);
    return fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
#endif
}

/**
 * Resolve.
 * @return 0 on success, -1 on error.
 */
int rp2p_resolve(
    const char *host,
    unsigned short port,
    int socktype,
    struct sockaddr_storage *out,
    socklen_t *out_len)
{
    struct addrinfo hints;
    struct addrinfo *ai;
    char port_str[16];

    if (!out || !out_len) return -1;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = host ? AF_UNSPEC : AF_INET6;
    hints.ai_socktype = socktype;

    snprintf(port_str, sizeof(port_str), "%u", (unsigned)port);
    if (getaddrinfo(host, port_str, &hints, &ai) != 0) return -1;

    if ((size_t)ai->ai_addrlen > sizeof(*out)) {
        freeaddrinfo(ai);
        return -1;
    }
    memset(out, 0, sizeof(*out));
    memcpy(out, ai->ai_addr, ai->ai_addrlen);
    *out_len = (socklen_t)ai->ai_addrlen;
    freeaddrinfo(ai);
    return 0;
}

/**
 * Returns the socket address length for a stored address family.
 * @param addr Stored socket address.
 * @return Socket address length, or 0 for unsupported families.
 */
static socklen_t rp2p_sockaddr_len(const struct sockaddr_storage *addr) {
    if (!addr) return 0;
    if (addr->ss_family == AF_INET) return sizeof(struct sockaddr_in);
    if (addr->ss_family == AF_INET6) return sizeof(struct sockaddr_in6);
    return 0;
}

/**
 * Returns the UDP or TCP port from a stored socket address.
 * @param addr Stored socket address.
 * @return Host-order port, or 0 for unsupported families.
 */
static unsigned short rp2p_sockaddr_port(
    const struct sockaddr_storage *addr)
{
    if (!addr) return 0;
    if (addr->ss_family == AF_INET)
        return ntohs(((const struct sockaddr_in *)addr)->sin_port);
    if (addr->ss_family == AF_INET6)
        return ntohs(((const struct sockaddr_in6 *)addr)->sin6_port);
    return 0;
}

/**
 * Sets the UDP or TCP port in a stored socket address.
 * @param addr Stored socket address.
 * @param port Host-order port.
 * @return 1 on success, 0 for unsupported families.
 */
static int rp2p_sockaddr_set_port(struct sockaddr_storage *addr,
    unsigned short port)
{
    if (!addr) return 0;
    if (addr->ss_family == AF_INET) {
        ((struct sockaddr_in *)addr)->sin_port = htons(port);
        return 1;
    }
    if (addr->ss_family == AF_INET6) {
        ((struct sockaddr_in6 *)addr)->sin6_port = htons(port);
        return 1;
    }
    return 0;
}

/**
 * Compares stored socket endpoints by family, address, and port.
 * @param a First address.
 * @param b Second address.
 * @return 1 when endpoints match, 0 otherwise.
 */
static int rp2p_sockaddr_equal(const struct sockaddr_storage *a,
    const struct sockaddr_storage *b)
{
    if (!a || !b || a->ss_family != b->ss_family) return 0;
    if (a->ss_family == AF_INET) {
        const struct sockaddr_in *aa = (const struct sockaddr_in *)a;
        const struct sockaddr_in *bb = (const struct sockaddr_in *)b;
        return aa->sin_port == bb->sin_port &&
            aa->sin_addr.s_addr == bb->sin_addr.s_addr;
    }
    if (a->ss_family == AF_INET6) {
        const struct sockaddr_in6 *aa = (const struct sockaddr_in6 *)a;
        const struct sockaddr_in6 *bb = (const struct sockaddr_in6 *)b;
        return aa->sin6_port == bb->sin6_port &&
            memcmp(&aa->sin6_addr, &bb->sin6_addr,
                sizeof(aa->sin6_addr)) == 0;
    }
    return 0;
}

/**
 * Sends bytes to one stored socket address.
 * @param fd   UDP socket.
 * @param buf  Bytes to send.
 * @param len  Byte count.
 * @param addr Destination address.
 * @return sendto result, or -1 for unsupported address families.
 */
static int rp2p_sendto_addr(rp2p_fd_t fd, const void *buf, size_t len,
    const struct sockaddr_storage *addr)
{
    socklen_t addr_len;

    addr_len = rp2p_sockaddr_len(addr);
    if (addr_len == 0) return -1;
    return (int)sendto(fd, buf, len, 0, (const struct sockaddr *)addr,
        addr_len);
}

/**
 * Reports whether a host string is an IPv6 literal.
 * @param host Host string.
 * @return 1 for IPv6 literals, 0 otherwise.
 */
static int rp2p_host_is_ipv6_literal(const char *host) {
    struct in6_addr addr;

    return host && inet_pton(AF_INET6, host, &addr) == 1;
}

/**
 * Extract addr.
 * @return None.
 */
void rp2p_extract_addr(
    const struct sockaddr_in *from,
    char *out,
    size_t out_cap,
    unsigned short *port)
{
#ifdef _WIN32
    const char *p = inet_ntoa(from->sin_addr);
    strncpy(out, p, out_cap - 1);
    out[out_cap - 1] = '\0';
#else
    inet_ntop(AF_INET, &from->sin_addr, out, (socklen_t)out_cap);
#endif
    *port = ntohs(from->sin_port);
}

/**
 * Send reply.
 * @return 0 on success, -1 on error.
 */
int rp2p_send_reply(
    rp2p_fd_t fd,
    const struct sockaddr_in *to,
    socklen_t tolen,
    const char *msg)
{
    return sendto(fd, msg, strlen(msg), 0,
        (const struct sockaddr *)to, tolen) > 0
        ? RP2P_OK : RP2P_ENET;
}

/**
 * Send recv.
 * @return 0 on success, -1 on error.
 */
int rp2p_send_recv(
    rp2p_fd_t fd,
    const char *srv_host,
    unsigned short srv_port,
    const char *send_msg,
    char *recv_buf,
    size_t recv_cap,
    int timeout_sec)
{
    struct sockaddr_storage srv;
    socklen_t srv_len;
    socklen_t srclen;
    fd_set fds;
    struct timeval tv;
    int n;
    struct sockaddr_storage from;

    if (rp2p_resolve(srv_host, srv_port, SOCK_DGRAM, &srv, &srv_len) != 0)
        return RP2P_ENET;

    if (sendto(fd, send_msg, strlen(send_msg), 0,
        (const struct sockaddr *)&srv, srv_len) < 0)
        return RP2P_ENET;

    if (!recv_buf || recv_cap == 0) return RP2P_OK;

    FD_ZERO(&fds);
    rp2p_fdset_add(fd, &fds, NULL);
    tv.tv_sec = timeout_sec;
    tv.tv_usec = 0;

    n = select((int)(fd + 1), &fds, NULL, NULL, &tv);
    if (n <= 0) return RP2P_ETIMEOUT;

    srclen = sizeof(from);
    n = (int)recvfrom(fd, recv_buf, (int)(recv_cap - 1), 0,
        (struct sockaddr *)&from, &srclen);
    if (n < 0) return RP2P_ENET;
    recv_buf[n] = '\0';
    return RP2P_OK;
}

/**
 * Adds one descriptor to one select set with descriptor-range validation.
 * Summary: Rejects descriptors that cannot be represented by fd_set.
 * @param fd    Descriptor to add.
 * @param set   Select set to update.
 * @param maxfd Current maximum descriptor, updated on success.
 * @return 1 when added, 0 when rejected.
 */
static int rp2p_fdset_add(rp2p_fd_t fd, fd_set *set, int *maxfd) {
#ifdef _WIN32
    (void)maxfd;
    if (fd == INVALID_SOCKET) return 0;
    if ((int)set->fd_count >= FD_SETSIZE) return 0;
#else
    if (fd < 0) return 0;
    if (fd >= FD_SETSIZE) return 0;
    if (maxfd && (int)fd > *maxfd) *maxfd = (int)fd;
#endif
    FD_SET(fd, set);
    return 1;
}

/**
 * Creates one UDP or TCP socket bound to one local address.
 * @return Valid descriptor, or RP2P_FD_INVALID on failure.
 */
rp2p_fd_t rp2p_create_socket(
    const char *bind_host,
    unsigned short bind_port)
{
    rp2p_fd_t fd;
    struct addrinfo hints;
    struct addrinfo *ai;
    struct addrinfo *it;
    char port_str[16];

    if (rp2p_platform_init() != 0) return RP2P_FD_INVALID;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_PASSIVE;

    snprintf(port_str, sizeof(port_str), "%u", (unsigned)bind_port);
    if (getaddrinfo(bind_host, port_str, &hints, &ai) != 0)
        return RP2P_FD_INVALID;

    fd = RP2P_FD_INVALID;
    for (it = ai; it; it = it->ai_next) {
        fd = socket(it->ai_family, it->ai_socktype, it->ai_protocol);
        if (RP2P_ISERR(fd)) continue;
        {
            int reuse = 1;
            setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
                (void *)&reuse, sizeof(reuse));
        }
#ifdef IPV6_V6ONLY
        if (it->ai_family == AF_INET6) {
            int v6only = 0;
            setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY,
                (void *)&v6only, sizeof(v6only));
        }
#endif
        if (bind(fd, it->ai_addr, (socklen_t)it->ai_addrlen) == 0)
            break;
        RP2P_FD_CLOSE(fd);
        fd = RP2P_FD_INVALID;
    }
    freeaddrinfo(ai);
    return fd;
}

/**
 * Create tcp listener.
 * @return 0 on success, -1 on error.
 */
static rp2p_fd_t rp2p_create_tcp_listener(
    const char *bind_host,
    unsigned short bind_port)
{
    rp2p_fd_t fd;
    struct addrinfo hints;
    struct addrinfo *ai;
    struct addrinfo *it;
    char port_str[16];

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    snprintf(port_str, sizeof(port_str), "%u", (unsigned)bind_port);
    if (getaddrinfo(bind_host, port_str, &hints, &ai) != 0)
        return RP2P_FD_INVALID;
    fd = RP2P_FD_INVALID;
    for (it = ai; it; it = it->ai_next) {
        fd = socket(it->ai_family, it->ai_socktype, it->ai_protocol);
        if (RP2P_ISERR(fd)) continue;
        {
            int reuse = 1;
            setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
                (void *)&reuse, sizeof(reuse));
        }
#ifdef IPV6_V6ONLY
        if (it->ai_family == AF_INET6) {
            int v6only = 0;
            setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY,
                (void *)&v6only, sizeof(v6only));
        }
#endif
        if (bind(fd, it->ai_addr, (socklen_t)it->ai_addrlen) == 0 &&
            listen(fd, 32) == 0)
            break;
        RP2P_FD_CLOSE(fd);
        fd = RP2P_FD_INVALID;
    }
    freeaddrinfo(ai);
    return fd;
}

/**
 * Connect local tcp.
 * @return 0 on success, -1 on error.
 */
static rp2p_fd_t rp2p_connect_local_tcp(unsigned short port) {
    rp2p_fd_t fd;
    struct sockaddr_in addr;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (RP2P_ISERR(fd)) return RP2P_FD_INVALID;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    if (connect(fd, (const struct sockaddr *)&addr, sizeof(addr)) != 0) {
        RP2P_FD_CLOSE(fd);
        return RP2P_FD_INVALID;
    }
    return fd;
}

/**
 * Sock read.
 * @return 0 on success, -1 on error.
 */
static int rp2p_sock_read(rp2p_fd_t fd, char *buf, int len) {
#ifdef _WIN32
    return recv(fd, buf, len, 0);
#else
    return (int)read(fd, buf, (size_t)len);
#endif
}

/**
 * Sock write.
 * @return 0 on success, -1 on error.
 */
static int rp2p_sock_write(rp2p_fd_t fd, const char *buf, int len) {
#ifdef _WIN32
    return send(fd, buf, len, 0);
#else
    return (int)write(fd, buf, (size_t)len);
#endif
}

/**
 * Write all.
 * @return 0 on success, -1 on error.
 */
static int rp2p_write_all(rp2p_fd_t fd, const char *buf, int len) {
    int off;
    int n;

    off = 0;
    while (off < len) {
        n = rp2p_sock_write(fd, buf + off, len - off);
        if (n <= 0) return -1;
        off += n;
    }
    return 0;
}

/**
 * Shuts down the local write side of one TCP socket.
 * @return None.
 */
static void rp2p_shutdown_write(rp2p_fd_t fd) {
#ifdef _WIN32
    shutdown(fd, SD_SEND);
#else
    shutdown(fd, SHUT_WR);
#endif
}

/**
 * Tcp connect.
 * @return 0 on success, -1 on error.
 */
static rp2p_fd_t rp2p_tcp_connect(const char *host, unsigned short port) {
    rp2p_fd_t fd;
    struct addrinfo hints;
    struct addrinfo *ai;
    struct addrinfo *it;
    char port_str[16];

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    snprintf(port_str, sizeof(port_str), "%u", (unsigned)port);
    if (getaddrinfo(host, port_str, &hints, &ai) != 0)
        return RP2P_FD_INVALID;
    fd = RP2P_FD_INVALID;
    for (it = ai; it; it = it->ai_next) {
        fd = socket(it->ai_family, it->ai_socktype, it->ai_protocol);
        if (RP2P_ISERR(fd)) continue;
        if (connect(fd, it->ai_addr, (socklen_t)it->ai_addrlen) == 0)
            break;
        RP2P_FD_CLOSE(fd);
        fd = RP2P_FD_INVALID;
    }
    freeaddrinfo(ai);
    return fd;
}

/**
 * Tcp send.
 * @return 0 on success, -1 on error.
 */
static int rp2p_tcp_send(rp2p_fd_t fd, const char *msg) {
    int len = (int)strlen(msg);

    if (rp2p_write_all(fd, msg, len) != 0) return RP2P_ENET;
    if (rp2p_write_all(fd, "\n", 1) != 0) return RP2P_ENET;
    return RP2P_OK;
}

/**
 * Tcp readline.
 * @return 0 on success, -1 on error.
 */
static int rp2p_tcp_readline(rp2p_fd_t fd, char *buf, int cap, int timeout_sec) {
    int total = 0;
    int n;
    char tmp[RP2P_BUF];

    if (cap < 1) return -1;

    while (total < cap - 1) {
        fd_set fds;
        struct timeval tv;

        FD_ZERO(&fds);
        rp2p_fdset_add(fd, &fds, NULL);
        tv.tv_sec = (timeout_sec > 0 && total == 0) ? timeout_sec : 1;
        tv.tv_usec = 0;

        n = select(fd + 1, &fds, NULL, NULL, &tv);
        if (n <= 0) {
            if (total > 0) { buf[total] = '\0'; return total; }
            return -1;
        }

        n = rp2p_sock_read(fd, tmp, 1);
        if (n <= 0) {
            if (total > 0) { buf[total] = '\0'; return total; }
            return -1;
        }

        for (int i = 0; i < n && total < cap - 1; i++) {
            if (tmp[i] == '\n') { buf[total] = '\0'; return total; }
            if (tmp[i] != '\r') buf[total++] = tmp[i];
        }
    }
    buf[total] = '\0';
    return total;
}

/**
 * Opens a TCP control connection and validates the control protocol version.
 * @param index_host Index host.
 * @param index_port Index port.
 * @return Connected fd on success, invalid fd on failure.
 */
static rp2p_fd_t rp2p_control_connect(const char *index_host,
    unsigned short index_port)
{
    rp2p_fd_t fd;
    char reply[RP2P_BUF];

    fd = rp2p_tcp_connect(index_host, index_port);
    if (RP2P_ISERR(fd)) return fd;
    if (rp2p_tcp_send(fd, RP2P_CTRTOK_HELLO) != RP2P_OK ||
        rp2p_tcp_readline(fd, reply, (int)sizeof(reply), 5) < 0 ||
        strcmp(reply, RP2P_CTRTOK_HELLO_OK) != 0)
    {
        RP2P_FD_CLOSE(fd);
        return RP2P_FD_INVALID;
    }
    return fd;
}

/**
 * Returns whether the byte is ASCII whitespace.
 * @param ch Input byte.
 * @return 1 when whitespace, 0 otherwise.
 */
static int rp2p_is_space(char ch) {
    return ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r' ||
        ch == '\f' || ch == '\v';
}

/**
 * Returns whether the identifier contains only alphanumeric characters.
 * @param id Identifier to validate.
 * @return 1 when valid, 0 otherwise.
 */
int rp2p_is_valid_id(const char *id) {
    size_t i;

    if (!id || !id[0]) return 0;
    for (i = 0; id[i]; i++) {
        if (i >= RP2P_ID_MAX) return 0;
        if (!((id[i] >= 'a' && id[i] <= 'z') ||
            (id[i] >= 'A' && id[i] <= 'Z') ||
            (id[i] >= '0' && id[i] <= '9')))
            return 0;
    }
    return 1;
}

/**
 * Returns whether one password byte is safe to type in a shell token.
 * @param ch Input byte.
 * @return 1 when allowed, 0 otherwise.
 */
static int rp2p_is_pass_char(char ch) {
    if (ch >= 'a' && ch <= 'z') return 1;
    if (ch >= 'A' && ch <= 'Z') return 1;
    if (ch >= '0' && ch <= '9') return 1;
    return ch == '.' || ch == '_' || ch == '-' || ch == '+' ||
        ch == '=' || ch == ',' || ch == ':' || ch == '@' ||
        ch == '%' || ch == '/';
}

/**
 * Returns whether the password token uses only terminal-safe characters.
 * @param pass Password token to validate.
 * @return 1 when valid, 0 otherwise.
 */
int rp2p_is_valid_pass_token(const char *pass) {
    size_t i;

    if (!pass || !pass[0]) return 0;
    for (i = 0; pass[i]; i++) {
        if (i >= RP2P_PASS_MAX) return 0;
        if (!rp2p_is_pass_char(pass[i])) return 0;
    }
    return 1;
}

/**
 * Trims leading and trailing ASCII whitespace in place.
 * @param text Mutable string buffer.
 * @return Pointer to the first non-whitespace byte.
 */
static char *rp2p_trim(char *text) {
    char *end;

    if (!text) return NULL;
    while (*text && rp2p_is_space(*text)) text++;
    end = text + strlen(text);
    while (end > text && rp2p_is_space(end[-1])) end--;
    *end = '\0';
    return text;
}

/**
 * Finds one VIP seat by identifier.
 * @param ctx Open context.
 * @param id Reserved seat identifier.
 * @return VIP index on success, -1 when missing.
 */
static int rp2p_find_vip(rp2p_t *ctx, const char *id) {
    int i;

    if (!ctx || !id) return -1;
    for (i = 0; i < ctx->n_vips; i++) {
        if (strcmp(ctx->vips[i].id, id) == 0) return i;
    }
    return -1;
}

/**
 * Recomputes non-VIP capacity after seats or VIP reservations change.
 * @param ctx Open context.
 * @return None.
 */
static void rp2p_update_nonvip_cap(rp2p_t *ctx) {
    if (!ctx) return;
    ctx->nonvip_cap = ctx->n_peers_cap - ctx->n_vips;
    if (ctx->nonvip_cap < 0) ctx->nonvip_cap = 0;
}

/**
 * Ensures peer storage can hold the requested number of online peers.
 * @param ctx  Open context.
 * @param need Required peer slots.
 * @return RP2P_OK on success, RP2P_ERROR on allocation failure.
 */
static int rp2p_ensure_peer_storage(rp2p_t *ctx, int need) {
    rp2p_peer_t *peers;
    int cap;

    if (!ctx) return RP2P_ERROR;
    if (need <= ctx->peers_alloc) return RP2P_OK;
    cap = ctx->peers_alloc > 0 ? ctx->peers_alloc : 8;
    while (cap < need) cap *= 2;
    peers = (rp2p_peer_t *)realloc(ctx->peers,
        (size_t)cap * sizeof(rp2p_peer_t));
    if (!peers) return RP2P_ERROR;
    ctx->peers = peers;
    ctx->peers_alloc = cap;
    return RP2P_OK;
}

/**
 * Counts online peers that do not have a reserved VIP seat.
 * @param ctx Open context.
 * @return Number of online non-VIP peers.
 */
static int rp2p_count_nonvip_peers(rp2p_t *ctx) {
    int i;
    int count;

    if (!ctx) return 0;
    count = 0;
    for (i = 0; i < ctx->n_peers; i++) {
        if (rp2p_find_vip(ctx, ctx->peers[i].id) < 0) count++;
    }
    return count;
}

/**
 * Adds one VIP seat definition to the context.
 * @param ctx Open context.
 * @param id Reserved seat identifier.
 * @param pass Reserved seat password.
 * @param err Output error buffer.
 * @param err_cap Output error buffer capacity.
 * @return RP2P_OK on success, RP2P_ERROR on validation failure.
 */
static int rp2p_add_vip(rp2p_t *ctx, const char *id, const char *pass,
    char *err, size_t err_cap)
{
    rp2p_vip_entry_t *vips;
    int cap;

    if (!ctx || !id || !pass) return RP2P_ERROR;
    if (!rp2p_is_valid_id(id)) {
        if (err && err_cap > 0)
            snprintf(err, err_cap, "RP2P_VIP invalid id '%s'", id);
        return RP2P_ERROR;
    }
    if (!rp2p_is_valid_pass_token(pass)) {
        if (err && err_cap > 0)
            snprintf(err, err_cap, "RP2P_VIP invalid password for id '%s'", id);
        return RP2P_ERROR;
    }
    if (rp2p_find_vip(ctx, id) >= 0) {
        if (err && err_cap > 0)
            snprintf(err, err_cap, "RP2P_VIP redefines reserved id '%s'", id);
        return RP2P_ERROR;
    }
    if (ctx->n_vips >= ctx->vips_cap) {
        cap = ctx->vips_cap > 0 ? ctx->vips_cap * 2 : 8;
        vips = (rp2p_vip_entry_t *)realloc(ctx->vips,
            (size_t)cap * sizeof(rp2p_vip_entry_t));
        if (!vips) {
            if (err && err_cap > 0)
                snprintf(err, err_cap, "failed to allocate RP2P_VIP table");
            return RP2P_ERROR;
        }
        ctx->vips = vips;
        ctx->vips_cap = cap;
    }
    strncpy(ctx->vips[ctx->n_vips].id, id, RP2P_ID_MAX);
    ctx->vips[ctx->n_vips].id[RP2P_ID_MAX] = '\0';
    strncpy(ctx->vips[ctx->n_vips].pass, pass, RP2P_PASS_MAX);
    ctx->vips[ctx->n_vips].pass[RP2P_PASS_MAX] = '\0';
    ctx->n_vips++;
    return RP2P_OK;
}

/**
 * Returns the registration password for one identifier.
 * @param ctx Open context.
 * @param id Service identifier.
 * @return VIP password when reserved, otherwise the global password.
 */
static const char *rp2p_get_register_pass(rp2p_t *ctx, const char *id) {
    int idx;

    if (!ctx) return "";
    idx = rp2p_find_vip(ctx, id);
    if (idx >= 0) return ctx->vips[idx].pass;
    return ctx->pass;
}

/**
 * Open.
 * @return 0 on success, -1 on error.
 */
int rp2p_open(rp2p_t **out) {
    rp2p_t *ctx;
    rp2p_peer_t *p;
    if (!out) return RP2P_ERROR;
    ctx = (rp2p_t *)calloc(1, sizeof(rp2p_t));
    if (!ctx) return RP2P_ERROR;
    p = (rp2p_peer_t *)calloc((size_t)RP2P_MAX_PEERS, sizeof(rp2p_peer_t));
    if (!p) {
        free(ctx);
        return RP2P_ERROR;
    }
    ctx->peers = p;
    ctx->n_peers = 0;
    ctx->peers_alloc = RP2P_MAX_PEERS;
    ctx->n_peers_cap = RP2P_MAX_PEERS;
    ctx->nonvip_cap = RP2P_MAX_PEERS;
    ctx->signal_entries = NULL;
    ctx->signal_count = 0;
    ctx->signal_capacity = 0;
    ctx->pass[0] = '\0';
    ctx->pow_bits = 0;
    ctx->bind_port = 0;
    ctx->explicit_port = 0;
    ctx->proto = RP2P_PROTO_TCP;
    ctx->n_pow_challenges = 0;
    ctx->conns = NULL;
    ctx->n_conns = 0;
    ctx->conns_cap = 0;
    ctx->vips = NULL;
    ctx->n_vips = 0;
    ctx->vips_cap = 0;
    ctx->stop_requested = 0;
#ifdef _WIN32
    InitializeCriticalSection(&ctx->mutex);
#else
    pthread_mutex_init(&ctx->mutex, NULL);
#endif

    *out = ctx;
    return RP2P_OK;
}

/**
 * Close.
 * @return 0 on success, -1 on error.
 */
int rp2p_close(rp2p_t *ctx) {
    int i;
    if (!ctx) return RP2P_ERROR;
    rp2p_global_lock();
    for (i = 0; i < g_signal_ctx_count; i++) {
        if (g_signal_ctx_list[i] == ctx) {
            g_signal_ctx_list[i] =
                g_signal_ctx_list[--g_signal_ctx_count];
            break;
        }
    }
    rp2p_global_unlock();
    for (i = 0; i < ctx->n_conns; i++)
        RP2P_FD_CLOSE(ctx->conns[i].fd);
    free(ctx->conns);
    free(ctx->vips);
    free(ctx->signal_entries);
    free(ctx->peers);
#ifdef _WIN32
    DeleteCriticalSection(&ctx->mutex);
#else
    pthread_mutex_destroy(&ctx->mutex);
#endif
    free(ctx);
    return RP2P_OK;
}

/**
 * Requests clean termination for the current blocking operation on one context.
 * @param ctx Context to stop.
 * @return 0 on success, -1 on error.
 */
int rp2p_stop(rp2p_t *ctx) {
    if (!ctx) return RP2P_ERROR;
    atomic_store(&ctx->stop_requested, 1);
    return RP2P_OK;
}

/**
 * Checks whether one context was requested to stop.
 * @return Nonzero if a stop was requested, zero otherwise.
 */
int rp2p_stop_requested(rp2p_t *ctx) {
    return ctx && atomic_load(&ctx->stop_requested);
}

/**
 * Return string for status code.
 * @return Status string.
 */
const char *rp2p_strerror(int code) {
    switch (code) {
        case RP2P_OK:       return "OK";
        case RP2P_ERROR:    return "general error";
        case RP2P_ENET:     return "network error";
        case RP2P_ENOENT:   return "peer not found";
        case RP2P_ETIMEOUT: return "timeout";
        case RP2P_EFULL:    return "peer table full";
        default:              return "unknown error";
    }
}

/**
 * Records one per-context detail error message.
 * @return None.
 */
void rp2p_set_error(rp2p_t *ctx, const char *fmt, ...) {
    va_list ap;
    if (!ctx) return;
    if (!fmt) { ctx->err_buf[0] = '\0'; return; }
    va_start(ap, fmt);
    vsnprintf(ctx->err_buf, sizeof(ctx->err_buf), fmt, ap);
    va_end(ap);
    ctx->err_buf[sizeof(ctx->err_buf) - 1] = '\0';
}

/**
 * Returns the last per-context detail error message.
 * @return Pointer to a caller-owned message string, or empty string.
 */
const char *rp2p_get_error(rp2p_t *ctx) {
    if (!ctx) return "";
    return ctx->err_buf;
}

/**
 * Returns one caller-owned options struct with safe defaults.
 * Summary: Index port and sweep are populated; callers own the returned struct.
 * @return Default options struct.
 */
rp2p_options_t rp2p_options_default(void) {
    rp2p_options_t opts;
    memset(&opts, 0, sizeof(opts));
    opts.seats = RP2P_MAX_PEERS;
    opts.pow = 0;
    opts.sweep = 20;
    return opts;
}

/**
 * Loads RP2P_* environment values into one options struct with strict rules.
 * Summary: Invalid numeric values are ignored and defaults are retained.
 * Initialize with rp2p_options_default and free with rp2p_options_free.
 * @param opts Options struct to populate.
 * @return None.
 */
void rp2p_options_load_env(rp2p_options_t *opts) {
    const char *val;
    long num;

    if (!opts) return;

    val = getenv("RP2P_SEATS");
    if (val && rp2p_parse_env(val, 0, RP2P_MAX_PEERS, &num))
        opts->seats = (int)num;

    val = getenv("RP2P_POW");
    if (val && rp2p_parse_env(val, 0, RP2P_POW_MAX, &num))
        opts->pow = (int)num;

    val = getenv("RP2P_SWEEP");
    if (val && rp2p_parse_env(val, 0, RP2P_SWEEP_MAX, &num))
        opts->sweep = (int)num;

    val = getenv("RP2P_PASS");
    if (val) {
        strncpy(opts->pass, val, RP2P_PASS_MAX);
        opts->pass[RP2P_PASS_MAX] = '\0';
    }

    val = getenv("RP2P_SECRET");
    if (val) {
        strncpy(opts->secret, val, RP2P_SECRET_MAX);
        opts->secret[RP2P_SECRET_MAX] = '\0';
    }

    val = getenv("RP2P_VIP");
    if (val) {
        size_t len = strlen(val);
        free(opts->vip);
        opts->vip = (char *)malloc(len + 1);
        if (opts->vip) memcpy(opts->vip, val, len + 1);
    }

    val = getenv("RP2P_STUN");
    if (val) {
        strncpy(opts->stun_url, val, sizeof(opts->stun_url) - 1);
        opts->stun_url[sizeof(opts->stun_url) - 1] = '\0';
    }
}

/**
 * Options free.
 * @return None.
 */
void rp2p_options_free(rp2p_options_t *opts) {
    if (!opts) return;
    free(opts->vip);
    opts->vip = NULL;
}

/**
 * Set seats.
 * @return 0 on success, -1 on error.
 */
int rp2p_set_seats(rp2p_t *ctx, int seats) {
    int cap;
    if (!ctx) return RP2P_ERROR;
    cap = seats >= 0 ? seats : RP2P_MAX_PEERS;
    ctx->n_peers_cap = cap;
    rp2p_update_nonvip_cap(ctx);
    return RP2P_OK;
}

/**
 * Set pow.
 * @return 0 on success, -1 on error.
 */
int rp2p_set_pow(rp2p_t *ctx, int bits) {
    if (!ctx) return RP2P_ERROR;
    if (bits < 0) bits = 0;
    if (bits > RP2P_POW_MAX) bits = RP2P_POW_MAX;
    ctx->pow_bits = bits;
    return RP2P_OK;
}

/**
 * Configures the local service or listener port used by set and con.
 * Summary: Marks the port as explicit for precedence over arguments.
 * @param ctx  Open context.
 * @param port Local bind port.
 * @return 0 on success, -1 on error.
 */
int rp2p_set_port(rp2p_t *ctx, unsigned short port) {
    if (!ctx) return RP2P_ERROR;
    ctx->bind_port = port;
    ctx->explicit_port = 1;
    return RP2P_OK;
}

/**
 * Set protocol.
 * @return 0 on success, -1 on error.
 */
int rp2p_set_protocol(rp2p_t *ctx, int proto) {
    if (!ctx) return RP2P_ERROR;
    if (proto != RP2P_PROTO_TCP && proto != RP2P_PROTO_UDP)
        return RP2P_ERROR;
    ctx->proto = proto;
    return RP2P_OK;
}

/**
 * Set sweep count.
 * @return Status code.
 */
int rp2p_set_sweep(rp2p_t *ctx, int sweep) {
    if (!ctx) return RP2P_ERROR;
    if (sweep < 0) sweep = 0;
    if (sweep > RP2P_SWEEP_MAX) sweep = RP2P_SWEEP_MAX;
    ctx->sweep = sweep;
    return RP2P_OK;
}

/**
 * Resolves the effective local port for set or con.
 * Summary: A nonzero argument overrides a default context port, while a nonzero
 * argument conflicting with an explicitly set context port is rejected.
 * @param ctx        Open context.
 * @param arg_port  Port argument from rp2p_wait or rp2p_connect.
 * @param out        Effective port output.
 * @return RP2P_OK on success, RP2P_ERROR on conflicting ports.
 */
static int rp2p_resolve_port(rp2p_t *ctx, unsigned short arg_port,
    unsigned short *out)
{
    if (arg_port == 0) {
        *out = ctx->bind_port;
        return RP2P_OK;
    }
    if (ctx->explicit_port && ctx->bind_port != 0 &&
        ctx->bind_port != arg_port)
        return RP2P_ERROR;
    *out = arg_port;
    return RP2P_OK;
}

/**
 * Stores the shared register password.
 * @param ctx  Open context.
 * @param pass Shared password string.
 * @return 0 on success, -1 on error.
 */
int rp2p_set_pass(rp2p_t *ctx, const char *pass) {
    if (!ctx || !pass) return RP2P_ERROR;
    if (pass[0] && !rp2p_is_valid_pass_token(pass)) return RP2P_ERROR;
    strncpy(ctx->pass, pass, RP2P_PASS_MAX);
    ctx->pass[RP2P_PASS_MAX] = '\0';
    return RP2P_OK;
}

/**
 * Stores the shared tunnel authentication secret.
 * @param ctx    Open context.
 * @param secret Shared tunnel secret string.
 * @return 0 on success, -1 on error.
 */
int rp2p_set_secret(rp2p_t *ctx, const char *secret) {
    if (!ctx || !secret) return RP2P_ERROR;
    if (secret[0] && !rp2p_is_valid_pass_token(secret)) return RP2P_ERROR;
    strncpy(ctx->secret, secret, RP2P_SECRET_MAX);
    ctx->secret[RP2P_SECRET_MAX] = '\0';
    return RP2P_OK;
}

/**
 * Parses the VIP seat map from one whitespace-separated string.
 * @param ctx Open context.
 * @param vip Whitespace-separated id/pass pairs.
 * @param err Output error buffer.
 * @param err_cap Output error buffer capacity.
 * @return RP2P_OK on success, RP2P_ERROR on parse failure.
 */
int rp2p_set_vip(
rp2p_t *ctx,
const char *vip,
char *err,
size_t err_cap
)
{
    char *copy;
    char *cursor;

    if (!ctx) return RP2P_ERROR;
    free(ctx->vips);
    ctx->vips = NULL;
    ctx->n_vips = 0;
    ctx->vips_cap = 0;
    rp2p_update_nonvip_cap(ctx);
    if (!vip || !vip[0]) return RP2P_OK;
    copy = (char *)malloc(strlen(vip) + 1);
    if (!copy) {
        if (err && err_cap > 0)
            snprintf(err, err_cap, "failed to allocate RP2P_VIP buffer");
        return RP2P_ERROR;
    }
    strcpy(copy, vip);
    cursor = rp2p_trim(copy);
    while (cursor && *cursor) {
        char *id;
        char *pass;

        id = cursor;
        while (*cursor && !rp2p_is_space(*cursor)) cursor++;
        if (*cursor) *cursor++ = '\0';
        while (*cursor && rp2p_is_space(*cursor)) cursor++;
        if (!*cursor) {
            if (err && err_cap > 0)
                snprintf(err, err_cap, "RP2P_VIP has odd token count");
            free(copy);
            free(ctx->vips);
            ctx->vips = NULL;
            ctx->n_vips = 0;
            ctx->vips_cap = 0;
            rp2p_update_nonvip_cap(ctx);
            return RP2P_ERROR;
        }
        pass = cursor;
        while (*cursor && !rp2p_is_space(*cursor)) cursor++;
        if (*cursor) *cursor++ = '\0';
        while (*cursor && rp2p_is_space(*cursor)) cursor++;
        if (rp2p_add_vip(ctx, id, pass, err, err_cap) != RP2P_OK) {
            free(copy);
            free(ctx->vips);
            ctx->vips = NULL;
            ctx->n_vips = 0;
            ctx->vips_cap = 0;
            rp2p_update_nonvip_cap(ctx);
            return RP2P_ERROR;
        }
    }
    free(copy);
    rp2p_update_nonvip_cap(ctx);
    return RP2P_OK;
}

/**
 * Find peer.
 * @return 0 on success, -1 on error.
 */
static int rp2p_find_peer(rp2p_t *ctx, const char *id) {
    int i;
    for (i = 0; i < ctx->n_peers; i++) {
        if (strcmp(ctx->peers[i].id, id) == 0)
            return i;
    }
    return -1;
}

/**
 * Evict stale.
 * @return Status code.
 */
static void rp2p_evict_stale(rp2p_t *ctx) {
    uint64_t now;
    int i;
    now = rp2p_now_s();
    for (i = ctx->n_peers - 1; i >= 0; i--) {
        if (now - ctx->peers[i].last_seen > RP2P_ETIMEOUT_SEC) {
            if (i < ctx->n_peers - 1) {
                memmove(&ctx->peers[i], &ctx->peers[i + 1],
                    (size_t)(ctx->n_peers - i - 1) * sizeof(ctx->peers[0]));
            }
            ctx->n_peers--;
        }
    }
}

/**
 * Generate key.
 * @return Status code.
 */
static int rp2p_generate_key(char *out) {
    unsigned char random_bytes[RP2P_KEY_SZ / 2];

    if (!out) return 0;
    if (rp2p_fill_random(random_bytes, sizeof(random_bytes)) != 0)
        return 0;
    return rp2p_hex_encode(random_bytes, sizeof(random_bytes), out,
        RP2P_KEY_SZ + 1);
}

/**
 * Add peer.
 * @return 0 on success, -1 on error.
 */
static int rp2p_add_peer(rp2p_t *ctx, const char *id)
{
    size_t id_len;
    int idx;
    int is_vip;

    idx = rp2p_find_peer(ctx, id);
    if (idx >= 0) {
        ctx->peers[idx].last_seen = rp2p_now_s();
        if (!rp2p_generate_key(ctx->peers[idx].key))
            return RP2P_ERROR;
        return RP2P_OK;
    }

    is_vip = rp2p_find_vip(ctx, id) >= 0;
    if (!is_vip && rp2p_count_nonvip_peers(ctx) >= ctx->nonvip_cap)
        return RP2P_EFULL;
    if (rp2p_ensure_peer_storage(ctx, ctx->n_peers + 1) != RP2P_OK)
        return RP2P_ERROR;

    id_len = strlen(id);
    if (id_len > RP2P_ID_MAX)
        id_len = RP2P_ID_MAX;
    memcpy(ctx->peers[ctx->n_peers].id, id, id_len);
    ctx->peers[ctx->n_peers].id[id_len] = '\0';

    ctx->peers[ctx->n_peers].last_seen = rp2p_now_s();
    if (!rp2p_generate_key(ctx->peers[ctx->n_peers].key))
        return RP2P_ERROR;
    ctx->n_peers++;
    return RP2P_OK;
}

/**
 * Remove peer.
 * @return 0 on success, -1 on error.
 */
static int rp2p_remove_peer(rp2p_t *ctx, const char *id) {
    int idx;
    idx = rp2p_find_peer(ctx, id);
    if (idx < 0) return RP2P_ENOENT;
    if (idx < ctx->n_peers - 1) {
        memmove(&ctx->peers[idx], &ctx->peers[idx + 1],
            (size_t)(ctx->n_peers - idx - 1) * sizeof(ctx->peers[0]));
    }
    ctx->n_peers--;
    return RP2P_OK;
}

/**
 * Refreshes one existing peer entry.
 * @param ctx  Open context.
 * @param id   Peer identifier.
 * @param addr Peer address.
 * @param port Peer port.
 * @return 0 on success, -1 on error.
 */
static int rp2p_refresh_peer(rp2p_t *ctx, const char *id)
{
    int idx;

    idx = rp2p_find_peer(ctx, id);
    if (idx < 0) return RP2P_ENOENT;
    ctx->peers[idx].last_seen = rp2p_now_s();
    return RP2P_OK;
}

/**
 * Finds one pending register challenge.
 * @param ctx     Open context.
 * @param peer_sa Remote peer address.
 * @return Challenge index on success, -1 on failure.
 */
static int rp2p_find_pow_challenge(rp2p_t *ctx,
    const struct sockaddr_storage *peer_sa)
{
    int i;

    for (i = 0; i < ctx->n_pow_challenges; i++) {
        if (rp2p_sockaddr_equal(&ctx->pow_challenges[i].addr, peer_sa))
            return i;
    }
    return -1;
}

/**
 * Removes one pending register challenge.
 * @param ctx Open context.
 * @param idx Challenge index.
 * @return None.
 */
static void rp2p_remove_pow_challenge(rp2p_t *ctx, int idx) {
    if (!ctx || idx < 0 || idx >= ctx->n_pow_challenges) return;
    if (idx < ctx->n_pow_challenges - 1)
        ctx->pow_challenges[idx] = ctx->pow_challenges[ctx->n_pow_challenges - 1];
    ctx->n_pow_challenges--;
}

/**
 * Evicts expired pending register challenges.
 * @param ctx Open context.
 * @param now Current monotonic time in seconds.
 * @return None.
 */
static void rp2p_evict_pow_challenges(rp2p_t *ctx, uint64_t now) {
    int i;

    if (!ctx) return;
    for (i = ctx->n_pow_challenges - 1; i >= 0; i--) {
        if (ctx->pow_challenges[i].expires_at != 0 &&
            now >= ctx->pow_challenges[i].expires_at)
            rp2p_remove_pow_challenge(ctx, i);
    }
}

/**
 * Stores one pending register challenge.
 * @param ctx       Open context.
 * @param peer_sa   Remote peer address.
 * @param id        Challenged service identifier.
 * @param nonce_hex Challenge nonce in hex.
 * @return 1 on success, 0 on failure.
 */
static int rp2p_store_pow_challenge(rp2p_t *ctx,
    const struct sockaddr_storage *peer_sa, const char *id, const char *nonce_hex)
{
    int idx;
    size_t id_len;
    size_t nonce_len;

    idx = rp2p_find_pow_challenge(ctx, peer_sa);
    if (idx < 0) {
        if (ctx->n_pow_challenges >= RP2P_POW_CHALLENGES_MAX) return 0;
        idx = ctx->n_pow_challenges++;
    }
    nonce_len = strlen(nonce_hex);
    if (nonce_len > sizeof(ctx->pow_challenges[idx].nonce_hex) - 1)
        nonce_len = sizeof(ctx->pow_challenges[idx].nonce_hex) - 1;
    memcpy(ctx->pow_challenges[idx].nonce_hex, nonce_hex, nonce_len);
    ctx->pow_challenges[idx].nonce_hex[nonce_len] = '\0';
    ctx->pow_challenges[idx].nonce_hex[16] = '\0';
    id_len = strlen(id);
    if (id_len > sizeof(ctx->pow_challenges[idx].id) - 1)
        id_len = sizeof(ctx->pow_challenges[idx].id) - 1;
    memcpy(ctx->pow_challenges[idx].id, id, id_len);
    ctx->pow_challenges[idx].id[id_len] = '\0';
    ctx->pow_challenges[idx].id[RP2P_ID_MAX] = '\0';
    ctx->pow_challenges[idx].addr = *peer_sa;
    ctx->pow_challenges[idx].issued_at = rp2p_now_s();
    ctx->pow_challenges[idx].expires_at =
        ctx->pow_challenges[idx].issued_at + RP2P_POW_CHALLENGE_TTL_S;
    return 1;
}

/**
 * Formats one successful register reply.
 * @param ctx      Open context.
 * @param id       Registered service identifier.
 * @param reply    Output reply buffer.
 * @param reply_sz Output reply capacity.
 * @return 1 on success, 0 on failure.
 */
static int rp2p_format_register_ok(rp2p_t *ctx, const char *id,
    char *reply, size_t reply_sz)
{
    int pidx;

    pidx = rp2p_find_peer(ctx, id);
    if (pidx < 0) return 0;
    snprintf(reply, reply_sz, "%s%s", RP2P_CTRTOK_OK_KEY,
        ctx->peers[pidx].key);
    return 1;
}

/**
 * Conn add.
 * @return 0 on success, -1 on error.
 */
static int rp2p_conn_add(rp2p_t *ctx, rp2p_fd_t fd) {
#ifdef _WIN32
    if (fd == INVALID_SOCKET) return RP2P_ERROR;
#else
    if (fd < 0) return RP2P_ERROR;
    if (fd >= FD_SETSIZE) { RP2P_FD_CLOSE(fd); return RP2P_ERROR; }
#endif
    if (ctx->n_conns >= ctx->conns_cap) {
        int new_cap = ctx->conns_cap == 0 ? 64 : ctx->conns_cap * 2;
        rp2p_tcp_conn_t *c = (rp2p_tcp_conn_t *)realloc(
            ctx->conns, (size_t)new_cap * sizeof(rp2p_tcp_conn_t));
        if (!c) return RP2P_ERROR;
        ctx->conns = c;
        ctx->conns_cap = new_cap;
    }
    ctx->conns[ctx->n_conns].fd = fd;
    ctx->conns[ctx->n_conns].buf_len = 0;
    ctx->conns[ctx->n_conns].id[0] = '\0';
    ctx->conns[ctx->n_conns].registered = 0;
    ctx->conns[ctx->n_conns].hello_ok = 0;
    ctx->n_conns++;
    return RP2P_OK;
}

/**
 * Conn remove.
 * @return Status code.
 */
static void rp2p_conn_remove(rp2p_t *ctx, int idx) {
    if (idx < 0 || idx >= ctx->n_conns) return;
    rp2p_fd_t fd = ctx->conns[idx].fd;
    RP2P_FD_CLOSE(fd);
    for (int pi = 0; pi < ctx->n_pending_punches; pi++) {
        if (ctx->pending_punches[pi].consumer_fd == fd) {
            ctx->pending_punches[pi] = ctx->pending_punches[--ctx->n_pending_punches];
            pi--;
        }
    }
    if (idx < ctx->n_conns - 1) {
        memmove(&ctx->conns[idx], &ctx->conns[idx + 1],
            (size_t)(ctx->n_conns - idx - 1) * sizeof(ctx->conns[0]));
    }
    ctx->n_conns--;
}

/**
 * Pending punch find.
 * @return index on success, -1 on error.
 */
static int rp2p_pending_punch_find(rp2p_t *ctx, const char *target_id, const char *self_id, const char *sess_id) {
    for (int i = 0; i < ctx->n_pending_punches; i++) {
        if (strcmp(ctx->pending_punches[i].target_id, target_id) == 0 &&
            strcmp(ctx->pending_punches[i].self_id, self_id) == 0 &&
            strcmp(ctx->pending_punches[i].sess_id, sess_id) == 0)
            return i;
    }
    return -1;
}

/**
 * Pending punch remove.
 * @return None.
 */
static void rp2p_pending_punch_remove(rp2p_t *ctx, int idx) {
    if (idx >= 0 && idx < ctx->n_pending_punches)
        ctx->pending_punches[idx] = ctx->pending_punches[--ctx->n_pending_punches];
}

/**
 * Pending punch evict stale.
 * @return None.
 */
static void rp2p_pending_punch_evict_stale(rp2p_t *ctx) {
    uint64_t now = rp2p_now_s();
    for (int i = 0; i < ctx->n_pending_punches; i++) {
        if (now - ctx->pending_punches[i].ts > 30) {
            ctx->pending_punches[i] = ctx->pending_punches[--ctx->n_pending_punches];
            i--;
        }
    }
}

/**
 * Appends text to a bounded output buffer.
 * @param out Output buffer.
 * @param cap Output buffer capacity.
 * @param text Text to append.
 * @return 1 on success, 0 on overflow.
 */
static int rp2p_append_text(char *out, size_t cap, const char *text) {
    size_t used;
    size_t add;

    if (!out || !text || cap == 0) return 0;
    used = strlen(out);
    add = strlen(text);
    if (used >= cap || add >= cap - used) return 0;
    memcpy(out + used, text, add + 1);
    return 1;
}

/**
 * Copies one colon-delimited field from a cursor.
 * @param cursor Input cursor updated after the field.
 * @param out    Output field buffer.
 * @param cap    Output field capacity.
 * @param delim  Required delimiter or NUL for final field.
 * @return 1 on success, 0 on malformed input.
 */
static int rp2p_parse_field(const char **cursor, char *out, size_t cap,
    char delim)
{
    const char *start;
    const char *end;
    size_t len;

    if (!cursor || !*cursor || !out || cap == 0) return 0;
    start = *cursor;
    end = delim ? strchr(start, delim) : start + strlen(start);
    if (!end) return 0;
    len = (size_t)(end - start);
    if (len == 0 || len >= cap) return 0;
    memcpy(out, start, len);
    out[len] = '\0';
    *cursor = delim ? end + 1 : end;
    return 1;
}

/**
 * Reports whether a token is lowercase or uppercase hexadecimal.
 * @param text Input token.
 * @param len  Required token length.
 * @return 1 when valid, 0 otherwise.
 */
static int rp2p_is_hex_token(const char *text, size_t len) {
    size_t i;

    if (!text || strlen(text) != len) return 0;
    for (i = 0; i < len; i++) {
        if ((text[i] >= '0' && text[i] <= '9') ||
            (text[i] >= 'a' && text[i] <= 'f') ||
            (text[i] >= 'A' && text[i] <= 'F'))
            continue;
        return 0;
    }
    return 1;
}

/**
 * Reports whether a session token is bounded and alphanumeric.
 * @param text Input token.
 * @return 1 when valid, 0 otherwise.
 */
static int rp2p_is_session_token(const char *text) {
    size_t i;

    if (!text || !text[0]) return 0;
    for (i = 0; text[i]; i++) {
        if (i >= RP2P_CTRL_SESSION_MAX) return 0;
        if (!((text[i] >= 'a' && text[i] <= 'z') ||
            (text[i] >= 'A' && text[i] <= 'Z') ||
            (text[i] >= '0' && text[i] <= '9')))
            return 0;
    }
    return 1;
}

/**
 * Reports whether a transient punch id is bounded and safe.
 * @param text Input token.
 * @return 1 when valid, 0 otherwise.
 */
static int rp2p_is_punch_id(const char *text) {
    size_t i;

    if (!text || !text[0]) return 0;
    for (i = 0; text[i]; i++) {
        if (i >= RP2P_ID_MAX) return 0;
        if (!((text[i] >= 'a' && text[i] <= 'z') ||
            (text[i] >= 'A' && text[i] <= 'Z') ||
            (text[i] >= '0' && text[i] <= '9') || text[i] == '-'))
            return 0;
    }
    return 1;
}

/**
 * Parses one strict decimal TCP or UDP port.
 * @param text Input token.
 * @param port Output port.
 * @return 1 on success, 0 on malformed input.
 */
static int rp2p_parse_port_token(const char *text, unsigned short *port) {
    unsigned long value;
    char *end;

    if (!text || !text[0] || !port) return 0;
    if (text[0] == '-' || text[0] == '+') return 0;
    value = strtoul(text, &end, 10);
    if (*end != '\0' || value == 0 || value > 65535) return 0;
    *port = (unsigned short)value;
    return 1;
}

/**
 * Maps one candidate type token to an internal type.
 * @param text Input candidate type token.
 * @param type Output candidate type.
 * @return 1 on success, 0 on unknown type.
 */
static int rp2p_parse_candidate_type(const char *text,
    rp2p_candidate_type_t *type)
{
    if (!text || !type) return 0;
    if (strcmp(text, "host") == 0) *type = RP2P_CAND_HOST;
    else if (strcmp(text, "lan") == 0) *type = RP2P_CAND_LAN;
    else if (strcmp(text, "public") == 0) *type = RP2P_CAND_PUBLIC;
    else if (strcmp(text, "srflx") == 0) *type = RP2P_CAND_SRFLX;
    else return 0;
    return 1;
}

/**
 * Returns the textual name for one local candidate type.
 * @param type Candidate type.
 * @return Candidate type name.
 */
static const char *rp2p_candidate_type_name(rp2p_candidate_type_t type) {
    if (type == RP2P_CAND_LAN) return "lan";
    if (type == RP2P_CAND_PUBLIC) return "public";
    if (type == RP2P_CAND_SRFLX) return "srflx";
    return "host";
}

/**
 * Returns the address family for one candidate address.
 * @param candidate Candidate to inspect.
 * @return AF_INET, AF_INET6, or AF_UNSPEC.
 */
static int rp2p_candidate_family(const rp2p_candidate_t *candidate) {
    struct in_addr ipv4;
    struct in6_addr ipv6;

    if (!candidate) return AF_UNSPEC;
    if (inet_pton(AF_INET, candidate->addr, &ipv4) == 1) return AF_INET;
    if (inet_pton(AF_INET6, candidate->addr, &ipv6) == 1) return AF_INET6;
    return AF_UNSPEC;
}

/**
 * Returns the deterministic local priority for one candidate.
 * @param candidate Candidate to rank.
 * @return Lower priority values are attempted first.
 */
static unsigned int rp2p_candidate_priority(
    const rp2p_candidate_t *candidate)
{
    int family;
    unsigned int base;

    if (!candidate) return 900u;
    family = rp2p_candidate_family(candidate);
    if (family == AF_INET6) base = 100u;
    else if (family == AF_INET) base = 200u;
    else return 900u;
    if (candidate->type == RP2P_CAND_HOST) return base;
    if (candidate->type == RP2P_CAND_LAN) return base + 10u;
    if (candidate->type == RP2P_CAND_PUBLIC) return base + 20u;
    if (candidate->type == RP2P_CAND_SRFLX) return base + 30u;
    if (candidate->type == RP2P_CAND_PRFLX) return base + 40u;
    if (candidate->type == RP2P_CAND_PREDICTED) return base + 50u;
    return 900u;
}

/**
 * Reports whether two candidates describe the same network endpoint.
 * @param a First candidate.
 * @param b Second candidate.
 * @return 1 when equivalent, 0 otherwise.
 */
static int rp2p_candidate_same_endpoint(const rp2p_candidate_t *a,
    const rp2p_candidate_t *b)
{
    struct sockaddr_storage aa;
    struct sockaddr_storage bb;

    if (!a || !b || a->port != b->port) return 0;
    if (rp2p_candidate_family(a) != rp2p_candidate_family(b)) return 0;
    if (!rp2p_candidate_sockaddr(a, &aa)) return 0;
    if (!rp2p_candidate_sockaddr(b, &bb)) return 0;
    return rp2p_sockaddr_equal(&aa, &bb);
}

/**
 * Compares two candidates by local priority and stable textual fields.
 * @param a First candidate.
 * @param b Second candidate.
 * @return Negative, zero, or positive comparison result.
 */
static int rp2p_candidate_compare(const rp2p_candidate_t *a,
    const rp2p_candidate_t *b)
{
    int cmp;

    if (a->priority != b->priority)
        return a->priority < b->priority ? -1 : 1;
    if (a->type != b->type) return (int)a->type - (int)b->type;
    cmp = strcmp(a->addr, b->addr);
    if (cmp != 0) return cmp;
    return (int)a->port - (int)b->port;
}

/**
 * Normalizes candidate priority, removes duplicates, and sorts the list.
 * @param candidates Candidate array.
 * @param count      Candidate count in and out.
 * @return 1 on success, 0 on malformed input.
 */
static int rp2p_normalize_candidates(rp2p_candidate_t *candidates,
    int *count)
{
    int i;
    int n;

    if (!candidates || !count || *count < 0 || *count > RP2P_CANDIDATES_MAX)
        return 0;
    n = 0;
    for (i = 0; i < *count; i++) {
        int j;
        if (candidates[i].port == 0) return 0;
        if (rp2p_candidate_family(&candidates[i]) == AF_UNSPEC) return 0;
        candidates[i].priority = rp2p_candidate_priority(&candidates[i]);
        if (candidates[i].priority >= 900u) return 0;
        for (j = 0; j < n; j++) {
            if (!rp2p_candidate_same_endpoint(&candidates[j], &candidates[i]))
                continue;
            if (rp2p_candidate_compare(&candidates[i], &candidates[j]) < 0)
                candidates[j] = candidates[i];
            break;
        }
        if (j == n) candidates[n++] = candidates[i];
    }
    for (i = 1; i < n; i++) {
        rp2p_candidate_t item = candidates[i];
        int j = i - 1;
        while (j >= 0 && rp2p_candidate_compare(&item, &candidates[j]) < 0) {
            candidates[j + 1] = candidates[j];
            j--;
        }
        candidates[j + 1] = item;
    }
    *count = n;
    return 1;
}

/**
 * Parses one strict candidate line.
 * @param line Input line.
 * @param out  Output candidate.
 * @return 1 on success, 0 on malformed input.
 */
static int rp2p_parse_candidate_line(const char *line,
    rp2p_candidate_t *out)
{
    const char *cursor;
    const char *end;
    char type_text[16];
    char addr[RP2P_ADDR_MAX + 1];
    char port_text[8];
    struct in_addr ipv4;
    struct in6_addr ipv6;
    size_t addr_len;

    if (!line || !out || strncmp(line, RP2P_CTRTOK_CAND,
        strlen(RP2P_CTRTOK_CAND)) != 0)
        return 0;
    cursor = line + strlen(RP2P_CTRTOK_CAND);
    if (!rp2p_parse_field(&cursor, type_text, sizeof(type_text), ':'))
        return 0;
    if (*cursor == '[') {
        cursor++;
        end = strchr(cursor, ']');
        if (!end || end[1] != ':') return 0;
        addr_len = (size_t)(end - cursor);
        if (addr_len == 0 || addr_len >= sizeof(addr)) return 0;
        memcpy(addr, cursor, addr_len);
        addr[addr_len] = '\0';
        cursor = end + 2;
    } else {
        if (!rp2p_parse_field(&cursor, addr, sizeof(addr), ':'))
            return 0;
    }
    if (!rp2p_parse_field(&cursor, port_text, sizeof(port_text), '\0'))
        return 0;
    if (*cursor != '\0') return 0;
    if (!rp2p_parse_candidate_type(type_text, &out->type)) return 0;
    if (inet_pton(AF_INET, addr, &ipv4) != 1 &&
        inet_pton(AF_INET6, addr, &ipv6) != 1)
        return 0;
    if (!rp2p_parse_port_token(port_text, &out->port)) return 0;
    snprintf(out->addr, sizeof(out->addr), "%s", addr);
    out->priority = rp2p_candidate_priority(out);
    if (out->priority >= 900u) return 0;
    return 1;
}

/**
 * Finds a complete END-framed block after the current line.
 * @param start First byte after the command line.
 * @param limit One byte past available buffered data.
 * @param end   Output pointer after END line.
 * @return 1 when END is present, 0 otherwise.
 */
static int rp2p_find_end_line(char *start, char *limit, char **end) {
    char *cursor;
    char *newline;

    if (!start || !limit || !end) return 0;
    cursor = start;
    while (cursor < limit &&
        (newline = (char *)memchr(cursor, '\n', (size_t)(limit - cursor))) != NULL)
    {
        size_t len = (size_t)(newline - cursor);
        if (len == strlen(RP2P_CTRTOK_END) &&
            memcmp(cursor, RP2P_CTRTOK_END, strlen(RP2P_CTRTOK_END)) == 0) {
            *end = newline + 1;
            return 1;
        }
        cursor = newline + 1;
    }
    return 0;
}

/**
 * Parse remote candidates.
 * Summary: Parses candidate list from a buffer.
 * @param buf       Input buffer.
 * @param out       Output array.
 * @param out_count Output count.
 * @return 1 on success, 0 on malformed input.
 */
static int rp2p_parse_remote_candidates(const char *buf,
    rp2p_candidate_t *out, int *out_count)
{
    const char *p;

    if (!buf || !out || !out_count) return 0;
    *out_count = 0;
    p = buf;
    if (strncmp(p, RP2P_CTRTOK_PUNCH_REQ2,
        strlen(RP2P_CTRTOK_PUNCH_REQ2)) == 0 ||
        strncmp(p, RP2P_CTRTOK_PUNCH_OK2,
        strlen(RP2P_CTRTOK_PUNCH_OK2)) == 0 ||
        strncmp(p, RP2P_CTRTOK_PUNCH_CALL2,
        strlen(RP2P_CTRTOK_PUNCH_CALL2)) == 0)
    {
        p = strchr(p, '\n');
        if (!p) return 0;
        p++;
    }
    while (p && *p) {
        const char *nl = strchr(p, '\n');
        char line[128];
        size_t len;

        if (!nl) return 0;
        len = (size_t)(nl - p);
        if (len == 0) return 0;
        if (len == strlen(RP2P_CTRTOK_END) &&
            memcmp(p, RP2P_CTRTOK_END, strlen(RP2P_CTRTOK_END)) == 0)
            return rp2p_normalize_candidates(out, out_count);
        if (len >= sizeof(line)) return 0;
        memcpy(line, p, len);
        line[len] = '\0';
        if (strncmp(line, RP2P_CTRTOK_CAND,
            strlen(RP2P_CTRTOK_CAND)) != 0)
            return 0;
        if (*out_count >= RP2P_CANDIDATES_MAX) return 0;
        if (!rp2p_parse_candidate_line(line, &out[*out_count])) return 0;
        (*out_count)++;
        p = nl + 1;
    }
    return 0;
}

/**
 * Appends one validated candidate line to a control message.
 * @param msg  Output message buffer.
 * @param cap  Output message capacity.
 * @param line Candidate line.
 * @return 1 on success, 0 on malformed input or overflow.
 */
static int rp2p_append_candidate_line(char *msg, size_t cap,
    const char *line)
{
    rp2p_candidate_t candidate;

    if (!rp2p_parse_candidate_line(line, &candidate)) return 0;
    if (!rp2p_append_text(msg, cap, line)) return 0;
    if (!rp2p_append_text(msg, cap, "\n")) return 0;
    return 1;
}

/**
 * Appends a bounded local candidate line.
 * @param msg       Output message buffer.
 * @param cap       Output message capacity.
 * @param candidate Candidate to append.
 * @return 1 on success, 0 on overflow.
 */
static int rp2p_append_candidate(char *msg, size_t cap,
    const rp2p_candidate_t *candidate)
{
    char cbuf[128];
    int n;

    if (!candidate) return 0;
    if (strchr(candidate->addr, ':')) {
        n = snprintf(cbuf, sizeof(cbuf), "%s%s:[%s]:%u\n",
            RP2P_CTRTOK_CAND, rp2p_candidate_type_name(candidate->type),
            candidate->addr, candidate->port);
    } else {
        n = snprintf(cbuf, sizeof(cbuf), "%s%s:%s:%u\n",
            RP2P_CTRTOK_CAND, rp2p_candidate_type_name(candidate->type),
            candidate->addr, candidate->port);
    }
    if (n < 0 || (size_t)n >= sizeof(cbuf)) return 0;
    return rp2p_append_text(msg, cap, cbuf);
}

/**
 * Copies validated CAND lines from one complete END-framed block.
 * @param cursor Input cursor after the command line.
 * @param end    One byte after END line.
 * @param msg    Output control message.
 * @param cap    Output control message capacity.
 * @return 1 on success, 0 on malformed input.
 */
static int rp2p_copy_candidate_block(char *cursor, char *end, char *msg,
    size_t cap)
{
    while (cursor < end) {
        char *newline = (char *)memchr(cursor, '\n', (size_t)(end - cursor));
        char line[128];
        size_t len;

        if (!newline) return 0;
        len = (size_t)(newline - cursor);
        if (len == strlen(RP2P_CTRTOK_END) &&
            memcmp(cursor, RP2P_CTRTOK_END, strlen(RP2P_CTRTOK_END)) == 0) {
            return rp2p_append_text(msg, cap, RP2P_CTRTOK_END "\n");
        }
        if (len == 0 || len >= sizeof(line)) return 0;
        memcpy(line, cursor, len);
        line[len] = '\0';
        if (!rp2p_append_candidate_line(msg, cap, line)) return 0;
        cursor = newline + 1;
    }
    return 0;
}

/**
 * Parses a REGISTER command without proof material.
 * @param line Input command line.
 * @param id   Output service id.
 * @return 1 on success, 0 on malformed input.
 */
static int rp2p_parse_register_id(const char *line,
    char id[RP2P_ID_MAX + 1])
{
    const char *cursor;

    if (!line || strncmp(line, RP2P_CTRTOK_REGISTER,
        strlen(RP2P_CTRTOK_REGISTER)) != 0)
        return 0;
    cursor = line + strlen(RP2P_CTRTOK_REGISTER);
    if (!rp2p_parse_field(&cursor, id, RP2P_ID_MAX + 1, '\0'))
        return 0;
    if (*cursor != '\0') return 0;
    return rp2p_is_valid_id(id);
}

/**
 * Parses a REGISTER proof command.
 * @param line     Input command line.
 * @param id       Output service id.
 * @param solution Output solution token.
 * @param proof    Output proof token.
 * @return 1 on success, 0 on malformed input.
 */
static int rp2p_parse_register_solution(const char *line,
    char id[RP2P_ID_MAX + 1], char solution[17], char proof[65])
{
    const char *cursor;

    if (!line || strncmp(line, RP2P_CTRTOK_REGISTER,
        strlen(RP2P_CTRTOK_REGISTER)) != 0)
        return 0;
    cursor = line + strlen(RP2P_CTRTOK_REGISTER);
    if (!rp2p_parse_field(&cursor, id, RP2P_ID_MAX + 1, ':'))
        return 0;
    if (strncmp(cursor, RP2P_CTRTOK_SOLUTION,
        strlen(RP2P_CTRTOK_SOLUTION)) != 0)
        return 0;
    cursor += strlen(RP2P_CTRTOK_SOLUTION);
    if (!rp2p_parse_field(&cursor, solution, 17, ':')) return 0;
    if (strncmp(cursor, RP2P_CTRTOK_PROOF,
        strlen(RP2P_CTRTOK_PROOF)) != 0)
        return 0;
    cursor += strlen(RP2P_CTRTOK_PROOF);
    if (!rp2p_parse_field(&cursor, proof, 65, '\0')) return 0;
    if (*cursor != '\0') return 0;
    if (!rp2p_is_valid_id(id)) return 0;
    if (strlen(solution) == 0 || strlen(solution) > 16) return 0;
    if (!rp2p_is_hex_token(solution, strlen(solution))) return 0;
    if (!rp2p_is_hex_token(proof, 64)) return 0;
    return 1;
}

/**
 * Parses a PUNCH_REQ2 command line.
 * @param line      Input command line.
 * @param self_id   Output requester id.
 * @param target_id Output target id.
 * @param sess_id   Output session id.
 * @return 1 on success, 0 on malformed input.
 */
static int rp2p_parse_punch_req2(const char *line,
    char self_id[RP2P_ID_MAX + 1], char target_id[RP2P_ID_MAX + 1],
    char sess_id[RP2P_CTRL_SESSION_MAX + 1])
{
    const char *cursor;

    if (!line || strncmp(line, RP2P_CTRTOK_PUNCH_REQ2,
        strlen(RP2P_CTRTOK_PUNCH_REQ2)) != 0)
        return 0;
    cursor = line + strlen(RP2P_CTRTOK_PUNCH_REQ2);
    if (!rp2p_parse_field(&cursor, self_id, RP2P_ID_MAX + 1, ':'))
        return 0;
    if (!rp2p_parse_field(&cursor, target_id, RP2P_ID_MAX + 1, ':'))
        return 0;
    if (!rp2p_parse_field(&cursor, sess_id, RP2P_CTRL_SESSION_MAX + 1,
        '\0'))
        return 0;
    if (*cursor != '\0') return 0;
    return rp2p_is_punch_id(self_id) && rp2p_is_valid_id(target_id) &&
        rp2p_is_session_token(sess_id);
}

/**
 * Parses a PUNCH_ACK2 command line.
 * @param line      Input command line.
 * @param self_id   Output publisher id.
 * @param target_id Output requester id.
 * @param sess_id   Output session id.
 * @return 1 on success, 0 on malformed input.
 */
static int rp2p_parse_punch_ack2(const char *line,
    char self_id[RP2P_ID_MAX + 1], char target_id[RP2P_ID_MAX + 1],
    char sess_id[RP2P_CTRL_SESSION_MAX + 1])
{
    const char *cursor;

    if (!line || strncmp(line, RP2P_CTRTOK_PUNCH_ACK2,
        strlen(RP2P_CTRTOK_PUNCH_ACK2)) != 0)
        return 0;
    cursor = line + strlen(RP2P_CTRTOK_PUNCH_ACK2);
    if (!rp2p_parse_field(&cursor, self_id, RP2P_ID_MAX + 1, ':'))
        return 0;
    if (!rp2p_parse_field(&cursor, target_id, RP2P_ID_MAX + 1, ':'))
        return 0;
    if (!rp2p_parse_field(&cursor, sess_id, RP2P_CTRL_SESSION_MAX + 1,
        '\0'))
        return 0;
    if (*cursor != '\0') return 0;
    return rp2p_is_valid_id(self_id) && rp2p_is_punch_id(target_id) &&
        rp2p_is_session_token(sess_id);
}

/**
 * Parses a PUNCH_CALL2 command line.
 * @param line    Input command line.
 * @param peer_id Output peer id.
 * @param sess_id Output session id.
 * @return 1 on success, 0 on malformed input.
 */
static int rp2p_parse_punch_call2(const char *line,
    char peer_id[RP2P_ID_MAX + 1], char sess_id[RP2P_CTRL_SESSION_MAX + 1])
{
    const char *cursor;

    if (!line || strncmp(line, RP2P_CTRTOK_PUNCH_CALL2,
        strlen(RP2P_CTRTOK_PUNCH_CALL2)) != 0)
        return 0;
    cursor = line + strlen(RP2P_CTRTOK_PUNCH_CALL2);
    if (!rp2p_parse_field(&cursor, peer_id, RP2P_ID_MAX + 1, ':'))
        return 0;
    if (!rp2p_parse_field(&cursor, sess_id, RP2P_CTRL_SESSION_MAX + 1,
        '\0'))
        return 0;
    if (*cursor != '\0') return 0;
    return rp2p_is_punch_id(peer_id) && rp2p_is_session_token(sess_id);
}

/**
 * Parses a PUNCH_OK2 command line.
 * @param line    Input command line.
 * @param peer_id Output peer id.
 * @param sess_id Output session id.
 * @return 1 on success, 0 on malformed input.
 */
static int rp2p_parse_punch_ok2(const char *line,
    char peer_id[RP2P_ID_MAX + 1], char sess_id[RP2P_CTRL_SESSION_MAX + 1])
{
    const char *cursor;

    if (!line || strncmp(line, RP2P_CTRTOK_PUNCH_OK2,
        strlen(RP2P_CTRTOK_PUNCH_OK2)) != 0)
        return 0;
    cursor = line + strlen(RP2P_CTRTOK_PUNCH_OK2);
    if (!rp2p_parse_field(&cursor, peer_id, RP2P_ID_MAX + 1, ':'))
        return 0;
    if (!rp2p_parse_field(&cursor, sess_id, RP2P_CTRL_SESSION_MAX + 1,
        '\0'))
        return 0;
    if (*cursor != '\0') return 0;
    return rp2p_is_punch_id(peer_id) && rp2p_is_session_token(sess_id);
}

/**
 * Parses a DEREGISTER command line.
 * @param line Input command line.
 * @param id   Output service id.
 * @param key  Output registration key.
 * @return 1 on success, 0 on malformed input.
 */
static int rp2p_parse_deregister(const char *line,
    char id[RP2P_ID_MAX + 1], char key[RP2P_KEY_STR_SZ])
{
    const char *cursor;

    if (!line || strncmp(line, RP2P_CTRTOK_DEREGISTER,
        strlen(RP2P_CTRTOK_DEREGISTER)) != 0)
        return 0;
    cursor = line + strlen(RP2P_CTRTOK_DEREGISTER);
    if (!rp2p_parse_field(&cursor, id, RP2P_ID_MAX + 1, ':')) return 0;
    if (strncmp(cursor, RP2P_CTRTOK_KEY, strlen(RP2P_CTRTOK_KEY)) != 0)
        return 0;
    cursor += strlen(RP2P_CTRTOK_KEY);
    if (!rp2p_parse_field(&cursor, key, RP2P_KEY_STR_SZ, '\0'))
        return 0;
    if (*cursor != '\0') return 0;
    return rp2p_is_valid_id(id) && rp2p_is_hex_token(key, strlen(key));
}

/**
 * Parses a LOOKUP command line.
 * @param line Input command line.
 * @param id   Output service id.
 * @return 1 on success, 0 on malformed input.
 */
static int rp2p_parse_lookup(const char *line,
    char id[RP2P_ID_MAX + 1])
{
    const char *cursor;

    if (!line || strncmp(line, RP2P_CTRTOK_LOOKUP,
        strlen(RP2P_CTRTOK_LOOKUP)) != 0)
        return 0;
    cursor = line + strlen(RP2P_CTRTOK_LOOKUP);
    if (!rp2p_parse_field(&cursor, id, RP2P_ID_MAX + 1, '\0'))
        return 0;
    if (*cursor != '\0') return 0;
    return rp2p_is_valid_id(id);
}

/**
 * Parses a CHALLENGE response line.
 * @param line Input response line.
 * @param nonce Output nonce token.
 * @param bits Output difficulty bits.
 * @return 1 on success, 0 on malformed input.
 */
static int rp2p_parse_challenge(const char *line, char nonce[17],
    unsigned int *bits)
{
    const char *cursor;
    char bits_text[16];
    unsigned long value;
    char *end;

    if (!line || !bits || strncmp(line, RP2P_CTRTOK_CHALLENGE,
        strlen(RP2P_CTRTOK_CHALLENGE)) != 0)
        return 0;
    cursor = line + strlen(RP2P_CTRTOK_CHALLENGE);
    if (!rp2p_parse_field(&cursor, nonce, 17, ':')) return 0;
    if (!rp2p_parse_field(&cursor, bits_text, sizeof(bits_text), '\0'))
        return 0;
    if (*cursor != '\0') return 0;
    if (!rp2p_is_hex_token(nonce, 16)) return 0;
    if (bits_text[0] == '-' || bits_text[0] == '+') return 0;
    value = strtoul(bits_text, &end, 10);
    if (*end != '\0' || value > 32) return 0;
    *bits = (unsigned int)value;
    return 1;
}

/**
 * Parses an OK registration response line.
 * @param line Input response line.
 * @param key  Output registration key.
 * @return 1 on success, 0 on malformed input.
 */
static int rp2p_parse_ok_key(const char *line, char key[RP2P_KEY_STR_SZ]) {
    const char *cursor;

    if (!line || strncmp(line, RP2P_CTRTOK_OK_KEY,
        strlen(RP2P_CTRTOK_OK_KEY)) != 0)
        return 0;
    cursor = line + strlen(RP2P_CTRTOK_OK_KEY);
    if (!rp2p_parse_field(&cursor, key, RP2P_KEY_STR_SZ, '\0'))
        return 0;
    if (*cursor != '\0') return 0;
    return rp2p_is_hex_token(key, strlen(key));
}

/**
 * Parses a UDP punch packet.
 * @param text     Input packet text.
 * @param prefix   Required packet prefix.
 * @param sess_id  Output session id.
 * @param from_id  Output source id.
 * @param to_id    Output destination id.
 * @return 1 on success, 0 on malformed input.
 */
static int rp2p_parse_punch_packet(const char *text, const char *prefix,
    char sess_id[RP2P_CTRL_SESSION_MAX + 1],
    char from_id[RP2P_ID_MAX + 1], char to_id[RP2P_ID_MAX + 1])
{
    const char *cursor;
    size_t prefix_len;

    if (!text || !prefix) return 0;
    prefix_len = strlen(prefix);
    if (strncmp(text, prefix, prefix_len) != 0) return 0;
    cursor = text + prefix_len;
    if (!rp2p_parse_field(&cursor, sess_id, RP2P_CTRL_SESSION_MAX + 1,
        ':'))
        return 0;
    if (!rp2p_parse_field(&cursor, from_id, RP2P_ID_MAX + 1, ':'))
        return 0;
    if (!rp2p_parse_field(&cursor, to_id, RP2P_ID_MAX + 1, '\0'))
        return 0;
    if (*cursor != '\0') return 0;
    while (to_id[0]) {
        size_t len = strlen(to_id);
        if (to_id[len - 1] != '\n' && to_id[len - 1] != '\r') break;
        to_id[len - 1] = '\0';
    }
    return rp2p_is_session_token(sess_id) && rp2p_is_punch_id(from_id) &&
        rp2p_is_punch_id(to_id);
}

#define RP2P_STUN_ATTR_DATA 0x0013

/**
 * STUN put16.
 * @return None.
 */
static void rp2p_stun_put16(unsigned char *b, int o, int v) {
    b[o] = (unsigned char)(v >> 8); b[o + 1] = (unsigned char)(v);
}

/**
 * STUN length.
 * @return None.
 */
static void rp2p_stun_len(unsigned char *buf, int o) {
    rp2p_stun_put16(buf, 2, o - 20);
}

/**
 * STUN gen id.
 * @return None.
 */
static int rp2p_stun_gen_id(unsigned char id[12]) {
    return rp2p_fill_random(id, 12) == 0;
}

/**
 * STUN build.
 * @return offset after header.
 */
static int rp2p_stun_build(unsigned char *buf, int mt, const unsigned char id[12]) {
    memset(buf, 0, 20);
    rp2p_stun_put16(buf, 0, mt);
    rp2p_stun_put16(buf, 4, 0x2112); buf[6] = 0xA4; buf[7] = 0x42;
    memcpy(buf + 8, id, 12);
    return 20;
}

/**
 * STUN hdr.
 * @return message type, or -1 on error.
 */
static int rp2p_stun_hdr(const unsigned char *buf, int len, unsigned char id[12]) {
    if (len < 20) return -1;
    uint32_t mg = ((uint32_t)buf[4] << 24) | ((uint32_t)buf[5] << 16) |
        ((uint32_t)buf[6] << 8) | buf[7];
    if (mg != RP2P_STUN_MAGIC) return -1;
    int msg_len = (buf[2] << 8) | buf[3];
    if (msg_len & 3) return -1;
    if (20 + msg_len > len) return -1;
    int mt = (buf[0] << 8) | buf[1];
    memcpy(id, buf + 8, 12);
    return mt;
}

/**
 * STUN find attr.
 * @return offset of attr, or -1.
 */
static int rp2p_stun_find(const unsigned char *buf, int len, int t, int *al) {
    int o = 20;
    while (o + 4 <= len) {
        int at = (buf[o] << 8) | buf[o + 1];
        int av = (buf[o + 2] << 8) | buf[o + 3];
        int pad = (av & 3) ? 4 - (av & 3) : 0;
        if (o + 4 + av > len) return -1;
        if (at == t) { if (al) *al = av; return o + 4; }
        o += 4 + av + pad;
    }
    return -1;
}

/**
 * STUN rd xaddr.
 * @return 0 on success, -1 on error.
 */
static int rp2p_stun_rd_xaddr(const unsigned char *buf, int o, int al,
    unsigned char id[12], char *addr, int acap, unsigned short *port)
{
    (void)id;
    if (al < 8) return -1;
    if (buf[o + 1] != 1) return -1;
    unsigned short xp = ((unsigned short)buf[o + 2] << 8) | buf[o + 3];
    uint32_t xa = ((uint32_t)buf[o + 4] << 24) | ((uint32_t)buf[o + 5] << 16) |
        ((uint32_t)buf[o + 6] << 8) | buf[o + 7];
    *port = xp ^ (unsigned short)(RP2P_STUN_MAGIC >> 16);
    uint32_t a = xa ^ RP2P_STUN_MAGIC;
    snprintf(addr, (size_t)acap, "%u.%u.%u.%u",
        (unsigned)(a >> 24) & 0xff, (unsigned)(a >> 16) & 0xff,
        (unsigned)(a >> 8) & 0xff, (unsigned)(a & 0xff));
    return 0;
}

/**
 * STUN binding.
 * Summary: Sends Binding Request and returns srflx ip:port for udp_fd.
 * @param ctx      RP2P context.
 * @param udp_fd   Bound UDP socket.
 * @param out_ip   Output address buffer.
 * @param out_cap  Output address buffer size.
 * @param out_port Output port.
 * @return 0 on success, -1 on error.
 */
static int rp2p_stun_binding(rp2p_t *ctx, int udp_fd,
    char *out_ip, int out_cap, unsigned short *out_port)
{
    unsigned char tx[4096], rx[4096], tx_id[12], rx_id[12];
    char host[256];
    unsigned short port;
    struct sockaddr_storage srv;
    socklen_t srv_len;
    fd_set rfds;
    struct timeval tv;
    int off, rl, n, mt, ao, al;
    size_t sl;

    if (!ctx || !ctx->stun_url[0] || !out_ip || out_cap <= 0 || !out_port)
        return -1;

    const char *p = ctx->stun_url;
    const char *co;
    char *endptr;
    long lport;

    if (strncmp(p, "stun:", 5) != 0) return -1;
    p += 5;

    co = strchr(p, ':');
    if (!co || co == p) return -1;

    sl = (size_t)(co - p);
    if (sl >= sizeof(host)) return -1;
    memcpy(host, p, sl);
    host[sl] = '\0';

    if (*(co + 1) == '\0') return -1;
    lport = strtol(co + 1, &endptr, 10);
    if (*endptr != '\0' || lport <= 0 || lport > 65535) return -1;
    port = (unsigned short)lport;

    if (rp2p_resolve(host, port, SOCK_DGRAM, &srv, &srv_len) != 0) return -1;
    if (srv.ss_family != AF_INET) return -1;

    if (!rp2p_stun_gen_id(tx_id)) return -1;
    off = rp2p_stun_build(tx, RP2P_STUN_BINDING, tx_id);
    rp2p_stun_len(tx, off);

    if (sendto(udp_fd, (const char *)tx, (size_t)off, 0,
        (const struct sockaddr *)&srv, srv_len) < 0) return -1;

    FD_ZERO(&rfds); rp2p_fdset_add(udp_fd, &rfds, NULL);
    tv.tv_sec = 3; tv.tv_usec = 0;
    n = select(udp_fd + 1, &rfds, NULL, NULL, &tv);
    if (n <= 0) return -1;
    rl = (int)recvfrom(udp_fd, (char *)rx, sizeof(rx), 0, NULL, NULL);
    if (rl < 20) return -1;

    mt = rp2p_stun_hdr(rx, rl, rx_id);
    if (mt != RP2P_STUN_BINDING_RESP) return -1;
    if (memcmp(tx_id, rx_id, sizeof(tx_id)) != 0) return -1;

    ao = rp2p_stun_find(rx, rl, RP2P_STUN_ATTR_XOR_MAPPED_ADDR, &al);
    if (ao < 0) return -1;
    if (rp2p_stun_rd_xaddr(rx, ao, al, tx_id, out_ip, out_cap, out_port) != 0)
        return -1;
    return 0;
}

/**
 * Set stun url.
 * @return 0 on success, -1 on error.
 */
int rp2p_set_stun_url(rp2p_t *ctx, const char *url) {
    if (!ctx) return RP2P_ERROR;
    if (url) {
        strncpy(ctx->stun_url, url, sizeof(ctx->stun_url) - 1);
        ctx->stun_url[sizeof(ctx->stun_url) - 1] = '\0';
    } else {
        ctx->stun_url[0] = '\0';
    }
    return RP2P_OK;
}

/**
 * Gather candidates.
 * Summary: Gathers candidates for hole punching.
 * @param udp_fd     UDP socket fd.
 * @param index_host Index hostname.
 * @param index_port Index port.
 * @param out        Output array.
 * @param out_cap    Array capacity.
 * @param out_count  Output count.
 * @return 0 on success, -1 on error.
 */
int rp2p_gather_candidates(rp2p_t *ctx, int udp_fd,
    rp2p_candidate_t *out, int out_cap, int *out_count) {
    struct sockaddr_storage udp_sa;
    char stun_ip[RP2P_ADDR_MAX + 1];
    unsigned short stun_port;
    socklen_t udp_sa_len = sizeof(udp_sa);

    stun_ip[0] = '\0';
    stun_port = 0;
    *out_count = 0;
    if (getsockname(udp_fd, (struct sockaddr *)&udp_sa, &udp_sa_len) == 0) {
        unsigned short udp_port = rp2p_sockaddr_port(&udp_sa);
        if (*out_count < out_cap) {
            out[*out_count].type = RP2P_CAND_HOST;
            if (udp_sa.ss_family == AF_INET6)
                strcpy(out[*out_count].addr, "::1");
            else
                strcpy(out[*out_count].addr, "127.0.0.1");
            out[*out_count].port = udp_port;
            out[*out_count].priority = rp2p_candidate_priority(&out[*out_count]);
            (*out_count)++;
        }
        
        rp2p_fd_t test_fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (!RP2P_ISERR(test_fd)) {
            struct sockaddr_in target;
            memset(&target, 0, sizeof(target));
            target.sin_family = AF_INET;
            target.sin_port = htons(53);
            inet_pton(AF_INET, "8.8.8.8", &target.sin_addr);
            
            if (connect(test_fd, (struct sockaddr *)&target, sizeof(target)) == 0) {
                struct sockaddr_in local_sa;
                socklen_t local_sa_len = sizeof(local_sa);
                if (getsockname(test_fd, (struct sockaddr *)&local_sa, &local_sa_len) == 0) {
                    char local_ip[64];
                    inet_ntop(AF_INET, &local_sa.sin_addr, local_ip, sizeof(local_ip));
                    
                    if (strcmp(local_ip, "127.0.0.1") != 0 && strcmp(local_ip, "0.0.0.0") != 0 && *out_count < out_cap) {
                        out[*out_count].type = RP2P_CAND_LAN;
                        strcpy(out[*out_count].addr, local_ip);
                        out[*out_count].port = udp_port;
                        out[*out_count].priority = rp2p_candidate_priority(&out[*out_count]);
                        (*out_count)++;
                    }
                }
            }
            RP2P_FD_CLOSE(test_fd);
        }

        if (ctx && ctx->stun_url[0]) {
            rp2p_stun_binding(ctx, udp_fd, stun_ip, (int)sizeof(stun_ip),
                &stun_port);
        }
        if (stun_ip[0] != '\0' && *out_count < out_cap) {
            unsigned short srflx_port = stun_port ? stun_port : udp_port;
            out[*out_count].type = RP2P_CAND_SRFLX;
            snprintf(out[*out_count].addr, sizeof(out[*out_count].addr),
                "%.47s", stun_ip);
            out[*out_count].port = srflx_port;
            out[*out_count].priority = rp2p_candidate_priority(&out[*out_count]);
            (*out_count)++;
        }
    }
    if (!rp2p_normalize_candidates(out, out_count)) return RP2P_ERROR;
    return RP2P_OK;
}

/**
 * Converts a candidate into a socket address.
 * @param candidate Candidate to convert.
 * @param out       Output socket address.
 * @return 1 on success, 0 on malformed input.
 */
static int rp2p_candidate_sockaddr(const rp2p_candidate_t *candidate,
    struct sockaddr_storage *out)
{
    struct sockaddr_in *v4;
    struct sockaddr_in6 *v6;

    if (!candidate || !out || candidate->port == 0) return 0;
    memset(out, 0, sizeof(*out));
    v4 = (struct sockaddr_in *)out;
    if (inet_pton(AF_INET, candidate->addr, &v4->sin_addr) == 1) {
        v4->sin_family = AF_INET;
        v4->sin_port = htons(candidate->port);
        return 1;
    }
    v6 = (struct sockaddr_in6 *)out;
    if (inet_pton(AF_INET6, candidate->addr, &v6->sin6_addr) == 1) {
        v6->sin6_family = AF_INET6;
        v6->sin6_port = htons(candidate->port);
        return 1;
    }
    return 0;
}

/**
 * Sends one punch packet to one candidate endpoint.
 * @param udp_fd      UDP socket fd.
 * @param candidate   Candidate endpoint.
 * @param ping_msg    Punch packet text.
 * @param unsupported Unsupported candidate counter.
 * @return 1 when a packet was sent, 0 otherwise.
 */
static int rp2p_punch_send_candidate(int udp_fd,
    const rp2p_candidate_t *candidate, const char *ping_msg,
    int *unsupported)
{
    struct sockaddr_storage cand_sa;
    socklen_t cand_len;

    if (!rp2p_candidate_sockaddr(candidate, &cand_sa)) {
        if (unsupported) (*unsupported)++;
        return 0;
    }
    cand_len = rp2p_sockaddr_len(&cand_sa);
    if (cand_len == 0) {
        if (unsupported) (*unsupported)++;
        return 0;
    }
    return sendto(udp_fd, ping_msg, strlen(ping_msg), 0,
        (struct sockaddr *)&cand_sa, cand_len) >= 0;
}

/**
 * Waits for one valid punch response within the monotonic deadline.
 * @param udp_fd       UDP socket fd.
 * @param session_id   Expected session id.
 * @param from_id      Local peer id.
 * @param to_id        Remote peer id.
 * @param wait_ms      Maximum wait for this step.
 * @param deadline_ms  Absolute monotonic deadline.
 * @param selected_addr Output selected address.
 * @param malformed    Malformed packet counter.
 * @param mismatched   Session or peer mismatch counter.
 * @return RP2P_OK on valid response, RP2P_ETIMEOUT otherwise.
 */
static int rp2p_punch_wait_response(int udp_fd, const char *session_id,
    const char *from_id, const char *to_id, int wait_ms, uint64_t deadline_ms,
    struct sockaddr_storage *selected_addr, int *malformed, int *mismatched)
{
    uint64_t now;
    int remaining_ms;
    fd_set readfds;
    struct timeval tv;

    now = rp2p_now_ms();
    if (now >= deadline_ms) return RP2P_ETIMEOUT;
    remaining_ms = (int)(deadline_ms - now);
    if (remaining_ms > wait_ms) remaining_ms = wait_ms;
    if (remaining_ms <= 0) return RP2P_ETIMEOUT;
    FD_ZERO(&readfds);
    rp2p_fdset_add(udp_fd, &readfds, NULL);
    tv.tv_sec = remaining_ms / 1000;
    tv.tv_usec = (remaining_ms % 1000) * 1000;
    if (select(udp_fd + 1, &readfds, NULL, NULL, &tv) <= 0)
        return RP2P_ETIMEOUT;
    if (FD_ISSET(udp_fd, &readfds)) {
        char recv_buf[1024];
        struct sockaddr_storage src_addr;
        socklen_t src_len = sizeof(src_addr);
        int n;

        n = recvfrom(udp_fd, recv_buf, sizeof(recv_buf) - 1, 0,
            (struct sockaddr *)&src_addr, &src_len);
        if (n > 0) {
            char rx_sess[64] = {0};
            char rx_from[RP2P_ID_MAX + 1] = {0};
            char rx_to[RP2P_ID_MAX + 1] = {0};
            int is_ping;
            int is_pong;

            recv_buf[n] = '\0';
            is_pong = rp2p_parse_punch_packet(recv_buf,
                RP2P_CTRTOK_PUNCH_PONG,
                rx_sess, rx_from, rx_to);
            is_ping = 0;
            if (!is_pong) {
                is_ping = rp2p_parse_punch_packet(recv_buf,
                    RP2P_CTRTOK_PUNCH_PING, rx_sess, rx_from, rx_to);
            }
            if (!is_ping && !is_pong) {
                if (malformed) (*malformed)++;
                return RP2P_ETIMEOUT;
            }
            if (((is_ping && strcmp(rx_from, to_id) == 0 &&
                strcmp(rx_to, from_id) == 0) ||
                (is_pong && strcmp(rx_from, from_id) == 0 &&
                strcmp(rx_to, to_id) == 0)) &&
                strcmp(rx_sess, session_id) == 0)
            {
                *selected_addr = src_addr;
                if (is_ping) {
                    char pong_msg[256];
                    snprintf(pong_msg, sizeof(pong_msg), "%s%s:%s:%s\n",
                        RP2P_CTRTOK_PUNCH_PONG, session_id, to_id, from_id);
                    sendto(udp_fd, pong_msg, strlen(pong_msg), 0,
                        (struct sockaddr *)&src_addr, src_len);
                }
                return RP2P_OK;
            }
            if (mismatched) (*mismatched)++;
        }
    }
    return RP2P_ETIMEOUT;
}

/**
 * Punch select.
 * Summary: Selects a candidate and performs hole punching.
 * @param ctx                   Context.
 * @param udp_fd                 UDP socket fd.
 * @param session_id             Session ID.
 * @param from_id                From peer ID.
 * @param to_id                  To peer ID.
 * @param remote_candidates      Remote candidate array.
 * @param remote_candidate_count Remote candidate count.
 * @param selected_addr          Selected output address.
 * @return 0 on success, -1 on error.
 */
int rp2p_punch_select(rp2p_t *ctx, int sweep_limit, int udp_fd, const char *session_id, const char *from_id, const char *to_id, const rp2p_candidate_t *remote_candidates, int remote_candidate_count, struct sockaddr_storage *selected_addr) {
    char ping_msg[256];
    uint64_t deadline_ms;
    int direct_count;
    int sent_count;
    int malformed_count;
    int mismatch_count;
    int unsupported_count;

    (void)ctx;
    if (remote_candidate_count <= 0) {
        fprintf(stderr, "rp2p: punch failed: no candidates\n");
        return RP2P_ERROR;
    }
    if (sweep_limit < 0) sweep_limit = 0;
    deadline_ms = rp2p_now_ms() + RP2P_PUNCH_TOTAL_MS;
    direct_count = 0;
    sent_count = 0;
    malformed_count = 0;
    mismatch_count = 0;
    unsupported_count = 0;
    for (int c = 0; c < remote_candidate_count; c++) {
        if (remote_candidates[c].priority < 300u) direct_count++;
    }
    snprintf(ping_msg, sizeof(ping_msg), "%s%s:%s:%s\n",
        RP2P_CTRTOK_PUNCH_PING, session_id, from_id, to_id);
    for (int i = 0; direct_count > 0 && i < RP2P_PUNCH_DIRECT_ROUNDS; i++) {
        for (int c = 0; c < remote_candidate_count; c++) {
            if (remote_candidates[c].priority >= 300u) continue;
            sent_count += rp2p_punch_send_candidate(udp_fd,
                &remote_candidates[c], ping_msg, &unsupported_count);
        }
        if (rp2p_punch_wait_response(udp_fd, session_id, from_id, to_id,
            RP2P_PUNCH_DIRECT_WAIT_MS, deadline_ms, selected_addr,
            &malformed_count, &mismatch_count) == RP2P_OK)
            return RP2P_OK;
    }
    for (int sweep = 1; sweep <= sweep_limit && rp2p_now_ms() < deadline_ms;
        sweep++)
    {
        for (int sign = -1; sign <= 1 && rp2p_now_ms() < deadline_ms;
            sign += 2)
        {
            int offset = sweep * sign;
            for (int c = 0; c < remote_candidate_count; c++) {
                struct sockaddr_storage exact_sa;
                int test_port;

                sent_count += rp2p_punch_send_candidate(udp_fd,
                    &remote_candidates[c], ping_msg, &unsupported_count);
                if (!rp2p_candidate_sockaddr(&remote_candidates[c], &exact_sa))
                    continue;
                if (exact_sa.ss_family != AF_INET) continue;
                if (remote_candidates[c].type != RP2P_CAND_SRFLX &&
                    remote_candidates[c].type != RP2P_CAND_PUBLIC)
                    continue;
                test_port = remote_candidates[c].port + offset;
                if (test_port <= 0 || test_port > 65535) continue;
                rp2p_sockaddr_set_port(&exact_sa, (unsigned short)test_port);
                if (rp2p_sendto_addr(udp_fd, ping_msg, strlen(ping_msg),
                    &exact_sa) >= 0)
                    sent_count++;
            }
            if (rp2p_punch_wait_response(udp_fd, session_id, from_id, to_id,
                RP2P_PUNCH_SWEEP_WAIT_MS, deadline_ms, selected_addr,
                &malformed_count, &mismatch_count) == RP2P_OK)
                return RP2P_OK;
        }
    }
    if (sent_count == 0) {
        fprintf(stderr, "rp2p: punch failed: all candidates invalid or unsupported\n");
    } else if (malformed_count > 0) {
        fprintf(stderr, "rp2p: punch failed: malformed peer packet\n");
    } else if (mismatch_count > 0) {
        fprintf(stderr, "rp2p: punch failed: session mismatch\n");
    } else if (unsupported_count > 0) {
        fprintf(stderr, "rp2p: punch failed: address family mismatch\n");
    } else if (rp2p_now_ms() >= deadline_ms) {
        fprintf(stderr, "rp2p: punch failed: timeout\n");
    } else {
        fprintf(stderr, "rp2p: punch failed: all attempts exhausted\n");
    }
    return RP2P_ERROR;
}

/**
 * Serve index.
 * Summary: Serve the index server.
 * @param ctx Context.
 * @param host Host.
 * @param port Port.
 * @return 0 on success, -1 on error.
 */
int rp2p_serve_index(
    rp2p_t *ctx,
    const char *host,
    unsigned short port)
{
    rp2p_fd_t tcp_fd;
    struct addrinfo hints;
    struct addrinfo *ai;
    struct addrinfo *it;
    char port_str[16];
    fd_set fds;
    struct timeval tv;
    int ret, i, n;
    int maxfd = -1;

    if (!ctx) return RP2P_ERROR;
    ctx->stop_requested = 0;
    if (rp2p_platform_init() != 0) {
        rp2p_set_error(ctx, "index: platform init failed");
        return RP2P_ENET;
    }

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = host ? AF_UNSPEC : AF_INET6;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    snprintf(port_str, sizeof(port_str), "%u", (unsigned)port);
    ret = getaddrinfo(host, port_str, &hints, &ai);
    if (ret != 0 && !host) {
        hints.ai_family = AF_INET;
        ret = getaddrinfo(host, port_str, &hints, &ai);
    }
    if (ret != 0) {
        rp2p_set_error(ctx, "index: resolve %s:%u failed (%s)",
            host ? host : "*", (unsigned)port, gai_strerror(ret));
        rp2p_platform_cleanup();
        return RP2P_ENET;
    }
    tcp_fd = RP2P_FD_INVALID;
    for (it = ai; it; it = it->ai_next) {
        tcp_fd = socket(it->ai_family, it->ai_socktype, it->ai_protocol);
        if (RP2P_ISERR(tcp_fd)) continue;
        { int reuse = 1; setsockopt(tcp_fd, SOL_SOCKET, SO_REUSEADDR, (void *)&reuse, sizeof(reuse)); }
#ifdef IPV6_V6ONLY
        if (it->ai_family == AF_INET6) {
            int v6only = 0;
            setsockopt(tcp_fd, IPPROTO_IPV6, IPV6_V6ONLY,
                (void *)&v6only, sizeof(v6only));
        }
#endif
        if (bind(tcp_fd, it->ai_addr, (socklen_t)it->ai_addrlen) == 0 &&
            listen(tcp_fd, 32) == 0)
            break;
        RP2P_FD_CLOSE(tcp_fd);
        tcp_fd = RP2P_FD_INVALID;
    }
    freeaddrinfo(ai);
    if (RP2P_ISERR(tcp_fd)) {
        rp2p_set_error(ctx, "index: bind/listen %s:%u failed",
            host ? host : "*", (unsigned)port);
        rp2p_platform_cleanup();
        return RP2P_ENET;
    }

    rp2p_set_nonblock(tcp_fd);

    fprintf(stderr, "rp2p: index server listening on %s:%u\n",
        host ? host : "*", (unsigned)port);

    while (1) {
        rp2p_dispatch_pending_signals();
        if (ctx->stop_requested) { fprintf(stderr, "rp2p: shutdown requested\n"); break; }

        FD_ZERO(&fds);
        rp2p_fdset_add(tcp_fd, &fds, &maxfd);

        rp2p_lock(ctx);
        for (i = 0; i < ctx->n_conns; i++) {
            rp2p_fdset_add(ctx->conns[i].fd, &fds, &maxfd);
        }
        rp2p_evict_pow_challenges(ctx, rp2p_now_s());
        rp2p_unlock(ctx);

        tv.tv_sec = 1; tv.tv_usec = 0;
        n = select(maxfd + 1, &fds, NULL, NULL, &tv);
        if (n < 0) { if (ctx->stop_requested) break; continue; }
        if (n == 0) continue;

        if (FD_ISSET(tcp_fd, &fds)) {
            struct sockaddr_storage client_addr;
            socklen_t client_len = sizeof(client_addr);
            rp2p_fd_t client_fd = accept(tcp_fd, (struct sockaddr *)&client_addr, &client_len);
            if (!RP2P_ISERR(client_fd)) {
                rp2p_set_nonblock(client_fd);
                rp2p_lock(ctx);
                rp2p_conn_add(ctx, client_fd);
                rp2p_unlock(ctx);
            }
        }

        rp2p_lock(ctx);
        for (i = ctx->n_conns - 1; i >= 0; i--) {
            if (!FD_ISSET(ctx->conns[i].fd, &fds)) continue;

            {
                rp2p_tcp_conn_t *c = &ctx->conns[i];
                char tmp[RP2P_BUF];
                int nr;

                nr = rp2p_sock_read(c->fd, tmp, (int)sizeof(tmp) - 1);
                if (nr <= 0) {
                    int cidx;
                    struct sockaddr_storage dead_peer_sa;
                    socklen_t dead_peer_len;

                    memset(&dead_peer_sa, 0, sizeof(dead_peer_sa));
                    dead_peer_len = sizeof(dead_peer_sa);
                    if (getpeername(c->fd, (struct sockaddr *)&dead_peer_sa,
                        &dead_peer_len) == 0)
                    {
                        cidx = rp2p_find_pow_challenge(ctx, &dead_peer_sa);
                    } else {
                        cidx = -1;
                    }
                    if (cidx >= 0)
                        rp2p_remove_pow_challenge(ctx, cidx);
                    if (c->registered) {
                        rp2p_remove_peer(ctx, c->id);
                        fprintf(stderr, "rp2p: peer '%s' disconnected\n", c->id);
                    }
                    rp2p_conn_remove(ctx, i);
                    continue;
                }

                tmp[nr] = '\0';

                {   int copy = nr;
                    if (c->buf_len + copy > (int)sizeof(c->buf) - 1) {
                        rp2p_conn_remove(ctx, i);
                        continue;
                    }
                    if (copy > 0) {
                        memcpy(c->buf + c->buf_len, tmp, copy);
                        c->buf_len += copy;
                    }
                    if (c->buf_len >= RP2P_CTRL_LINE_MAX &&
                        !memchr(c->buf, '\n', (size_t)c->buf_len))
                    {
                        rp2p_conn_remove(ctx, i);
                        continue;
                    }
                }

                {
                    char *line_start = c->buf;
                    char *newline;
                    int fatal_frame = 0;

                    while ((newline = (char *)memchr(line_start, '\n',
                        (size_t)(c->buf + c->buf_len - line_start))) != NULL)
                    {
                        char *line_base = line_start;
                        int line_len = (int)(newline - line_start);
                        char cmd_buf[RP2P_BUF];
                        char cmd[32];
                        char id[RP2P_ID_MAX + 1];
                        char reply_buf[RP2P_BUF];
                        int srv_idx;

                        if (line_len <= 0) {
                            line_start += line_len + 1;
                            continue;
                        }
                        if (line_len > RP2P_CTRL_LINE_MAX ||
                            line_len > (int)sizeof(cmd_buf) - 1)
                        {
                            rp2p_conn_remove(ctx, i);
                            fatal_frame = 1;
                            break;
                        }
                        memcpy(cmd_buf, line_start, line_len);
                        cmd_buf[line_len] = '\0';
                        line_start += line_len + 1;

                        if (strcmp(cmd_buf, RP2P_CTRTOK_HELLO) == 0) {
                            if (c->hello_ok) {
                                rp2p_tcp_send(c->fd,
                                    RP2P_CTRTOK_ERROR_VERSION_MISMATCH);
                                rp2p_conn_remove(ctx, i);
                                fatal_frame = 1;
                                break;
                            }
                            c->hello_ok = 1;
                            rp2p_tcp_send(c->fd, RP2P_CTRTOK_HELLO_OK);
                            continue;
                        }
                        if (strncmp(cmd_buf, RP2P_CTRTOK_HELLO,
                            strlen(RP2P_CTRTOK_HELLO) - strlen("RP2P/1")) == 0 ||
                            !c->hello_ok)
                        {
                            rp2p_tcp_send(c->fd,
                                RP2P_CTRTOK_ERROR_VERSION_MISMATCH);
                            rp2p_conn_remove(ctx, i);
                            fatal_frame = 1;
                            break;
                        }

                        {
                            const char *colon = strchr(cmd_buf, ':');
                            size_t cmd_len = colon ? (size_t)(colon - cmd_buf) : strlen(cmd_buf);
                            if (cmd_len == 0 || cmd_len >= sizeof(cmd)) {
                                rp2p_tcp_send(c->fd,
                                    RP2P_CTRTOK_ERROR_MALFORMED);
                                continue;
                            }
                            memcpy(cmd, cmd_buf, cmd_len);
                            cmd[cmd_len] = '\0';
                        }

                        if (strcmp(cmd, RP2P_CTRCMD_REGISTER) == 0) {
                            struct sockaddr_storage peer_sa;
                            socklen_t peer_len = sizeof(peer_sa);

                            if (getpeername(c->fd, (struct sockaddr *)&peer_sa,
                                &peer_len) != 0)
                                memset(&peer_sa, 0, sizeof(peer_sa));

                            if (strstr(cmd_buf, ":" RP2P_CTRTOK_SOLUTION) == NULL &&
                                !rp2p_parse_register_id(cmd_buf, id))
                            {
                                rp2p_tcp_send(c->fd,
                                    RP2P_CTRTOK_ERROR_INVALID_ID);
                                continue;
                            }

                            if (strstr(cmd_buf, ":" RP2P_CTRTOK_SOLUTION) != NULL) {
                                char solution[17];
                                char proof[65];
                                int cidx;
                                const char *register_pass;

                                if (rp2p_parse_register_solution(cmd_buf, id,
                                    solution, proof))
                                {
                                    uint64_t now_pow = rp2p_now_s();
                                    register_pass = rp2p_get_register_pass(ctx, id);
                                    cidx = rp2p_find_pow_challenge(ctx, &peer_sa);
                                    if (cidx < 0 ||
                                        (ctx->pow_challenges[cidx].expires_at != 0 &&
                                        now_pow >=
                                            ctx->pow_challenges[cidx].expires_at) ||
                                        strcmp(ctx->pow_challenges[cidx].id, id) != 0 ||
                                        !rp2p_verify_register_pow(register_pass,
                                            ctx->pow_challenges[cidx].nonce_hex, id,
                                            solution, proof, ctx->pow_bits))
                                    {
                                        if (cidx >= 0)
                                            rp2p_remove_pow_challenge(ctx, cidx);
                                        rp2p_tcp_send(c->fd,
                                            RP2P_CTRTOK_AUTH_FAILED);
                                        continue;
                                    }
                                    rp2p_remove_pow_challenge(ctx, cidx);
                                    if (rp2p_add_peer(ctx, id) == RP2P_OK &&
                                        rp2p_format_register_ok(ctx, id,
                                            reply_buf, sizeof(reply_buf)))
                                    {
                                        rp2p_tcp_send(c->fd, reply_buf);
                                        strcpy(c->id, id);
                                        c->registered = 1;
                                    } else {
                                        rp2p_tcp_send(c->fd,
                                            RP2P_CTRTOK_ERROR_PEER_TABLE_FULL);
                                    }
                                } else {
                                    int cidx_fail =
                                        rp2p_find_pow_challenge(ctx, &peer_sa);
                                    if (cidx_fail >= 0)
                                        rp2p_remove_pow_challenge(ctx, cidx_fail);
                                    rp2p_tcp_send(c->fd,
                                        RP2P_CTRTOK_AUTH_FAILED);
                                    continue;
                                }
                            } else if (c->registered && strcmp(c->id, id) == 0) {
                                if (rp2p_refresh_peer(ctx, id) == RP2P_OK &&
                                    rp2p_format_register_ok(ctx, id,
                                        reply_buf, sizeof(reply_buf)))
                                {
                                    rp2p_tcp_send(c->fd, reply_buf);
                                } else {
                                    rp2p_tcp_send(c->fd,
                                        RP2P_CTRTOK_ERROR_NOT_REGISTERED);
                                }
                            } else if (ctx->n_pow_challenges >= RP2P_POW_CHALLENGES_MAX &&
                                rp2p_find_pow_challenge(ctx, &peer_sa) < 0)
                            {
                                rp2p_tcp_send(c->fd,
                                    RP2P_CTRTOK_ERROR_BUSY);
                            } else {
                                unsigned char nonce[8];
                                char nonce_hex[17];

                                if (rp2p_fill_random(nonce, sizeof(nonce)) != 0 ||
                                    !rp2p_hex_encode(nonce, sizeof(nonce),
                                        nonce_hex, sizeof(nonce_hex)))
                                {
                                    rp2p_tcp_send(c->fd,
                                        RP2P_CTRTOK_ERROR_RANDOM);
                                    continue;
                                }
                                snprintf(reply_buf, sizeof(reply_buf),
                                    "%s%s:%d", RP2P_CTRTOK_CHALLENGE,
                                    nonce_hex, ctx->pow_bits);
                                if (!rp2p_store_pow_challenge(ctx, &peer_sa, id,
                                    reply_buf + strlen(RP2P_CTRTOK_CHALLENGE)))
                                {
                                    rp2p_tcp_send(c->fd,
                                        RP2P_CTRTOK_ERROR_BUSY);
                                } else {
                                    rp2p_tcp_send(c->fd, reply_buf);
                                }
                            }

                        } else if (strcmp(cmd, RP2P_CTRCMD_PUNCH_REQ2) == 0) {
                            char self_id[RP2P_ID_MAX + 1] = {0};
                            char target_id[RP2P_ID_MAX + 1] = {0};
                            char sess_id[RP2P_CTRL_SESSION_MAX + 1] = {0};
                            char *block_end;

                            if (!rp2p_find_end_line(line_start,
                                c->buf + c->buf_len, &block_end))
                            {
                                line_start = line_base;
                                break;
                            }
                            if (rp2p_parse_punch_req2(cmd_buf, self_id,
                                target_id, sess_id)) {
                                int target_fd = -1;
                                for (int j = 0; j < ctx->n_conns; j++) {
                                    if (ctx->conns[j].registered && strcmp(ctx->conns[j].id, target_id) == 0) {
                                        target_fd = ctx->conns[j].fd;
                                        break;
                                    }
                                }

                                srv_idx = rp2p_find_peer(ctx, target_id);

                                if (target_fd != -1 && srv_idx >= 0) {
                                    char msg[RP2P_BUF];
                                    snprintf(msg, sizeof(msg), "%s%s:%s\n",
                                        RP2P_CTRTOK_PUNCH_CALL2, self_id,
                                        sess_id);

                                    if (!rp2p_copy_candidate_block(line_start,
                                        block_end, msg, sizeof(msg)))
                                    {
                                        rp2p_tcp_send(c->fd,
                                            RP2P_CTRTOK_ERROR_MALFORMED);
                                        line_start = block_end;
                                        continue;
                                    }
                                    line_start = block_end;
                                    rp2p_tcp_send(target_fd, msg);
                                    
                                    rp2p_pending_punch_evict_stale(ctx);
                                    if (ctx->n_pending_punches < RP2P_MAX_PENDING_PUNCHES) {
                                        rp2p_pending_punch_t *pp = &ctx->pending_punches[ctx->n_pending_punches++];
                                        snprintf(pp->self_id, sizeof(pp->self_id), "%s", self_id);
                                        snprintf(pp->target_id, sizeof(pp->target_id), "%s", target_id);
                                        snprintf(pp->sess_id, sizeof(pp->sess_id), "%s", sess_id);
                                        pp->consumer_fd = c->fd;
                                        pp->ts = rp2p_now_s();
                                    } else {
                                        rp2p_tcp_send(c->fd,
                                            RP2P_CTRTOK_ERROR_BUSY);
                                    }
                                } else {
                                    rp2p_tcp_send(c->fd,
                                        RP2P_CTRTOK_ERROR_OFFLINE);
                                    line_start = block_end;
                                }
                            } else {
                                rp2p_tcp_send(c->fd,
                                    RP2P_CTRTOK_ERROR_MALFORMED);
                                line_start = block_end;
                            }

                        } else if (strcmp(cmd, RP2P_CTRCMD_PUNCH_ACK2) == 0) {
                            char ack_self_id[RP2P_ID_MAX + 1] = {0};
                            char ack_target_id[RP2P_ID_MAX + 1] = {0};
                            char ack_sess_id[RP2P_CTRL_SESSION_MAX + 1] = {0};
                            char *block_end;

                            if (!rp2p_find_end_line(line_start,
                                c->buf + c->buf_len, &block_end))
                            {
                                line_start = line_base;
                                break;
                            }
                            if (rp2p_parse_punch_ack2(cmd_buf, ack_self_id,
                                ack_target_id, ack_sess_id)) {
                                int pp_idx = rp2p_pending_punch_find(ctx, ack_self_id, ack_target_id, ack_sess_id);
                                if (pp_idx >= 0) {
                                    char ok2[RP2P_BUF];
                                    snprintf(ok2, sizeof(ok2), "%s%s:%s\n",
                                        RP2P_CTRTOK_PUNCH_OK2, ack_self_id,
                                        ack_sess_id);
                                    if (!rp2p_copy_candidate_block(line_start,
                                        block_end, ok2, sizeof(ok2)))
                                    {
                                        rp2p_tcp_send(c->fd,
                                            RP2P_CTRTOK_ERROR_MALFORMED);
                                        line_start = block_end;
                                        continue;
                                    }
                                    rp2p_tcp_send(ctx->pending_punches[pp_idx].consumer_fd, ok2);
                                    rp2p_pending_punch_remove(ctx, pp_idx);
                                }
                                line_start = block_end;
                            } else {
                                rp2p_tcp_send(c->fd,
                                    RP2P_CTRTOK_ERROR_MALFORMED);
                                line_start = block_end;
                            }
                            
                        } else if (strcmp(cmd, RP2P_CTRCMD_DEREGISTER) == 0) {
                            char dkey[RP2P_KEY_STR_SZ];
                            if (rp2p_parse_deregister(cmd_buf, id, dkey)) {
                                srv_idx = rp2p_find_peer(ctx, id);
                                if (srv_idx >= 0 && strcmp(ctx->peers[srv_idx].key, dkey) == 0) {
                                    rp2p_remove_peer(ctx, id);
                                    rp2p_tcp_send(c->fd, RP2P_CTRTOK_OK);
                                } else {
                                    rp2p_tcp_send(c->fd,
                                        RP2P_CTRTOK_ERROR_INVALID_KEY);
                                }
                            } else {
                                rp2p_tcp_send(c->fd,
                                    RP2P_CTRTOK_ERROR_MALFORMED);
                            }

                        } else if (strcmp(cmd, RP2P_CTRCMD_LIST_PUBLISHERS) == 0) {
                            if (strcmp(cmd_buf, RP2P_CTRTOK_LIST_PUBLISHERS) != 0) {
                                rp2p_tcp_send(c->fd,
                                    RP2P_CTRTOK_ERROR_MALFORMED);
                                continue;
                            }
                            rp2p_evict_stale(ctx);
                            for (srv_idx = 0; srv_idx < ctx->n_peers; srv_idx++) {
                                snprintf(reply_buf, sizeof(reply_buf), "%s%s",
                                    RP2P_CTRTOK_PUBLISHER,
                                    ctx->peers[srv_idx].id);
                                rp2p_tcp_send(c->fd, reply_buf);
                            }
                            rp2p_tcp_send(c->fd, RP2P_CTRTOK_END);

                        } else if (strcmp(cmd, RP2P_CTRCMD_LOOKUP) == 0) {
                            if (rp2p_parse_lookup(cmd_buf, id)) {
                                srv_idx = rp2p_find_peer(ctx, id);
                                if (srv_idx >= 0) {
                                    snprintf(reply_buf, sizeof(reply_buf), "%s%s",
                                        RP2P_CTRTOK_PUBLISHER,
                                        ctx->peers[srv_idx].id);
                                    rp2p_tcp_send(c->fd, reply_buf);
                                } else {
                                    rp2p_tcp_send(c->fd,
                                        RP2P_CTRTOK_NOT_FOUND);
                                }
                            } else {
                                rp2p_tcp_send(c->fd,
                                    RP2P_CTRTOK_ERROR_MALFORMED);
                            }
                        } else {
                            rp2p_tcp_send(c->fd,
                                RP2P_CTRTOK_ERROR_UNKNOWN_COMMAND);
                        }

                        if (line_start >= c->buf + c->buf_len) break;
                    }

                    if (fatal_frame) continue;
                    if (line_start > c->buf) {
                        int remaining = (int)(c->buf + c->buf_len - line_start);
                        if (remaining > 0)
                            memmove(c->buf, line_start, remaining);
                        c->buf_len = remaining;
                    }
                }
            }
        }
        rp2p_unlock(ctx);
    }

    RP2P_FD_CLOSE(tcp_fd);
    rp2p_platform_cleanup();
    return RP2P_OK;
}

/**
 * Save key.
 * @return Status code.
 */
static void rp2p_save_key(const char *id, const char *key);

/**
 * Load key.
 * @return Status code.
 */
static void rp2p_load_key(const char *id, char *key, size_t cap);

/**
 * Mkdir p.
 * @return Status code.
 */
static void rp2p_mkdir_p(char *path) {
    char *p;
#ifdef _WIN32
    for (p = path + 1; *p; p++) {
        if (*p == '/' || *p == '\\') { *p = '\0'; _mkdir(path); *p = '/'; }
    }
    _mkdir(path);
#else
    for (p = path + 1; *p; p++) {
        if (*p == '/') { *p = '\0'; mkdir(path, 0755); *p = '/'; }
    }
    mkdir(path, 0755);
#endif
}

/**
 * Save key.
 * @return Status code.
 */
static void rp2p_save_key(const char *id, const char *key) {
    const char *home;
    char dir[512];
    char path[576];
    FILE *f;

    home = getenv("HOME");
    if (!home) return;

    snprintf(dir, sizeof(dir), "%s/.local/share/rp2p/keys", home);
    rp2p_mkdir_p(dir);

#ifndef _WIN32
    chmod(dir, 0700);
#endif

    snprintf(path, sizeof(path), "%s/%s", dir, id);
    f = fopen(path, "w");
    if (f) {
        fprintf(f, "%s\n", key);
        fclose(f);
    }
}

/**
 * Load key.
 * @return Status code.
 */
static void rp2p_load_key(const char *id, char *key, size_t cap) {
    const char *home;
    char path[576];
    FILE *f;
    home = getenv("HOME");
    if (!home) return;
    snprintf(path, sizeof(path), "%s/.local/share/rp2p/keys/%s", home, id);
    f = fopen(path, "r");
    if (f) {
        if (fgets(key, (int)cap, f)) {
            size_t len = strlen(key);
            if (len > 0 && key[len - 1] == '\n') key[len - 1] = '\0';
        }
        fclose(f);
    }
}

/**
 * Deregister.
 * @return 0 on success, -1 on error.
 */
int rp2p_deregister(
    rp2p_t *ctx,
    const char *index_host,
    unsigned short index_port,
    const char *id)
{
    char key[RP2P_KEY_STR_SZ] = "";
    char cmd[RP2P_BUF];
    char reply[RP2P_BUF];

    (void)ctx;
    rp2p_load_key(id, key, sizeof(key));
    if (key[0] == '\0') return RP2P_ENOENT;

    snprintf(cmd, sizeof(cmd), "%s%s:%s%s", RP2P_CTRTOK_DEREGISTER,
        id, RP2P_CTRTOK_KEY, key);
    {
    rp2p_fd_t fd = rp2p_control_connect(index_host, index_port);
        if (RP2P_ISERR(fd)) return RP2P_ENET;
        if (rp2p_tcp_send(fd, cmd) != RP2P_OK) { RP2P_FD_CLOSE(fd); return RP2P_ENET; }
        if (rp2p_tcp_readline(fd, reply, (int)sizeof(reply), 5) < 0) { RP2P_FD_CLOSE(fd); return RP2P_ETIMEOUT; }
        RP2P_FD_CLOSE(fd);
    }

    if (strcmp(reply, RP2P_CTRTOK_OK) != 0) return RP2P_ERROR;
    return RP2P_OK;
}

/**
 * List publishers.
 * @return 0 on success, negative error code on failure.
 */
int rp2p_list_publishers(
    rp2p_t *ctx,
    const char *index_host,
    unsigned short index_port,
    rp2p_publisher_cb cb,
    void *userdata)
{
    rp2p_fd_t fd;
    char line[RP2P_BUF];
    size_t prefix_len;

    if (!ctx || !index_host || !index_host[0] || !cb) return RP2P_ERROR;
    fd = rp2p_control_connect(index_host, index_port);
    if (RP2P_ISERR(fd)) return RP2P_ENET;
    if (rp2p_tcp_send(fd, RP2P_CTRTOK_LIST_PUBLISHERS) != RP2P_OK) {
        RP2P_FD_CLOSE(fd);
        return RP2P_ENET;
    }
    prefix_len = strlen(RP2P_CTRTOK_PUBLISHER);
    for (;;) {
        if (rp2p_tcp_readline(fd, line, (int)sizeof(line),
            RP2P_ETIMEOUT_SEC) < 0)
        {
            RP2P_FD_CLOSE(fd);
            return RP2P_ETIMEOUT;
        }
        if (strcmp(line, RP2P_CTRTOK_END) == 0) {
            RP2P_FD_CLOSE(fd);
            return RP2P_OK;
        }
        if (strncmp(line, RP2P_CTRTOK_PUBLISHER, prefix_len) == 0) {
            const char *id = line + prefix_len;
            if (!rp2p_is_valid_id(id)) {
                RP2P_FD_CLOSE(fd);
                return RP2P_ERROR;
            }
            cb(id, userdata);
            continue;
        }
        RP2P_FD_CLOSE(fd);
        return RP2P_ERROR;
    }
}

/**
 * Wait.
 * @return 0 on success, -1 on error.
 */
int rp2p_wait(
    rp2p_t *ctx,
    const char *index_host,
    unsigned short index_port,
    const char *self_id,
    unsigned short bind_port)
{
    rp2p_fd_t control_fd;
    char send_buf[RP2P_BUF];
    char recv_buf[RP2P_BUF];
    rp2p_fd_t udp_fd = RP2P_FD_INVALID;
    uint64_t last_heartbeat;
    const char *udp_any_host;
    unsigned short eff_port;

    if (!ctx) return RP2P_ERROR;
    ctx->stop_requested = 0;
    if (ctx->proto != RP2P_PROTO_TCP && ctx->proto != RP2P_PROTO_UDP)
        return RP2P_ERROR;
    if (rp2p_resolve_port(ctx, bind_port, &eff_port) != RP2P_OK)
        return RP2P_ERROR;
    if (eff_port == 0) return RP2P_ERROR;
    ctx->bind_port = eff_port;
    udp_any_host = rp2p_host_is_ipv6_literal(index_host) ? "::" : "0.0.0.0";

    control_fd = rp2p_control_connect(index_host, index_port);
    if (RP2P_ISERR(control_fd)) {
        rp2p_set_error(ctx, "wait: control connect %s:%u failed",
            index_host, (unsigned)index_port);
        return RP2P_ENET;
    }

    udp_fd = rp2p_create_socket(udp_any_host, 0);
    if (RP2P_ISERR(udp_fd)) { RP2P_FD_CLOSE(control_fd); return RP2P_ENET; }

    snprintf(send_buf, sizeof(send_buf), "%s%s", RP2P_CTRTOK_REGISTER,
        self_id);
    if (rp2p_tcp_send(control_fd, send_buf) != RP2P_OK ||
        rp2p_tcp_readline(control_fd, recv_buf, (int)sizeof(recv_buf), 10) < 0)
    {
        RP2P_FD_CLOSE(control_fd);
        if (!RP2P_ISERR(udp_fd)) RP2P_FD_CLOSE(udp_fd);
        return RP2P_ENET;
    }

    if (strncmp(recv_buf, RP2P_CTRTOK_CHALLENGE,
        strlen(RP2P_CTRTOK_CHALLENGE)) == 0) {
        char nonce[17];
        char solution[17];
        char proof[65];
        unsigned int chall_bits;

        if (!rp2p_parse_challenge(recv_buf, nonce, &chall_bits)) {
            RP2P_FD_CLOSE(control_fd);
            if (!RP2P_ISERR(udp_fd)) RP2P_FD_CLOSE(udp_fd);
            return RP2P_ERROR;
        }
        fprintf(stderr, "rp2p: connecting...\n");
        if (!rp2p_solve_register_pow(ctx, ctx->pass, nonce, self_id,
            (int)chall_bits, solution, sizeof(solution), proof, sizeof(proof)))
        {
            RP2P_FD_CLOSE(control_fd);
            if (!RP2P_ISERR(udp_fd)) RP2P_FD_CLOSE(udp_fd);
            return RP2P_ERROR;
        }
        snprintf(send_buf, sizeof(send_buf), "%s%s:%s%s:%s%s",
            RP2P_CTRTOK_REGISTER, self_id, RP2P_CTRTOK_SOLUTION,
            solution, RP2P_CTRTOK_PROOF, proof);
        if (rp2p_tcp_send(control_fd, send_buf) != RP2P_OK ||
            rp2p_tcp_readline(control_fd, recv_buf, (int)sizeof(recv_buf), 10) < 0)
        {
            RP2P_FD_CLOSE(control_fd);
            if (!RP2P_ISERR(udp_fd)) RP2P_FD_CLOSE(udp_fd);
            return RP2P_ENET;
        }
    } else {
        RP2P_FD_CLOSE(control_fd);
        if (!RP2P_ISERR(udp_fd)) RP2P_FD_CLOSE(udp_fd);
        return RP2P_ERROR;
    }

    {
        char obs_key[RP2P_KEY_STR_SZ];
        if (!rp2p_parse_ok_key(recv_buf, obs_key)) {
            fprintf(stderr, "rp2p: registration failed: %s\n", recv_buf);
            RP2P_FD_CLOSE(control_fd);
            if (!RP2P_ISERR(udp_fd)) RP2P_FD_CLOSE(udp_fd);
            return RP2P_ERROR;
        }
        memcpy(ctx->key, obs_key, RP2P_KEY_STR_SZ);
        ctx->key[RP2P_KEY_STR_SZ - 1] = '\0';
        rp2p_save_key(self_id, ctx->key);
    }

    fprintf(stderr, "rp2p: published %s backend 127.0.0.1:%u as '%s'\n",
        ctx->proto == RP2P_PROTO_TCP ? "tcp" : "udp",
        (unsigned)ctx->bind_port, self_id);

    {
        rp2p_udp_server_session_t *sessions;
        int n_sessions;
        int cap_sessions;
        int n, i;

        sessions = NULL;
        n_sessions = 0;
        cap_sessions = 0;
        last_heartbeat = rp2p_now_s();

        rp2p_set_nonblock(control_fd);
        rp2p_set_nonblock(udp_fd);

        while (!ctx->stop_requested) {
            fd_set fds;
            struct timeval tv;
            rp2p_dispatch_pending_signals();
    int maxfd = -1;

            FD_ZERO(&fds);
            rp2p_fdset_add(control_fd, &fds, &maxfd);
            rp2p_fdset_add(udp_fd, &fds, &maxfd);

            for (i = 0; i < n_sessions; i++) {
                if (!sessions[i].active) continue;
                if (sessions[i].backend_fd != RP2P_FD_INVALID) {
                    if (sessions[i].is_tcp &&
                        !rp2p_stream_can_send_data(&sessions[i].stream) &&
                        !sessions[i].stream.out.local_eof)
                        continue;
                    rp2p_fdset_add(sessions[i].backend_fd, &fds, &maxfd);
                }
            }

            tv.tv_sec = 1; tv.tv_usec = 0;
            n = select(maxfd + 1, &fds, NULL, NULL, &tv);
            if (n < 0) continue;
            if (ctx->stop_requested) break;

            if (rp2p_now_s() - last_heartbeat >= RP2P_HEARTBEAT_S) {
                snprintf(send_buf, sizeof(send_buf), "%s%s",
                    RP2P_CTRTOK_REGISTER, self_id);
                rp2p_tcp_send(control_fd, send_buf);
                last_heartbeat = rp2p_now_s();
            }

            if (FD_ISSET(control_fd, &fds)) {
                if (rp2p_tcp_readline(control_fd, recv_buf,
                    (int)sizeof(recv_buf), 0) > 0)
                {
                    char conn_id[RP2P_ID_MAX + 1];
                    char remote_token[RP2P_CTRL_SESSION_MAX + 1];
                    char sess_hex[RP2P_STREAM_SESSION_ID_SZ * 2 + 1];
                    unsigned char sess_id[RP2P_STREAM_SESSION_ID_SZ];

                    memset(sess_hex, 0, sizeof(sess_hex));

                    if (rp2p_parse_punch_call2(recv_buf, conn_id,
                        remote_token))
                    {
                        if (ctx->proto == RP2P_PROTO_TCP) {
                            memcpy(sess_hex, remote_token,
                                RP2P_STREAM_SESSION_ID_SZ * 2);
                            sess_hex[RP2P_STREAM_SESSION_ID_SZ * 2] = '\0';
                            if (!rp2p_hex_decode(sess_hex, sess_id, sizeof(sess_id)))
                                continue;
                        }

                        {
                            char lbuf[128];
                            int saw_end = 0;
                            while (rp2p_tcp_readline(control_fd, lbuf, sizeof(lbuf), 5) > 0) {
                                if (!rp2p_append_text(recv_buf,
                                    sizeof(recv_buf), "\n") ||
                                    !rp2p_append_text(recv_buf,
                                        sizeof(recv_buf), lbuf))
                                    break;
                                if (strcmp(lbuf, RP2P_CTRTOK_END) == 0) {
                                    saw_end = 1;
                                    break;
                                }
                            }
                            if (saw_end && !rp2p_append_text(recv_buf,
                                sizeof(recv_buf), "\n"))
                                continue;
                            if (!saw_end) continue;
                        }
                        rp2p_candidate_t remote_cands[RP2P_CANDIDATES_MAX];
                        int remote_cand_count = 0;
                        if (!rp2p_parse_remote_candidates(recv_buf,
                            remote_cands, &remote_cand_count))
                            continue;
                        rp2p_candidate_t my_cands[RP2P_CANDIDATES_MAX];
                        int my_cand_count = 0;
                        char ack_buf[RP2P_BUF];
                        const char *ack_sess = sess_hex[0] ? sess_hex : remote_token;

                        rp2p_gather_candidates(ctx, udp_fd, my_cands,
                            RP2P_CANDIDATES_MAX, &my_cand_count);
                        snprintf(ack_buf, sizeof(ack_buf), "%s%s:%s:%s\n",
                            RP2P_CTRTOK_PUNCH_ACK2, self_id, conn_id,
                            ack_sess);
                        for (int ci = 0; ci < my_cand_count; ci++) {
                            if (!rp2p_append_candidate(ack_buf,
                                sizeof(ack_buf), &my_cands[ci]))
                                continue;
                        }
                        if (!rp2p_append_text(ack_buf, sizeof(ack_buf),
                            RP2P_CTRTOK_END "\n"))
                            continue;
                        rp2p_tcp_send(control_fd, ack_buf);
                        
                        struct sockaddr_storage peer;
                        memset(&peer, 0, sizeof(peer));
                        if (rp2p_punch_select(ctx, ctx->sweep, udp_fd, ack_sess,
                            self_id, conn_id, remote_cands, remote_cand_count,
                            &peer) != RP2P_OK)
                            continue;

                        int found = -1;
                        for (i = 0; i < n_sessions; i++) {
                            if (!sessions[i].active) continue;
                            if (rp2p_sockaddr_equal(&sessions[i].peer_addr,
                                &peer)) {
                                found = i; break;
                            }
                        }

                        if (found < 0) {
                            rp2p_udp_server_session_t sess;
                            memset(&sess, 0, sizeof(sess));
                            sess.peer_addr = peer;
                            sess.last_rx = rp2p_now_s();
                            sess.last_ka = sess.last_rx;
                            sess.is_tcp = (ctx->proto == RP2P_PROTO_TCP) ? 1 : 0;
                            sess.tcp_fd = RP2P_FD_INVALID;

                            if (sess.is_tcp) {
                                sess.backend_fd = rp2p_connect_local_tcp(ctx->bind_port);
                                if (RP2P_ISERR(sess.backend_fd)) {
                                    fprintf(stderr, "rp2p: local backend connect failed on 127.0.0.1:%u\n",
                                        (unsigned)ctx->bind_port);
                                    continue;
                                }
                                rp2p_stream_init(&sess.stream, 0, sess_id,
                                    sess_hex, ctx->secret);
                                if (!rp2p_stream_crypto_init(&sess.stream)) {
                                    RP2P_FD_CLOSE(sess.backend_fd);
                                    continue;
                                }
                            } else {
                                sess.backend_fd = rp2p_create_socket(udp_any_host, 0);
                                if (RP2P_ISERR(sess.backend_fd)) continue;
                                if (!rp2p_udp_crypto_init(&sess.udp_crypto,
                                    ctx->secret, remote_token, 0))
                                {
                                    RP2P_FD_CLOSE(sess.backend_fd);
                                    continue;
                                }
                            }
                            sess.active = 1;

                            if (n_sessions >= cap_sessions) {
                                int new_cap = cap_sessions == 0 ? 8 : cap_sessions * 2;
                                rp2p_udp_server_session_t *new_sessions =
                                    (rp2p_udp_server_session_t *)realloc(
                                        sessions, (size_t)new_cap * sizeof(*sessions));
                                if (!new_sessions) {
                                    RP2P_FD_CLOSE(sess.backend_fd);
                                    continue;
                                }
                                sessions = new_sessions;
                                cap_sessions = new_cap;
                            }
                            sessions[n_sessions++] = sess;

                            rp2p_sendto_addr(udp_fd, RP2P_CTRTOK_PUNCH_SERVER,
                                strlen(RP2P_CTRTOK_PUNCH_SERVER), &peer);
                        } else {
                            rp2p_sendto_addr(udp_fd, RP2P_CTRTOK_PUNCH_SERVER,
                                strlen(RP2P_CTRTOK_PUNCH_SERVER), &peer);
                        }
                    }
                }
            }

            if (FD_ISSET(udp_fd, &fds)) {
                char buf[RP2P_BUF + RP2P_UDP_HEADER_SZ + RP2P_UDP_TAG_SZ + 1];
                struct sockaddr_storage from;
                socklen_t fromlen = sizeof(from);
                int recv_flags = 0;
#ifndef _WIN32
                recv_flags |= MSG_TRUNC;
#endif
                n = (int)recvfrom(udp_fd, buf, sizeof(buf) - 1, recv_flags,
                    (struct sockaddr *)&from, &fromlen);
                if (n > 0) {
#ifndef _WIN32
                    if ((size_t)n > sizeof(buf) - 1) return -1;
#endif
                    if ((size_t)n >= sizeof(buf)) n = (int)(sizeof(buf) - 1);
                    buf[n] = '\0';

                    int found = -1;
                    for (i = 0; i < n_sessions; i++) {
                        if (!sessions[i].active) continue;
                        if (rp2p_sockaddr_equal(&sessions[i].peer_addr,
                            &from)) {
                            found = i; break;
                        }
                    }

                    if (found >= 0) {
                        if (strncmp(buf, RP2P_CTRTOK_KA,
                            strlen(RP2P_CTRTOK_KA)) == 0 ||
                            strncmp(buf, RP2P_CTRTOK_PUNCH,
                            strlen(RP2P_CTRTOK_PUNCH)) == 0 ||
                            strncmp(buf, RP2P_CTRTOK_PUNCH_PING,
                            strlen(RP2P_CTRTOK_PUNCH_PING)) == 0 ||
                            strncmp(buf, RP2P_CTRTOK_PUNCH_PONG,
                            strlen(RP2P_CTRTOK_PUNCH_PONG)) == 0) {
                            sessions[found].last_rx = rp2p_now_s();
                        } else {
                            if (sessions[found].is_tcp) {
                                if (sessions[found].backend_fd != RP2P_FD_INVALID &&
                                    rp2p_stream_process_packet(ctx, udp_fd,
                                        &sessions[found].peer_addr,
                                        &sessions[found].stream,
                                        sessions[found].backend_fd,
                                        (const unsigned char *)buf,
                                        (size_t)n) != 0)
                                {
                                    rp2p_server_session_close(&sessions[found]);
                                }
                            } else {
                                struct sockaddr_in backend_addr;
                                unsigned char plain[RP2P_BUF];
                                size_t plain_len;

                                plain_len = rp2p_udp_decrypt(
                                    &sessions[found].udp_crypto,
                                    (const unsigned char *)buf, (size_t)n,
                                    plain, sizeof(plain));
                                if (plain_len == 0) continue;
                                memset(&backend_addr, 0, sizeof(backend_addr));
                                backend_addr.sin_family = AF_INET;
                                backend_addr.sin_port = htons(ctx->bind_port);
                                inet_pton(AF_INET, "127.0.0.1", &backend_addr.sin_addr);
                                sendto(sessions[found].backend_fd,
                                    (const char *)plain, plain_len, 0,
                                    (const struct sockaddr *)&backend_addr, sizeof(backend_addr));
                            }
                            sessions[found].last_rx = rp2p_now_s();
                        }
                    } else if (strncmp(buf, RP2P_CTRTOK_PUNCH_PING,
                        strlen(RP2P_CTRTOK_PUNCH_PING)) == 0) {
                        char pong[256];
                        char ping_sess[64] = {0}, ping_from[64] = {0}, ping_to[64] = {0};
                        if (rp2p_parse_punch_packet(buf,
                            RP2P_CTRTOK_PUNCH_PING,
                            ping_sess, ping_from, ping_to))
                        {
                            snprintf(pong, sizeof(pong), "%s%s:%s:%s",
                                RP2P_CTRTOK_PUNCH_PONG, ping_sess, ping_to,
                                ping_from);
                            sendto(udp_fd, pong, strlen(pong), 0,
                                (const struct sockaddr *)&from, fromlen);
                        }
                    } else {
                        int unset = -1;
                        for (i = 0; i < n_sessions; i++) {
                            if (!sessions[i].active) continue;
                            if (rp2p_sockaddr_port(&sessions[i].peer_addr) == 0) { unset = i; break; }
                        }
                        if (unset >= 0) {
                            sessions[unset].peer_addr = from;
                            sessions[unset].last_rx = rp2p_now_s();
                            sessions[unset].last_ka = sessions[unset].last_rx;
                            rp2p_sendto_addr(udp_fd, buf, (size_t)n, &from);
                            if (strncmp(buf, RP2P_CTRTOK_PUNCH,
                                strlen(RP2P_CTRTOK_PUNCH)) != 0 &&
                                strncmp(buf, RP2P_CTRTOK_KA,
                                strlen(RP2P_CTRTOK_KA)) != 0 &&
                                strncmp(buf, RP2P_CTRTOK_PUNCH_PING,
                                strlen(RP2P_CTRTOK_PUNCH_PING)) != 0 &&
                                strncmp(buf, RP2P_CTRTOK_PUNCH_PONG,
                                strlen(RP2P_CTRTOK_PUNCH_PONG)) != 0) {
                                if (sessions[unset].is_tcp) {
                                    if (sessions[unset].backend_fd != RP2P_FD_INVALID &&
                                        rp2p_stream_process_packet(ctx, udp_fd,
                                            &sessions[unset].peer_addr,
                                            &sessions[unset].stream,
                                            sessions[unset].backend_fd,
                                            (const unsigned char *)buf,
                                            (size_t)n) != 0)
                                    {
                                        rp2p_server_session_close(&sessions[unset]);
                                    }
                                } else {
                                    struct sockaddr_in backend_addr;
                                    unsigned char plain[RP2P_BUF];
                                    size_t plain_len;

                                    plain_len = rp2p_udp_decrypt(
                                        &sessions[unset].udp_crypto,
                                        (const unsigned char *)buf, (size_t)n,
                                        plain, sizeof(plain));
                                    if (plain_len == 0) continue;
                                    memset(&backend_addr, 0, sizeof(backend_addr));
                                    backend_addr.sin_family = AF_INET;
                                    backend_addr.sin_port = htons(ctx->bind_port);
                                    inet_pton(AF_INET, "127.0.0.1", &backend_addr.sin_addr);
                                    sendto(sessions[unset].backend_fd,
                                        (const char *)plain, plain_len, 0,
                                        (const struct sockaddr *)&backend_addr, sizeof(backend_addr));
                                }
                            }
                        } else if (strncmp(buf, RP2P_CTRTOK_PUNCH,
                            strlen(RP2P_CTRTOK_PUNCH)) == 0) {
                            rp2p_sendto_addr(udp_fd, buf, (size_t)n, &from);
                        }
                    }
                }
            }

            for (i = 0; i < n_sessions; i++) {
                if (!sessions[i].active) continue;
                if (sessions[i].backend_fd == RP2P_FD_INVALID) continue;
                if (!FD_ISSET(sessions[i].backend_fd, &fds)) continue;

                if (sessions[i].is_tcp) {
                    if (rp2p_stream_pump_tcp(ctx, udp_fd,
                        &sessions[i].peer_addr, &sessions[i].stream,
                        sessions[i].backend_fd) != 0)
                    {
                        rp2p_server_session_close(&sessions[i]);
                    }
                } else {
                    char buf[RP2P_BUF];
                    unsigned char packet[RP2P_BUF + RP2P_UDP_HEADER_SZ +
                        RP2P_UDP_TAG_SZ];
                    struct sockaddr_in bfrom;
                    socklen_t bfromlen = sizeof(bfrom);
                    n = (int)recvfrom(sessions[i].backend_fd, buf, sizeof(buf), 0,
                        (struct sockaddr *)&bfrom, &bfromlen);
                    if (n > 0) {
                        size_t packet_len = rp2p_udp_encrypt(
                            &sessions[i].udp_crypto,
                            (const unsigned char *)buf, (size_t)n, packet,
                            sizeof(packet));
                        if (packet_len > 0)
                            rp2p_sendto_addr(udp_fd, packet, packet_len,
                                &sessions[i].peer_addr);
                        sessions[i].last_rx = rp2p_now_s();
                    }
                }
            }

            for (i = 0; i < n_sessions; i++) {
                if (!sessions[i].active) continue;
                if (sessions[i].is_tcp) {
                    if (rp2p_stream_tick(ctx, udp_fd,
                        &sessions[i].peer_addr, &sessions[i].stream) != 0)
                    {
                        rp2p_server_session_close(&sessions[i]);
                        continue;
                    }
                    if (rp2p_stream_is_done(&sessions[i].stream)) {
                        rp2p_server_session_close(&sessions[i]);
                        continue;
                    }
                }
                if (rp2p_now_s() - sessions[i].last_ka > RP2P_KEEPALIVE_S) {
                rp2p_sendto_addr(udp_fd, RP2P_CTRTOK_KA,
                    strlen(RP2P_CTRTOK_KA), &sessions[i].peer_addr);
                    sessions[i].last_ka = rp2p_now_s();
                }
                if (rp2p_now_s() - sessions[i].last_rx > RP2P_DISCONNECT_S) {
                    rp2p_server_session_close(&sessions[i]);
                }
            }
        }

        for (i = 0; i < n_sessions; i++) {
            if (!sessions[i].active) continue;
            rp2p_server_session_close(&sessions[i]);
        }
        free(sessions);
    }

    if (ctx->key[0] != '\0')
        rp2p_deregister(ctx, index_host, index_port, self_id);

    RP2P_FD_CLOSE(control_fd);
    RP2P_FD_CLOSE(udp_fd);
    return RP2P_OK;
}

/**
 * Send punch req cands.
 * Summary: Send punch request with candidates.
 * @param ctrl_fd Control fd.
 * @param self_id Self id.
 * @param target_id Target id.
 * @param cands Candidates.
 * @param cand_count Candidate count.
 * @param remote_cands Remote candidates.
 * @param remote_cand_count Remote candidate count.
 * @return 0 on success, -1 on error.
 */
static int rp2p_send_punch_req_cands(
    rp2p_fd_t ctrl_fd,
    const char *self_id,
    const char *target_id,
    const char *session_id,
    rp2p_candidate_t *cands,
    int cand_count,
    rp2p_candidate_t *remote_cands,
    int *remote_cand_count)
{
    char send_buf[RP2P_BUF];
    char recv_buf[RP2P_BUF];
    int n;
    
    n = snprintf(send_buf, sizeof(send_buf), "%s%s:%s:%s\n",
        RP2P_CTRTOK_PUNCH_REQ2, self_id, target_id,
        session_id ? session_id : "0");
    if (n < 0 || (size_t)n >= sizeof(send_buf)) return RP2P_ERROR;
    for (int i = 0; i < cand_count; i++) {
        if (!rp2p_append_candidate(send_buf, sizeof(send_buf), &cands[i]))
            return RP2P_ERROR;
    }
    if (!rp2p_append_text(send_buf, sizeof(send_buf), RP2P_CTRTOK_END "\n"))
        return RP2P_ERROR;
    
    if (rp2p_tcp_send(ctrl_fd, send_buf) != RP2P_OK)
        return RP2P_ENET;
    if (rp2p_tcp_readline(ctrl_fd, recv_buf, (int)sizeof(recv_buf), 20) < 0)
        return RP2P_OK;
    
    if (strncmp(recv_buf, RP2P_CTRTOK_PUNCH_OK2,
        strlen(RP2P_CTRTOK_PUNCH_OK2)) == 0) {
        char lbuf[128];
        char ok_id[RP2P_ID_MAX + 1];
        char ok_sess[RP2P_CTRL_SESSION_MAX + 1];
        int saw_end = 0;
        if (!rp2p_parse_punch_ok2(recv_buf, ok_id, ok_sess))
            return RP2P_ERROR;
        while (rp2p_tcp_readline(ctrl_fd, lbuf, sizeof(lbuf), 5) > 0) {
            if (!rp2p_append_text(recv_buf, sizeof(recv_buf), "\n") ||
                !rp2p_append_text(recv_buf, sizeof(recv_buf), lbuf))
                return RP2P_ERROR;
            if (strcmp(lbuf, RP2P_CTRTOK_END) == 0) {
                saw_end = 1;
                break;
            }
        }
        if (saw_end && !rp2p_append_text(recv_buf, sizeof(recv_buf), "\n"))
            return RP2P_ERROR;
        if (!saw_end) return RP2P_ERROR;
        if (!rp2p_parse_remote_candidates(recv_buf, remote_cands,
            remote_cand_count))
            return RP2P_ERROR;
    }
    return RP2P_OK;
}

/**
 * Open udp session cands.
 * Summary: Open UDP session with candidates.
 * @param fd socket fd.
 * @param self_id Self id.
 * @param target_id Target id.
 * @param remote_cands Remote candidates.
 * @param remote_cand_count Remote candidate count.
 * @param out_fd Out fd.
 * @param out_peer Out peer.
 * @return 0 on success, -1 on error.
 */
static int rp2p_open_udp_session_cands(
    rp2p_t *ctx,
    int sweep_limit,
    int fd,
    const char *self_id,
    const char *target_id,
    const char *session_id,
    rp2p_candidate_t *remote_cands,
    int remote_cand_count,
    rp2p_fd_t *out_fd,
    struct sockaddr_storage *out_peer,
    rp2p_udp_consumer_session_t *sess)
{
    struct sockaddr_storage peer_addr;
    memset(&peer_addr, 0, sizeof(peer_addr));

    int rc = rp2p_punch_select(ctx, sweep_limit, fd, session_id ? session_id : "0", self_id, target_id, remote_cands, remote_cand_count, &peer_addr);
    if (rc != RP2P_OK) {
        fprintf(stderr, "rp2p: udp punch failed\n");
        RP2P_FD_CLOSE(fd);
        return rc;
    }

    (void)ctx;
    (void)sess;

    *out_fd = fd;
    *out_peer = peer_addr;
    return RP2P_OK;
}

/**
 * Connect.
 * @return 0 on success, -1 on error.
 */
int rp2p_connect(
    rp2p_t *ctx,
    const char *index_host,
    unsigned short index_port,
    const char *self_id,
    const char *target_id,
    unsigned short bind_port)
{
    rp2p_fd_t ctrl_fd;
    rp2p_fd_t local_fd;
    rp2p_fd_t tcp_listen_fd;
    rp2p_udp_consumer_session_t *sessions;
    const char *udp_any_host;
    int n_sessions, cap_sessions;
    unsigned short eff_port;

    if (!ctx) return RP2P_ERROR;
    ctx->stop_requested = 0;
    if (rp2p_resolve_port(ctx, bind_port, &eff_port) != RP2P_OK)
        return RP2P_ERROR;
    if (eff_port == 0) return RP2P_ERROR;
    ctx->bind_port = eff_port;
    if (rp2p_platform_init() != 0) return RP2P_ENET;
    udp_any_host = rp2p_host_is_ipv6_literal(index_host) ? "::" : "0.0.0.0";

    if (ctx->proto == RP2P_PROTO_UDP) {
        local_fd = rp2p_create_socket("127.0.0.1", ctx->bind_port);
        if (RP2P_ISERR(local_fd)) { rp2p_platform_cleanup(); return RP2P_ENET; }
        tcp_listen_fd = RP2P_FD_INVALID;
    } else {
        local_fd = rp2p_create_socket(udp_any_host, 0);
        if (RP2P_ISERR(local_fd)) { rp2p_platform_cleanup(); return RP2P_ENET; }
        tcp_listen_fd = rp2p_create_tcp_listener("127.0.0.1", ctx->bind_port);
        if (RP2P_ISERR(tcp_listen_fd)) {
            RP2P_FD_CLOSE(local_fd);
            rp2p_platform_cleanup();
            return RP2P_ENET;
        }
    }

    ctrl_fd = rp2p_control_connect(index_host, index_port);
    if (RP2P_ISERR(ctrl_fd)) {
        rp2p_set_error(ctx, "connect: control connect %s:%u failed",
            index_host, (unsigned)index_port);
        RP2P_FD_CLOSE(local_fd);
        if (!RP2P_ISERR(tcp_listen_fd)) RP2P_FD_CLOSE(tcp_listen_fd);
        rp2p_platform_cleanup();
        return RP2P_ENET;
    }
    {
        char recv_buf[RP2P_BUF];
        snprintf(recv_buf, sizeof(recv_buf), "%s%s", RP2P_CTRTOK_LOOKUP,
            target_id);
        if (rp2p_tcp_send(ctrl_fd, recv_buf) != RP2P_OK ||
            rp2p_tcp_readline(ctrl_fd, recv_buf, (int)sizeof(recv_buf), 5) < 0)
        { RP2P_FD_CLOSE(ctrl_fd); RP2P_FD_CLOSE(local_fd); if (!RP2P_ISERR(tcp_listen_fd)) RP2P_FD_CLOSE(tcp_listen_fd); rp2p_platform_cleanup(); return RP2P_ENET; }
        if (strcmp(recv_buf, RP2P_CTRTOK_NOT_FOUND) == 0)
        { RP2P_FD_CLOSE(ctrl_fd); RP2P_FD_CLOSE(local_fd); if (!RP2P_ISERR(tcp_listen_fd)) RP2P_FD_CLOSE(tcp_listen_fd); rp2p_platform_cleanup(); return RP2P_ENOENT; }
        if (strcmp(recv_buf, RP2P_CTRTOK_PUBLISHER) == 0 ||
            strncmp(recv_buf, RP2P_CTRTOK_PUBLISHER,
            strlen(RP2P_CTRTOK_PUBLISHER)) != 0 ||
            strcmp(recv_buf + strlen(RP2P_CTRTOK_PUBLISHER), target_id) != 0)
        { RP2P_FD_CLOSE(ctrl_fd); RP2P_FD_CLOSE(local_fd); if (!RP2P_ISERR(tcp_listen_fd)) RP2P_FD_CLOSE(tcp_listen_fd); rp2p_platform_cleanup(); return RP2P_ERROR; }
    }
    RP2P_FD_CLOSE(ctrl_fd);

    sessions = NULL;
    n_sessions = 0;
    cap_sessions = 0;

    fprintf(stderr, "rp2p: %s edge adapter on 127.0.0.1:%u for %s\n",
        ctx->proto == RP2P_PROTO_TCP ? "tcp" : "udp",
        (unsigned)ctx->bind_port, target_id);

    rp2p_set_nonblock(local_fd);
    if (!RP2P_ISERR(tcp_listen_fd)) rp2p_set_nonblock(tcp_listen_fd);

    while (!ctx->stop_requested) {
        fd_set fds;
        struct timeval tv;
        rp2p_dispatch_pending_signals();
        int maxfd = -1;
        int n, i;

        FD_ZERO(&fds);
        rp2p_fdset_add(local_fd, &fds, &maxfd);

        if (!RP2P_ISERR(tcp_listen_fd)) {
            rp2p_fdset_add(tcp_listen_fd, &fds, &maxfd);
        }

        for (i = 0; i < n_sessions; i++) {
            if (!sessions[i].active) continue;
            rp2p_fdset_add(sessions[i].fd, &fds, &maxfd);
            if (sessions[i].is_tcp && sessions[i].tcp_fd != RP2P_FD_INVALID) {
                if (!rp2p_stream_can_send_data(&sessions[i].stream) &&
                    !sessions[i].stream.out.local_eof)
                    continue;
                rp2p_fdset_add(sessions[i].tcp_fd, &fds, &maxfd);
            }
        }
        tv.tv_sec = 1; tv.tv_usec = 0;
        n = select(maxfd + 1, &fds, NULL, NULL, &tv);
        if (n < 0) continue;
        if (ctx->stop_requested) break;

        if (!RP2P_ISERR(tcp_listen_fd) && FD_ISSET(tcp_listen_fd, &fds)) {
            rp2p_fd_t client_fd = accept(tcp_listen_fd, NULL, NULL);
            if (!RP2P_ISERR(client_fd)) {
                ctrl_fd = rp2p_control_connect(index_host, index_port);
                if (!RP2P_ISERR(ctrl_fd)) {
                    unsigned char sess_id_bin[RP2P_STREAM_SESSION_ID_SZ];
                    
                    rp2p_candidate_t cands[RP2P_CANDIDATES_MAX];
                    int cand_count = 0;
                    rp2p_candidate_t remote_cands[RP2P_CANDIDATES_MAX];
                    int remote_cand_count = 0;
                    char sess_id[RP2P_STREAM_SESSION_ID_SZ * 2 + 1];
                    if (!rp2p_stream_make_session_id(sess_id_bin, sess_id)) {
                        RP2P_FD_CLOSE(ctrl_fd);
                        RP2P_FD_CLOSE(client_fd);
                        continue;
                    }
                    
                    int temp_udp = rp2p_create_socket(udp_any_host, 0);
                    rp2p_gather_candidates(ctx, temp_udp, cands,
                        RP2P_CANDIDATES_MAX, &cand_count);
                    
                    rp2p_send_punch_req_cands(ctrl_fd, self_id, target_id, sess_id, cands, cand_count, remote_cands, &remote_cand_count);
                    RP2P_FD_CLOSE(ctrl_fd);

                    {
                        rp2p_udp_consumer_session_t sess;
                        memset(&sess, 0, sizeof(sess));
                        if (rp2p_open_udp_session_cands(
                            ctx, ctx->sweep, temp_udp, self_id, target_id, sess_id,
                            remote_cands, remote_cand_count,
                            &sess.fd, &sess.peer_addr, &sess) == RP2P_OK)
                        {
                            rp2p_stream_init(&sess.stream, 1, sess_id_bin,
                                sess_id, ctx->secret);
                            if (!rp2p_stream_crypto_init(&sess.stream)) {
                                RP2P_FD_CLOSE(sess.fd);
                                RP2P_FD_CLOSE(client_fd);
                                continue;
                            }
                            sess.tcp_fd = client_fd;
                            sess.active = 1;
                            sess.is_tcp = 1;
                            sess.last_rx = rp2p_now_s();
                            sess.last_ka = sess.last_rx;
                            memset(&sess.client_addr, 0, sizeof(sess.client_addr));
                            if (n_sessions >= cap_sessions) {
                                int new_cap = cap_sessions == 0 ? 8 : cap_sessions * 2;
                                rp2p_udp_consumer_session_t *new_sessions =
                                    (rp2p_udp_consumer_session_t *)realloc(
                                        sessions, (size_t)new_cap * sizeof(*sessions));
                                if (!new_sessions) { RP2P_FD_CLOSE(sess.fd); RP2P_FD_CLOSE(client_fd); continue; }
                                sessions = new_sessions;
                                cap_sessions = new_cap;
                            }
                            sessions[n_sessions++] = sess;
                        } else {
                            RP2P_FD_CLOSE(client_fd);
                        }
                    }
                } else {
                    RP2P_FD_CLOSE(client_fd);
                }
            }
        }

        if (!RP2P_ISERR(tcp_listen_fd)) {
            for (i = 0; i < n_sessions; i++) {
                if (!sessions[i].active) continue;
                if (!FD_ISSET(sessions[i].tcp_fd, &fds)) continue;
                if (rp2p_stream_pump_tcp(ctx, sessions[i].fd,
                    &sessions[i].peer_addr, &sessions[i].stream,
                    sessions[i].tcp_fd) != 0)
                {
                    rp2p_consumer_session_close(&sessions[i]);
                }
            }
        } else if (FD_ISSET(local_fd, &fds)) {
            char buf[RP2P_BUF];
            struct sockaddr_storage from;
            socklen_t fromlen = sizeof(from);
            int found;

            n = (int)recvfrom(local_fd, buf, sizeof(buf), 0,
                (struct sockaddr *)&from, &fromlen);
            if (n > 0) {
                found = -1;
                for (i = 0; i < n_sessions; i++) {
                    if (!sessions[i].active) continue;
                    if (rp2p_sockaddr_equal(&sessions[i].client_addr,
                        &from)) {
                        found = i; break;
                    }
                }
                if (found < 0) {
                    rp2p_udp_consumer_session_t sess;
                    memset(&sess, 0, sizeof(sess));

                    ctrl_fd = rp2p_control_connect(index_host, index_port);
                    if (!RP2P_ISERR(ctrl_fd)) {
                        rp2p_candidate_t cands[RP2P_CANDIDATES_MAX];
                        int cand_count = 0;
                        rp2p_candidate_t remote_cands[RP2P_CANDIDATES_MAX];
                        int remote_cand_count = 0;
                        unsigned char sess_random[8];
                        char sess_id[17];
                        if (rp2p_fill_random(sess_random, sizeof(sess_random)) != 0 ||
                            !rp2p_hex_encode(sess_random, sizeof(sess_random),
                                sess_id, sizeof(sess_id)))
                        {
                            RP2P_FD_CLOSE(ctrl_fd);
                            goto udp_skip;
                        }
                        
                        int temp_udp = rp2p_create_socket(udp_any_host, 0);
                        rp2p_gather_candidates(ctx, temp_udp, cands,
                            RP2P_CANDIDATES_MAX, &cand_count);
                        
                        rp2p_send_punch_req_cands(ctrl_fd, self_id, target_id, sess_id, cands, cand_count, remote_cands, &remote_cand_count);
                        RP2P_FD_CLOSE(ctrl_fd);

                        if (rp2p_open_udp_session_cands(
                            ctx, ctx->sweep, temp_udp, self_id, target_id, sess_id,
                            remote_cands, remote_cand_count,
                            &sess.fd, &sess.peer_addr, &sess) == RP2P_OK)
                        {
                            sess.client_addr = from;
                            sess.last_rx = rp2p_now_s();
                            sess.last_ka = sess.last_rx;
                            sess.active = 1;
                            sess.is_tcp = 0;
                            sess.tcp_fd = RP2P_FD_INVALID;
                            if (!rp2p_udp_crypto_init(&sess.udp_crypto,
                                ctx->secret, sess_id, 1))
                            {
                                RP2P_FD_CLOSE(sess.fd);
                                goto udp_skip;
                            }
                            if (n_sessions >= cap_sessions) {
                                int new_cap = cap_sessions == 0 ? 8 : cap_sessions * 2;
                                rp2p_udp_consumer_session_t *new_sessions =
                                    (rp2p_udp_consumer_session_t *)realloc(
                                        sessions, (size_t)new_cap * sizeof(*sessions));
                                if (!new_sessions) { RP2P_FD_CLOSE(sess.fd); goto udp_skip; }
                                sessions = new_sessions; cap_sessions = new_cap;
                            }
                            sessions[n_sessions++] = sess;
                            found = n_sessions - 1;
                        }
                    }
                }
udp_skip:
                if (found >= 0) {
                    unsigned char packet[RP2P_BUF + RP2P_UDP_HEADER_SZ +
                        RP2P_UDP_TAG_SZ];
                    size_t packet_len = rp2p_udp_encrypt(
                        &sessions[found].udp_crypto,
                        (const unsigned char *)buf, (size_t)n, packet,
                        sizeof(packet));
                    if (packet_len > 0)
                        rp2p_sendto_addr(sessions[found].fd, packet,
                            packet_len, &sessions[found].peer_addr);
                    sessions[found].last_rx = rp2p_now_s();
                }
            }
        }

        for (i = 0; i < n_sessions; i++) {
            if (!sessions[i].active) continue;
            if (!FD_ISSET(sessions[i].fd, &fds)) continue;
            char buf[RP2P_BUF + RP2P_UDP_HEADER_SZ + RP2P_UDP_TAG_SZ];
            struct sockaddr_storage from;
            socklen_t fromlen = sizeof(from);
            n = (int)recvfrom(sessions[i].fd, buf, sizeof(buf), 0,
                (struct sockaddr *)&from, &fromlen);
            if (n > 0) {
                if (!rp2p_sockaddr_equal(&from, &sessions[i].peer_addr))
                    continue;
                if (((size_t)n >= strlen(RP2P_CTRTOK_KA) &&
                    strncmp(buf, RP2P_CTRTOK_KA,
                    strlen(RP2P_CTRTOK_KA)) == 0) ||
                    ((size_t)n >= strlen(RP2P_CTRTOK_PUNCH) &&
                    strncmp(buf, RP2P_CTRTOK_PUNCH,
                    strlen(RP2P_CTRTOK_PUNCH)) == 0) ||
                    ((size_t)n >= strlen(RP2P_CTRTOK_PUNCH_PING) &&
                    strncmp(buf, RP2P_CTRTOK_PUNCH_PING,
                    strlen(RP2P_CTRTOK_PUNCH_PING)) == 0) ||
                    ((size_t)n >= strlen(RP2P_CTRTOK_PUNCH_PONG) &&
                    strncmp(buf, RP2P_CTRTOK_PUNCH_PONG,
                    strlen(RP2P_CTRTOK_PUNCH_PONG)) == 0)) {
                    sessions[i].last_rx = rp2p_now_s();
                } else {
                    if (sessions[i].is_tcp) {
                        if (sessions[i].tcp_fd != RP2P_FD_INVALID &&
                            rp2p_stream_process_packet(ctx, sessions[i].fd,
                                &sessions[i].peer_addr,
                                &sessions[i].stream, sessions[i].tcp_fd,
                                (const unsigned char *)buf, (size_t)n) != 0)
                        {
                            rp2p_consumer_session_close(&sessions[i]);
                        }
                    } else {
                        unsigned char plain[RP2P_BUF];
                        size_t plain_len = rp2p_udp_decrypt(
                            &sessions[i].udp_crypto,
                            (const unsigned char *)buf, (size_t)n, plain,
                            sizeof(plain));
                        if (plain_len == 0) continue;
                        rp2p_sendto_addr(local_fd, plain, plain_len,
                            &sessions[i].client_addr);
                    }
                    sessions[i].last_rx = rp2p_now_s();
                }
            }
        }

        for (i = 0; i < n_sessions; i++) {
            if (!sessions[i].active) continue;
            if (sessions[i].is_tcp) {
                if (rp2p_stream_tick(ctx, sessions[i].fd,
                    &sessions[i].peer_addr, &sessions[i].stream) != 0)
                {
                    rp2p_consumer_session_close(&sessions[i]);
                    continue;
                }
                if (rp2p_stream_is_done(&sessions[i].stream)) {
                    rp2p_consumer_session_close(&sessions[i]);
                    continue;
                }
            }
            if (rp2p_now_s() - sessions[i].last_ka > RP2P_KEEPALIVE_S) {
                rp2p_sendto_addr(sessions[i].fd, RP2P_CTRTOK_KA,
                    strlen(RP2P_CTRTOK_KA), &sessions[i].peer_addr);
                sessions[i].last_ka = rp2p_now_s();
            }
            if (rp2p_now_s() - sessions[i].last_rx > RP2P_DISCONNECT_S) {
                rp2p_consumer_session_close(&sessions[i]);
            }
        }
    }

    for (int cleanup_i = 0; cleanup_i < n_sessions; cleanup_i++) {
        if (!sessions[cleanup_i].active) continue;
        rp2p_consumer_session_close(&sessions[cleanup_i]);
    }
    free(sessions);
    RP2P_FD_CLOSE(local_fd);
    if (!RP2P_ISERR(tcp_listen_fd)) RP2P_FD_CLOSE(tcp_listen_fd);
    rp2p_platform_cleanup();
    return RP2P_OK;
}

#ifdef RP2P_TEST_RANDOM
/**
 * Generates one registration key through the test-visible path.
 * @param out Output key buffer.
 * @return 1 on success, 0 on error.
 */
int rp2p_test_generate_key(char *out) {
    return rp2p_generate_key(out);
}

/**
 * Generates one STUN transaction identifier through the test-visible path.
 * @param out Output transaction identifier.
 * @return 1 on success, 0 on error.
 */
int rp2p_test_stun_gen_id(unsigned char out[12]) {
    return rp2p_stun_gen_id(out);
}

/**
 * Generates one stream session identifier through the test-visible path.
 * @param out Output binary identifier.
 * @param hex Output hex identifier.
 * @return 1 on success, 0 on error.
 */
int rp2p_test_stream_make_session_id(
unsigned char out[RP2P_STREAM_SESSION_ID_SZ],
char hex[RP2P_STREAM_SESSION_ID_SZ * 2 + 1]
)
{
    return rp2p_stream_make_session_id(out, hex);
}

/**
 * Generates one register challenge nonce through the test-visible path.
 * @param hex Output hex nonce.
 * @return 1 on success, 0 on error.
 */
int rp2p_test_pow_nonce(char hex[17]) {
    unsigned char nonce[8];

    if (rp2p_fill_random(nonce, sizeof(nonce)) != 0) return 0;
    return rp2p_hex_encode(nonce, sizeof(nonce), hex, 17);
}

/**
 * Generates one UDP session identifier through the test-visible path.
 * @param hex Output hex session identifier.
 * @return 1 on success, 0 on error.
 */
int rp2p_test_udp_session_id(char hex[17]) {
    unsigned char session_id[8];

    if (rp2p_fill_random(session_id, sizeof(session_id)) != 0) return 0;
    return rp2p_hex_encode(session_id, sizeof(session_id), hex, 17);
}

/**
 * Compares STUN transaction identifiers through the test-visible path.
 * @param expected Expected transaction identifier.
 * @param actual   Actual transaction identifier.
 * @return 1 when equal, 0 otherwise.
 */
int rp2p_test_stun_id_matches(const unsigned char expected[12],
const unsigned char actual[12])
{
    return memcmp(expected, actual, 12) == 0;
}
#endif
