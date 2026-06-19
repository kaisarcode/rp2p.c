/**
 * libkcp2p.c - KaisarCode P2P.
 * Summary: Core shared library. TCP rendezvous control and direct P2P UDP relay.
 *
 * Author:  KaisarCode
 * Website: https://kaisarcode.com
 * License: https://www.gnu.org/licenses/gpl-3.0.html
 */

#ifndef _WIN32
#define _POSIX_C_SOURCE 200809L
#endif

#include "p2p.h"
#include "monocypher.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include <stdint.h>
#include <stdarg.h>

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
typedef SOCKET kc_p2p_fd_t;
#  define KC_P2P_FD_INVALID  INVALID_SOCKET
#  define KC_P2P_FD_CLOSE(f) closesocket(f)
#  define KC_P2P_ISERR(f)    ((f) == INVALID_SOCKET)
#  define KC_P2P_LASTERR()   ((int)WSAGetLastError())
#  define KC_P2P_EWOULD      WSAEWOULDBLOCK
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
typedef int kc_p2p_fd_t;
#  define KC_P2P_FD_INVALID  (-1)
#  define KC_P2P_FD_CLOSE(f) close(f)
#  define KC_P2P_ISERR(f)    ((f) < 0)
#  define KC_P2P_LASTERR()   errno
#  define KC_P2P_EWOULD      EAGAIN
#  define INVALID_SOCKET     (-1)
#  define SOCKET_ERROR       (-1)
#endif

#define KC_P2P_ETIMEOUT_SEC     15
#define KC_P2P_HALFCLOSE_S       2
#define KC_P2P_DISCONNECT_S     10
#define KC_P2P_KEEPALIVE_S       3
#define KC_P2P_PUNCH_ATTEMPTS   10
#define KC_P2P_PUNCH_INTERVAL_MS 200
#define KC_P2P_CANDIDATES_MAX       16
#define KC_P2P_MAX_PENDING_PUNCHES  32
#define KC_P2P_POW_CHALLENGES_MAX 256
#define KC_P2P_STREAM_MAGIC      0x48535452u
#define KC_P2P_STREAM_VERSION    1u
#define KC_P2P_STREAM_SESSION_ID_SZ 16
#define KC_P2P_STREAM_HELLO_NONCE_SZ 16
#define KC_P2P_STREAM_KEY_SZ     32
#define KC_P2P_STREAM_TAG_SZ     16
#define KC_P2P_STREAM_NONCE_SZ   24
#define KC_P2P_STREAM_MAX_PAYLOAD 1024
#define KC_P2P_STREAM_MAX_FRAME  1400
#define KC_P2P_STREAM_SEND_WINDOW 64
#define KC_P2P_STREAM_RECV_WINDOW 64
#define KC_P2P_STREAM_RTO_MS     700
#define KC_P2P_STREAM_ACK_MS     120
#define KC_P2P_STREAM_HELLO_MS   500
#define KC_P2P_STREAM_IDLE_MS    20000
#define KC_P2P_STREAM_MAX_RETRIES 12
#define KC_P2P_STREAM_RTO_BACKOFF_SHIFT 4
#define KC_P2P_STREAM_MAX_BURST          16
#define KC_P2P_STREAM_HEADER_SZ         44
#define KC_P2P_IPV4_UDP_OVERHEAD        28
#define KC_P2P_IPV6_UDP_OVERHEAD        40
#define KC_P2P_MAX_DATAGRAM_V4          1472
#define KC_P2P_MAX_DATAGRAM_V6          1452
#define KC_P2P_PUNCH_DIRECT_ROUNDS 3
#define KC_P2P_PUNCH_DIRECT_WAIT_MS 500
#define KC_P2P_PUNCH_SWEEP_WAIT_MS 20
#define KC_P2P_PUNCH_TOTAL_MS 4000
#define KC_P2P_CTRL_LINE_MAX     1024
#define KC_P2P_CTRL_FIELD_MAX     256
#define KC_P2P_CTRL_SESSION_MAX    63
#define KC_P2P_CTRL_HELLO          "HELLO KCP2P/1"
#define KC_P2P_CTRL_HELLO_OK       "OK:HELLO"
#define KC_P2P_CTRL_VERSION_ERROR  "ERROR:version mismatch"

#define KC_P2P_STREAM_TYPE_HELLO     1u
#define KC_P2P_STREAM_TYPE_HELLO_ACK 2u
#define KC_P2P_STREAM_TYPE_DATA      3u
#define KC_P2P_STREAM_TYPE_ACK       4u
#define KC_P2P_STREAM_TYPE_SACK      5u
#define KC_P2P_STREAM_TYPE_FIN       6u
#define KC_P2P_STREAM_TYPE_FIN_ACK   7u
#define KC_P2P_STREAM_TYPE_RESET     8u
#define KC_P2P_STREAM_TYPE_PING      9u
#define KC_P2P_STREAM_TYPE_PONG      10u

#define KC_P2P_STREAM_DIR_C2S    1u
#define KC_P2P_STREAM_DIR_S2C    2u

typedef struct {
    uint8_t type;
    uint8_t direction;
    uint32_t seq;
    uint32_t ack;
    uint16_t window;
    uint16_t payload_len;
    uint32_t gap_start;
    uint32_t gap_end;
    unsigned char session_id[KC_P2P_STREAM_SESSION_ID_SZ];
} kc_p2p_stream_header_t;

typedef struct {
    int used;
    uint8_t type;
    uint32_t seq;
    int attempts;
    uint64_t last_tx_ms;
    size_t frame_len;
    unsigned char frame[KC_P2P_STREAM_MAX_FRAME];
} kc_p2p_stream_send_slot_t;

#ifndef KC_P2P_BUILD_VERSION
#define KC_P2P_BUILD_VERSION 0
#endif

/**
 * Compile-time size assertion for MTU safety.
 * @return void.
 */
static void kc_p2p_size_check(void) {
    (void)sizeof(char[1 - 2 * (KC_P2P_STREAM_HEADER_SZ + KC_P2P_STREAM_TAG_SZ >
        KC_P2P_STREAM_MAX_FRAME - KC_P2P_STREAM_MAX_PAYLOAD)]);
    (void)sizeof(char[1 - 2 * (KC_P2P_STREAM_MAX_FRAME > KC_P2P_MAX_DATAGRAM_V4)]);
}

/**
 * Returns the build version generated at compile time.
 * @return Unix timestamp for the current build.
 */
uint64_t kc_p2p_version(void) {
    return (uint64_t)KC_P2P_BUILD_VERSION;
}

typedef struct {
    int used;
    uint8_t type;
    uint32_t seq;
    uint16_t len;
    unsigned char data[KC_P2P_STREAM_MAX_PAYLOAD];
} kc_p2p_stream_recv_slot_t;

typedef struct {
    int ready;
    unsigned char local_secret[32];
    unsigned char local_public[32];
    unsigned char peer_public[32];
    unsigned char local_nonce[KC_P2P_STREAM_HELLO_NONCE_SZ];
    unsigned char peer_nonce[KC_P2P_STREAM_HELLO_NONCE_SZ];
    unsigned char tx_key[KC_P2P_STREAM_KEY_SZ];
    unsigned char rx_key[KC_P2P_STREAM_KEY_SZ];
} kc_p2p_stream_crypto_t;

typedef struct {
    uint32_t next_seq;
    int fin_sent;
    int fin_acked;
    int local_eof;
    kc_p2p_stream_send_slot_t slots[KC_P2P_STREAM_SEND_WINDOW];
} kc_p2p_stream_outbound_t;

typedef struct {
    uint32_t next_expected;
    int remote_fin;
    int remote_fin_acked;
    kc_p2p_stream_recv_slot_t slots[KC_P2P_STREAM_RECV_WINDOW];
} kc_p2p_stream_inbound_t;

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
    unsigned char session_id[KC_P2P_STREAM_SESSION_ID_SZ];
    char session_hex[KC_P2P_STREAM_SESSION_ID_SZ * 2 + 1];
    kc_p2p_stream_crypto_t crypto;
    kc_p2p_stream_outbound_t out;
    kc_p2p_stream_inbound_t in;
    uint64_t last_rx_ms;
    uint64_t last_tx_ms;
    uint64_t last_ack_ms;
    uint64_t last_hello_ms;
} kc_p2p_stream_state_t;

typedef struct {
    int used;
    unsigned char session_id[KC_P2P_STREAM_SESSION_ID_SZ];
    uint32_t seq;
} kc_p2p_stream_drop_record_t;

typedef struct {
    int used;
    size_t len;
    unsigned char frame[KC_P2P_STREAM_MAX_FRAME];
} kc_p2p_stream_pending_frame_t;

volatile sig_atomic_t kc_p2p_stop_requested = 0;

static kc_p2p_t *g_signal_ctx = NULL;

typedef struct {
    uint32_t state[8];
    uint64_t count;
    unsigned char buf[64];
} kc_p2p_sha256_t;

static const uint32_t kc_p2p_sha256_k[64] = {
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

#define KC_P2P_SHA256_ROR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define KC_P2P_SHA256_CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define KC_P2P_SHA256_MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define KC_P2P_SHA256_S0(x) (KC_P2P_SHA256_ROR(x, 2) ^ KC_P2P_SHA256_ROR(x, 13) ^ KC_P2P_SHA256_ROR(x, 22))
#define KC_P2P_SHA256_S1(x) (KC_P2P_SHA256_ROR(x, 6) ^ KC_P2P_SHA256_ROR(x, 11) ^ KC_P2P_SHA256_ROR(x, 25))
#define KC_P2P_SHA256_s0(x) (KC_P2P_SHA256_ROR(x, 7) ^ KC_P2P_SHA256_ROR(x, 18) ^ ((x) >> 3))
#define KC_P2P_SHA256_s1(x) (KC_P2P_SHA256_ROR(x, 17) ^ KC_P2P_SHA256_ROR(x, 19) ^ ((x) >> 10))

/**
 * sha256 transform.
 * @return None.
 */

/**
 * Sha256 transform.
 * @return Status code.
 */
static void kc_p2p_sha256_transform(uint32_t state[8], const unsigned char block[64]) {
    uint32_t W[64], a, b, c, d, e, f, g, h, T1, T2;
    int t;
    for (t = 0; t < 16; t++)
        W[t] = ((uint32_t)block[t*4]) << 24 |
            ((uint32_t)block[t*4+1]) << 16 |
            ((uint32_t)block[t*4+2]) << 8 |
            block[t*4+3];
    for (t = 16; t < 64; t++)
        W[t] = KC_P2P_SHA256_s1(W[t-2]) + W[t-7] + KC_P2P_SHA256_s0(W[t-15]) + W[t-16];
    a = state[0]; b = state[1]; c = state[2]; d = state[3];
    e = state[4]; f = state[5]; g = state[6]; h = state[7];
    for (t = 0; t < 64; t++) {
        T1 = h + KC_P2P_SHA256_S1(e) + KC_P2P_SHA256_CH(e, f, g) + kc_p2p_sha256_k[t] + W[t];
        T2 = KC_P2P_SHA256_S0(a) + KC_P2P_SHA256_MAJ(a, b, c);
        h = g; g = f; f = e; e = d + T1; d = c; c = b; b = a; a = T1 + T2;
    }
    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

/**
 * sha256 init.
 * @return None.
 */

/**
 * Sha256 init.
 * @return Status code.
 */
static void kc_p2p_sha256_init(kc_p2p_sha256_t *ctx) {
    ctx->state[0] = 0x6a09e667; ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372; ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f; ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab; ctx->state[7] = 0x5be0cd19;
    ctx->count = 0;
}

/**
 * sha256 update.
 * @return None.
 */

/**
 * Sha256 update.
 * @return Status code.
 */
static void kc_p2p_sha256_update(kc_p2p_sha256_t *ctx, const unsigned char *data, size_t len) {
    size_t i;
    for (i = 0; i < len; i++) {
        ctx->buf[ctx->count & 63] = data[i];
        ctx->count++;
        if ((ctx->count & 63) == 0)
            kc_p2p_sha256_transform(ctx->state, ctx->buf);
    }
}

/**
 * sha256 final.
 * @return None.
 */

/**
 * Sha256 final.
 * @return Status code.
 */
static void kc_p2p_sha256_final(kc_p2p_sha256_t *ctx, unsigned char hash[32]) {
    uint64_t bits = ctx->count * 8;
    int idx = (int)(ctx->count & 63);
    ctx->buf[idx++] = 0x80;
    if (idx > 56) {
        while (idx < 64) ctx->buf[idx++] = 0;
        kc_p2p_sha256_transform(ctx->state, ctx->buf);
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
    kc_p2p_sha256_transform(ctx->state, ctx->buf);
    memcpy(hash, ctx->state, 32);
}

typedef struct {
    char nonce_hex[17];
    char id[KC_P2P_ID_MAX + 1];
    struct sockaddr_storage addr;
    uint64_t issued_at;
} kc_p2p_pow_challenge_t;

/**
 * Computes one HMAC-SHA256 digest.
 * @param key     Shared password material.
 * @param msg     Input message bytes.
 * @param msg_len Input message length.
 * @param hash    Output digest buffer.
 * @return None.
 */
static void kc_p2p_hmac_sha256(const char *key, const unsigned char *msg,
    size_t msg_len, unsigned char hash[32])
{
    kc_p2p_sha256_t ctx;
    unsigned char key_block[64];
    unsigned char ipad[64];
    unsigned char opad[64];
    unsigned char inner[32];
    size_t key_len;
    size_t i;

    memset(key_block, 0, sizeof(key_block));
    key_len = key ? strlen(key) : 0;
    if (key_len > sizeof(key_block)) {
        kc_p2p_sha256_init(&ctx);
        kc_p2p_sha256_update(&ctx, (const unsigned char *)key, key_len);
        kc_p2p_sha256_final(&ctx, key_block);
    } else if (key_len > 0) {
        memcpy(key_block, key, key_len);
    }
    for (i = 0; i < sizeof(key_block); i++) {
        ipad[i] = (unsigned char)(key_block[i] ^ 0x36);
        opad[i] = (unsigned char)(key_block[i] ^ 0x5c);
    }
    kc_p2p_sha256_init(&ctx);
    kc_p2p_sha256_update(&ctx, ipad, sizeof(ipad));
    kc_p2p_sha256_update(&ctx, msg, msg_len);
    kc_p2p_sha256_final(&ctx, inner);
    kc_p2p_sha256_init(&ctx);
    kc_p2p_sha256_update(&ctx, opad, sizeof(opad));
    kc_p2p_sha256_update(&ctx, inner, sizeof(inner));
    kc_p2p_sha256_final(&ctx, hash);
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
static void kc_p2p_hash_register_once(const char *pass, const char *nonce_hex,
    const char *id, const char *solution_hex, unsigned char hash[32])
{
    unsigned char msg[KC_P2P_ID_MAX + 33];
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
    kc_p2p_hmac_sha256(pass ? pass : "", msg, pos, hash);
}

/**
 * Encodes a digest as lowercase hex.
 * @param hash     Input digest bytes.
 * @param hash_len Digest length in bytes.
 * @param out      Output hex buffer.
 * @param out_cap  Output buffer capacity.
 * @return 1 on success, 0 on failure.
 */
static int kc_p2p_hex_encode(const unsigned char *hash, size_t hash_len,
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
static int kc_p2p_count_leading_zero_bits(const unsigned char hash[32]);

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
static int kc_p2p_solve_register_pow(const char *pass, const char *nonce_hex,
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
        kc_p2p_hash_register_once(pass, nonce_hex, id, buf, hash);
        if (kc_p2p_count_leading_zero_bits(hash) >= bits) {
            memcpy(solution_hex, buf, sizeof(buf));
            return kc_p2p_hex_encode(hash, sizeof(hash), proof_hex, proof_cap);
        }
        counter++;
        if (counter == 0) break;
        if ((counter & 0xfffff) == 0 && kc_p2p_stop_requested) break;
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
static int kc_p2p_verify_register_pow(const char *pass, const char *nonce_hex,
    const char *id, const char *solution_hex, const char *proof_hex, int bits)
{
    unsigned char hash[32];
    char expected[65];

    if (!proof_hex || strlen(proof_hex) != 64) return 0;
    kc_p2p_hash_register_once(pass, nonce_hex, id, solution_hex, hash);
    if (!kc_p2p_hex_encode(hash, sizeof(hash), expected, sizeof(expected))) return 0;
    if (strcmp(proof_hex, expected) != 0) return 0;
    return kc_p2p_count_leading_zero_bits(hash) >= bits;
}

/**
 * Counts leading zero bits in one digest.
 * @param hash Input digest bytes.
 * @return Count of leading zero bits.
 */
static int kc_p2p_count_leading_zero_bits(const unsigned char hash[32]) {
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
    kc_p2p_fd_t fd;
    char buf[KC_P2P_BUF];
    int buf_len;
    char id[KC_P2P_ID_MAX + 1];
    int registered;
    int hello_ok;
} kc_p2p_tcp_conn_t;

typedef struct {
    char id[KC_P2P_ID_MAX + 1];
    char pass[KC_P2P_PASS_MAX + 1];
} kc_p2p_vip_entry_t;

/**
 * Pending punch.
 * Summary: Tracks a two-round punch request awaiting ACK2 from publisher.
 */
typedef struct {
    char self_id[KC_P2P_ID_MAX + 1];
    char target_id[KC_P2P_ID_MAX + 1];
    char sess_id[64];
    kc_p2p_fd_t consumer_fd;
    uint64_t ts;
} kc_p2p_pending_punch_t;

struct kc_p2p {
    kc_p2p_signal_entry_t *signal_entries;
    int signal_count;
    int signal_capacity;
    kc_p2p_peer_t *peers;
    int n_peers;
    int peers_alloc;
    int n_peers_cap;
    int nonvip_cap;
    kc_p2p_tcp_conn_t *conns;
    int n_conns;
    int conns_cap;
    kc_p2p_vip_entry_t *vips;
    int n_vips;
    int vips_cap;
    char key[KC_P2P_KEY_STR_SZ];
    char pass[KC_P2P_PASS_MAX + 1];
    int pow_bits;
    unsigned short bind_port;
    int proto;
    int sweep;
    kc_p2p_pow_challenge_t pow_challenges[KC_P2P_POW_CHALLENGES_MAX];
    int n_pow_challenges;
#ifdef _WIN32
    CRITICAL_SECTION mutex;
#else
    pthread_mutex_t mutex;
#endif
    char stun_url[512];
    kc_p2p_pending_punch_t pending_punches[KC_P2P_MAX_PENDING_PUNCHES];
    int n_pending_punches;
};

typedef struct kc_p2p_udp_consumer_session {
    kc_p2p_fd_t fd;
    kc_p2p_fd_t tcp_fd;
    struct sockaddr_storage client_addr;
    struct sockaddr_storage peer_addr;
    uint64_t last_rx;
    uint64_t last_ka;
    int active;
    int is_tcp;
    kc_p2p_stream_state_t stream;
} kc_p2p_udp_consumer_session_t;

typedef struct kc_p2p_udp_server_session {
    kc_p2p_fd_t backend_fd;
    kc_p2p_fd_t tcp_fd;
    struct sockaddr_storage peer_addr;
    uint64_t last_rx;
    uint64_t last_ka;
    int active;
    int is_tcp;
    kc_p2p_stream_state_t stream;
} kc_p2p_udp_server_session_t;

#ifdef _WIN32
typedef HANDLE kc_p2p_thread_t;
#define KC_P2P_THREAD_RET unsigned __stdcall
#else
typedef pthread_t kc_p2p_thread_t;
#define KC_P2P_THREAD_RET void *
#endif

static int kc_p2p_sock_read(kc_p2p_fd_t fd, char *buf, int len);
static int kc_p2p_write_all(kc_p2p_fd_t fd, const char *buf, int len);
static void kc_p2p_shutdown_write(kc_p2p_fd_t fd);
static socklen_t kc_p2p_sockaddr_len(const struct sockaddr_storage *addr);
static int kc_p2p_candidate_sockaddr(const kc_p2p_candidate_t *candidate,
    struct sockaddr_storage *out);
static int kc_p2p_is_space(char ch);
static char *kc_p2p_trim(char *text);
static int kc_p2p_find_vip(kc_p2p_t *ctx, const char *id);
static int kc_p2p_add_vip(kc_p2p_t *ctx, const char *id, const char *pass,
    char *err, size_t err_cap);
static const char *kc_p2p_get_register_pass(kc_p2p_t *ctx, const char *id);
static uint32_t kc_p2p_load_u32_le(const unsigned char *p);

/**
 * Reports whether detailed stream logs are enabled.
 * @return 1 when stream debug logging is enabled, 0 otherwise.
 */
static int kc_p2p_stream_debug_enabled(void) {
    static int loaded = 0;
    static int enabled = 0;
    const char *env;

    if (loaded) return enabled;
    env = getenv("P2P_DEBUG_STREAM");
    enabled = env && env[0] != '\0' && strcmp(env, "0") != 0;
    loaded = 1;
    return enabled;
}

/**
 * Emits one conditional debug log line for stream internals.
 * @return None.
 */
static void kc_p2p_stream_log(const char *fmt, ...) {
    va_list ap;

    if (!kc_p2p_stream_debug_enabled()) return;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}

/**
 * Returns the configured debug drop cadence for TCP stream DATA frames.
 * @return Drop cadence, or 0 when disabled.
 */
static int kc_p2p_stream_debug_drop_every(void) {
    static int loaded = 0;
    static int every = 0;
    const char *env;

    if (loaded) return every;
    env = getenv("P2P_DEBUG_STREAM_DROP_EVERY");
    if (env && env[0] != '\0') every = atoi(env);
    if (every < 0) every = 0;
    loaded = 1;
    return every;
}

/**
 * Returns the configured debug reorder cadence for TCP DATA frames.
 * @return Reorder cadence, or 0 when disabled.
 */
static int kc_p2p_stream_debug_reorder_every(void) {
    static int loaded = 0;
    static int every = 0;
    const char *env;

    if (loaded) return every;
    env = getenv("P2P_DEBUG_STREAM_REORDER_EVERY");
    if (env && env[0] != '\0') every = atoi(env);
    if (every < 0) every = 0;
    loaded = 1;
    return every;
}

/**
 * Decides whether to drop one outgoing DATA frame once for testing.
 * @return 1 when the frame should be dropped, 0 otherwise.
 */
static int kc_p2p_stream_should_drop_once(const unsigned char *buf, size_t len) {
    static int counter = 0;
    static kc_p2p_stream_drop_record_t dropped[256];
    int every;
    uint8_t type;
    uint32_t seq;
    int i;
    int free_slot;

    every = kc_p2p_stream_debug_drop_every();
    if (every <= 0 || len < 44) return 0;
    if (kc_p2p_load_u32_le(buf) != KC_P2P_STREAM_MAGIC) return 0;
    if (buf[4] != KC_P2P_STREAM_VERSION) return 0;
    type = buf[5];
    if (type != KC_P2P_STREAM_TYPE_DATA) return 0;
    seq = kc_p2p_load_u32_le(buf + 24);
    free_slot = -1;
    for (i = 0; i < 256; i++) {
        if (!dropped[i].used) {
            if (free_slot < 0) free_slot = i;
            continue;
        }
        if (dropped[i].seq == seq &&
            memcmp(dropped[i].session_id, buf + 8,
                KC_P2P_STREAM_SESSION_ID_SZ) == 0)
            return 0;
    }
    counter++;
    if ((counter % every) != 0) return 0;
    if (free_slot < 0) free_slot = counter % 256;
    dropped[free_slot].used = 1;
    dropped[free_slot].seq = seq;
    memcpy(dropped[free_slot].session_id, buf + 8,
        KC_P2P_STREAM_SESSION_ID_SZ);
    kc_p2p_stream_log("p2p: stream drop-test seq=%u\n", (unsigned)seq);
    return 1;
}

/**
 * Decides whether to delay one DATA frame for reordering tests.
 * @return 1 when the frame should be delayed, 0 otherwise.
 */
static int kc_p2p_stream_should_reorder_once(const unsigned char *buf, size_t len) {
    static int counter = 0;
    static kc_p2p_stream_drop_record_t delayed[256];
    int every;
    uint8_t type;
    uint32_t seq;
    int i;
    int free_slot;

    every = kc_p2p_stream_debug_reorder_every();
    if (every <= 0 || len < 44) return 0;
    if (kc_p2p_load_u32_le(buf) != KC_P2P_STREAM_MAGIC) return 0;
    if (buf[4] != KC_P2P_STREAM_VERSION) return 0;
    type = buf[5];
    if (type != KC_P2P_STREAM_TYPE_DATA) return 0;
    seq = kc_p2p_load_u32_le(buf + 24);
    free_slot = -1;
    for (i = 0; i < 256; i++) {
        if (!delayed[i].used) {
            if (free_slot < 0) free_slot = i;
            continue;
        }
        if (delayed[i].seq == seq &&
            memcmp(delayed[i].session_id, buf + 8,
                KC_P2P_STREAM_SESSION_ID_SZ) == 0)
            return 0;
    }
    counter++;
    if ((counter % every) != 0) return 0;
    if (free_slot < 0) free_slot = counter % 256;
    delayed[free_slot].used = 1;
    delayed[free_slot].seq = seq;
    memcpy(delayed[free_slot].session_id, buf + 8,
        KC_P2P_STREAM_SESSION_ID_SZ);
    kc_p2p_stream_log("p2p: stream reorder-test seq=%u\n", (unsigned)seq);
    return 1;
}

/**
 * lock.
 * @return None.
 */

/**
 * Lock.
 * @return Status code.
 */
static void kc_p2p_lock(kc_p2p_t *ctx) {
#ifdef _WIN32
    EnterCriticalSection(&ctx->mutex);
#else
    pthread_mutex_lock(&ctx->mutex);
#endif
}

/**
 * unlock.
 * @return None.
 */

/**
 * Unlock.
 * @return Status code.
 */
static void kc_p2p_unlock(kc_p2p_t *ctx) {
#ifdef _WIN32
    LeaveCriticalSection(&ctx->mutex);
#else
    pthread_mutex_unlock(&ctx->mutex);
#endif
}

/**
 * Loads one little-endian u16.
 * @return Decoded value.
 */
static uint16_t kc_p2p_load_u16_le(const unsigned char *p) {
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

/**
 * Loads one little-endian u32.
 * @return Decoded value.
 */
static uint32_t kc_p2p_load_u32_le(const unsigned char *p) {
    return (uint32_t)p[0] |
        ((uint32_t)p[1] << 8) |
        ((uint32_t)p[2] << 16) |
        ((uint32_t)p[3] << 24);
}

/**
 * Stores one little-endian u16.
 * @return None.
 */
static void kc_p2p_store_u16_le(unsigned char *p, uint16_t v) {
    p[0] = (unsigned char)(v & 0xffu);
    p[1] = (unsigned char)((v >> 8) & 0xffu);
}

/**
 * Stores one little-endian u32.
 * @return None.
 */
static void kc_p2p_store_u32_le(unsigned char *p, uint32_t v) {
    p[0] = (unsigned char)(v & 0xffu);
    p[1] = (unsigned char)((v >> 8) & 0xffu);
    p[2] = (unsigned char)((v >> 16) & 0xffu);
    p[3] = (unsigned char)((v >> 24) & 0xffu);
}

/**
 * Returns a millisecond timestamp.
 * @return Monotonic-ish timestamp in milliseconds.
 */
static uint64_t kc_p2p_now_ms(void) {
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
static uint64_t kc_p2p_now_s(void) {
    return kc_p2p_now_ms() / 1000;
}

#ifdef KC_P2P_TEST_RANDOM
static unsigned char kc_p2p_test_random_bytes[256];
static size_t kc_p2p_test_random_len;
static size_t kc_p2p_test_random_pos;
static int kc_p2p_test_random_fail;
#endif

/**
 * Fills a buffer with secure random bytes.
 * @return 0 on success, -1 on error.
 */
static int kc_p2p_fill_random(unsigned char *buf, size_t len) {
#ifdef KC_P2P_TEST_RANDOM
    if (kc_p2p_test_random_fail) return -1;
    if (kc_p2p_test_random_len > 0) {
        size_t i;
        for (i = 0; i < len; i++) {
            buf[i] = kc_p2p_test_random_bytes[kc_p2p_test_random_pos %
                kc_p2p_test_random_len];
            kc_p2p_test_random_pos++;
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

#ifdef KC_P2P_TEST_RANDOM
/**
 * Configures deterministic random bytes for test builds.
 * @param bytes Byte stream to repeat.
 * @param len   Byte stream length.
 * @return None.
 */
void kc_p2p_test_random_set(const unsigned char *bytes, size_t len) {
    if (!bytes || len == 0) {
        kc_p2p_test_random_len = 0;
        kc_p2p_test_random_pos = 0;
        return;
    }
    if (len > sizeof(kc_p2p_test_random_bytes))
        len = sizeof(kc_p2p_test_random_bytes);
    memcpy(kc_p2p_test_random_bytes, bytes, len);
    kc_p2p_test_random_len = len;
    kc_p2p_test_random_pos = 0;
    kc_p2p_test_random_fail = 0;
}

/**
 * Configures random-source failure for test builds.
 * @param fail Non-zero forces failure.
 * @return None.
 */
void kc_p2p_test_random_set_fail(int fail) {
    kc_p2p_test_random_fail = fail ? 1 : 0;
}
#endif

/**
 * Decodes one hex nibble.
 * @return Nibble value, or -1 on error.
 */
static int kc_p2p_hex_decode_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/**
 * Decodes a fixed-size hex string.
 * @return 1 on success, 0 on error.
 */
static int kc_p2p_hex_decode(const char *hex, unsigned char *out, size_t out_len) {
    size_t i;

    if (!hex || !out) return 0;
    for (i = 0; i < out_len; i++) {
        int hi = kc_p2p_hex_decode_nibble(hex[i * 2]);
        int lo = kc_p2p_hex_decode_nibble(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return 0;
        out[i] = (unsigned char)((hi << 4) | lo);
    }
    return 1;
}

/**
 * Generates one secure stream session identifier.
 * @return 1 on success, 0 on error.
 */
static int kc_p2p_stream_make_session_id(unsigned char out[KC_P2P_STREAM_SESSION_ID_SZ],
    char hex[KC_P2P_STREAM_SESSION_ID_SZ * 2 + 1])
{
    if (kc_p2p_fill_random(out, KC_P2P_STREAM_SESSION_ID_SZ) != 0) return 0;
    return kc_p2p_hex_encode(out, KC_P2P_STREAM_SESSION_ID_SZ, hex,
        KC_P2P_STREAM_SESSION_ID_SZ * 2 + 1);
}

/**
 * Builds one AEAD nonce from session direction and sequence.
 * @return None.
 */
static void kc_p2p_stream_nonce(unsigned char nonce[KC_P2P_STREAM_NONCE_SZ],
    const unsigned char session_id[KC_P2P_STREAM_SESSION_ID_SZ],
    uint8_t direction, uint32_t seq)
{
    memset(nonce, 0, KC_P2P_STREAM_NONCE_SZ);
    memcpy(nonce, session_id, KC_P2P_STREAM_SESSION_ID_SZ);
    nonce[16] = direction;
    kc_p2p_store_u32_le(nonce + 20, seq);
}

/**
 * Reports the currently advertised receive window.
 * @return Available receive slots.
 */
static uint16_t kc_p2p_stream_advertised_window(const kc_p2p_stream_state_t *st) {
    int used = 0;
    int i;

    for (i = 0; i < KC_P2P_STREAM_RECV_WINDOW; i++) {
        if (st->in.slots[i].used) used++;
    }
    if (used >= KC_P2P_STREAM_RECV_WINDOW) return 0;
    return (uint16_t)(KC_P2P_STREAM_RECV_WINDOW - used);
}

/**
 * Initializes one TCP stream state block.
 * @return None.
 */
static void kc_p2p_stream_init(kc_p2p_stream_state_t *st, int initiator,
    const unsigned char session_id[KC_P2P_STREAM_SESSION_ID_SZ],
    const char *session_hex)
{
    memset(st, 0, sizeof(*st));
    st->enabled = 1;
    st->initiator = initiator;
    st->tx_direction = initiator ? KC_P2P_STREAM_DIR_C2S : KC_P2P_STREAM_DIR_S2C;
    st->rx_direction = initiator ? KC_P2P_STREAM_DIR_S2C : KC_P2P_STREAM_DIR_C2S;
    st->ctrl_seq = 1;
    memcpy(st->session_id, session_id, KC_P2P_STREAM_SESSION_ID_SZ);
    if (session_hex) {
        memcpy(st->session_hex, session_hex,
            KC_P2P_STREAM_SESSION_ID_SZ * 2);
        st->session_hex[KC_P2P_STREAM_SESSION_ID_SZ * 2] = '\0';
    }
    st->out.next_seq = 1;
    st->in.next_expected = 1;
    st->last_rx_ms = kc_p2p_now_ms();
    st->last_tx_ms = st->last_rx_ms;
    st->last_ack_ms = st->last_rx_ms;
    st->last_hello_ms = 0;
}

/**
 * Sends one raw packet over the selected transport.
 * @return 0 on success, -1 on error.
 */
static int kc_p2p_stream_send_raw(kc_p2p_t *ctx, kc_p2p_fd_t fd,
    const struct sockaddr_storage *peer_addr, const unsigned char *buf, size_t len)
{
    static kc_p2p_stream_pending_frame_t pending;
    socklen_t peer_len;

    (void)ctx;
    if (len > KC_P2P_STREAM_MAX_FRAME) return -1;
    peer_len = kc_p2p_sockaddr_len(peer_addr);
    if (peer_len == 0) return -1;

    if (kc_p2p_stream_should_drop_once(buf, len)) return 0;
    if (!pending.used && kc_p2p_stream_should_reorder_once(buf, len)) {
        pending.used = 1;
        pending.len = len;
        memcpy(pending.frame, buf, len);
        return 0;
    }
    if (sendto(fd, (const char *)buf, len, 0,
        (const struct sockaddr *)peer_addr, peer_len) < 0)
        return -1;
    if (pending.used) {
        if (sendto(fd, (const char *)pending.frame, pending.len, 0,
            (const struct sockaddr *)peer_addr, peer_len) < 0)
            return -1;
        pending.used = 0;
    }
    return 0;
}

/**
 * Builds transcript input for session key derivation.
 * @return None.
 */
static void kc_p2p_stream_build_kdf_input(unsigned char *buf, size_t *len,
    const kc_p2p_stream_state_t *st)
{
    const unsigned char *init_pub;
    const unsigned char *resp_pub;
    const unsigned char *init_nonce;
    const unsigned char *resp_nonce;

    init_pub = st->initiator ? st->crypto.local_public : st->crypto.peer_public;
    resp_pub = st->initiator ? st->crypto.peer_public : st->crypto.local_public;
    init_nonce = st->initiator ? st->crypto.local_nonce : st->crypto.peer_nonce;
    resp_nonce = st->initiator ? st->crypto.peer_nonce : st->crypto.local_nonce;

    memcpy(buf, st->session_id, KC_P2P_STREAM_SESSION_ID_SZ);
    memcpy(buf + 16, init_pub, 32);
    memcpy(buf + 48, resp_pub, 32);
    memcpy(buf + 80, init_nonce, KC_P2P_STREAM_HELLO_NONCE_SZ);
    memcpy(buf + 96, resp_nonce, KC_P2P_STREAM_HELLO_NONCE_SZ);
    *len = 112;
}

/**
 * Derives one directional key from shared secret material.
 * @return None.
 */
static void kc_p2p_stream_derive_key(unsigned char out[32], const unsigned char shared[32],
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
static int kc_p2p_stream_crypto_ready(kc_p2p_stream_state_t *st) {
    unsigned char shared[32];
    unsigned char kdf[112];
    size_t kdf_len;

    if (st->crypto.ready) return 1;
    if (st->crypto.peer_public[0] == 0 &&
        memcmp(st->crypto.peer_public, (unsigned char[32]){0}, 32) == 0)
        return 0;
    if (crypto_verify32(st->crypto.local_public, st->crypto.peer_public) == 0)
        return 0;
    crypto_x25519(shared, st->crypto.local_secret, st->crypto.peer_public);
    kc_p2p_stream_build_kdf_input(kdf, &kdf_len, st);
    if (st->initiator) {
        kc_p2p_stream_derive_key(st->crypto.tx_key, shared, kdf, kdf_len, "c2s");
        kc_p2p_stream_derive_key(st->crypto.rx_key, shared, kdf, kdf_len, "s2c");
    } else {
        kc_p2p_stream_derive_key(st->crypto.tx_key, shared, kdf, kdf_len, "s2c");
        kc_p2p_stream_derive_key(st->crypto.rx_key, shared, kdf, kdf_len, "c2s");
    }
    st->crypto.ready = 1;
    st->ready = 1;
    kc_p2p_stream_log("p2p: tcp session %s stream ready\n", st->session_hex);
    crypto_wipe(shared, sizeof(shared));
    crypto_wipe(kdf, sizeof(kdf));
    return 1;
}

/**
 * Generates local ephemeral keys and hello nonce.
 * @return 1 on success, 0 on error.
 */
static int kc_p2p_stream_crypto_init(kc_p2p_stream_state_t *st) {
    if (kc_p2p_fill_random(st->crypto.local_secret, 32) != 0) return 0;
    if (kc_p2p_fill_random(st->crypto.local_nonce,
        KC_P2P_STREAM_HELLO_NONCE_SZ) != 0) return 0;
    crypto_x25519_public_key(st->crypto.local_public, st->crypto.local_secret);
    return 1;
}

/**
 * Counts currently unacknowledged reliable frames.
 * @return In-flight frame count.
 */
static int kc_p2p_stream_inflight(const kc_p2p_stream_state_t *st) {
    int i;
    int n = 0;
    for (i = 0; i < KC_P2P_STREAM_SEND_WINDOW; i++) {
        if (st->out.slots[i].used) n++;
    }
    return n;
}

/**
 * Reports whether the local TCP side may queue more data.
 * @return 1 when more data may be read, 0 otherwise.
 */
static int kc_p2p_stream_can_send_data(const kc_p2p_stream_state_t *st) {
    return st->ready && !st->out.local_eof &&
        kc_p2p_stream_inflight(st) < KC_P2P_STREAM_SEND_WINDOW;
}

/**
 * Packs one plaintext hello frame.
 * @return Encoded byte length.
 */
static size_t kc_p2p_stream_pack_hello(uint8_t type, const kc_p2p_stream_state_t *st,
    unsigned char *out)
{
    kc_p2p_store_u32_le(out, KC_P2P_STREAM_MAGIC);
    out[4] = KC_P2P_STREAM_VERSION;
    out[5] = type;
    out[6] = st->tx_direction;
    out[7] = 0;
    memcpy(out + 8, st->session_id, KC_P2P_STREAM_SESSION_ID_SZ);
    memcpy(out + 24, st->crypto.local_public, 32);
    memcpy(out + 56, st->crypto.local_nonce, KC_P2P_STREAM_HELLO_NONCE_SZ);
    return 72;
}

/**
 * Parses one plaintext hello frame.
 * @return 1 on success, 0 on mismatch.
 */
static int kc_p2p_stream_unpack_hello(const unsigned char *buf, size_t len,
    uint8_t *type, uint8_t *direction,
    unsigned char session_id[KC_P2P_STREAM_SESSION_ID_SZ],
    unsigned char peer_public[32],
    unsigned char peer_nonce[KC_P2P_STREAM_HELLO_NONCE_SZ])
{
    if (len < 72) return 0;
    if (kc_p2p_load_u32_le(buf) != KC_P2P_STREAM_MAGIC) return 0;
    if (buf[4] != KC_P2P_STREAM_VERSION) return 0;
    *type = buf[5];
    *direction = buf[6];
    memcpy(session_id, buf + 8, KC_P2P_STREAM_SESSION_ID_SZ);
    memcpy(peer_public, buf + 24, 32);
    memcpy(peer_nonce, buf + 56, KC_P2P_STREAM_HELLO_NONCE_SZ);
    return 1;
}

/**
 * Encodes one authenticated stream header.
 * @return Encoded header length.
 */
static size_t kc_p2p_stream_pack_header(const kc_p2p_stream_header_t *hdr,
    unsigned char *out)
{
    kc_p2p_store_u32_le(out, KC_P2P_STREAM_MAGIC);
    out[4] = KC_P2P_STREAM_VERSION;
    out[5] = hdr->type;
    out[6] = hdr->direction;
    out[7] = 0;
    memcpy(out + 8, hdr->session_id, KC_P2P_STREAM_SESSION_ID_SZ);
    kc_p2p_store_u32_le(out + 24, hdr->seq);
    kc_p2p_store_u32_le(out + 28, hdr->ack);
    kc_p2p_store_u16_le(out + 32, hdr->window);
    kc_p2p_store_u16_le(out + 34, hdr->payload_len);
    kc_p2p_store_u32_le(out + 36, hdr->gap_start);
    kc_p2p_store_u32_le(out + 40, hdr->gap_end);
    return 44;
}

/**
 * Parses one authenticated stream header.
 * @return 1 on success, 0 on error.
 */
static int kc_p2p_stream_unpack_header(const unsigned char *buf, size_t len,
    kc_p2p_stream_header_t *hdr)
{
    if (len < 60) return 0;
    if (kc_p2p_load_u32_le(buf) != KC_P2P_STREAM_MAGIC) return 0;
    if (buf[4] != KC_P2P_STREAM_VERSION) return 0;
    hdr->type = buf[5];
    hdr->direction = buf[6];
    memcpy(hdr->session_id, buf + 8, KC_P2P_STREAM_SESSION_ID_SZ);
    hdr->seq = kc_p2p_load_u32_le(buf + 24);
    hdr->ack = kc_p2p_load_u32_le(buf + 28);
    hdr->window = kc_p2p_load_u16_le(buf + 32);
    hdr->payload_len = kc_p2p_load_u16_le(buf + 34);
    hdr->gap_start = kc_p2p_load_u32_le(buf + 36);
    hdr->gap_end = kc_p2p_load_u32_le(buf + 40);
    if ((size_t)(60 + hdr->payload_len) > len) return 0;
    return 1;
}

/**
 * Encrypts one post-handshake stream packet.
 * @return 1 on success, 0 on error.
 */
static int kc_p2p_stream_encrypt_packet(kc_p2p_stream_state_t *st,
    const kc_p2p_stream_header_t *hdr, const unsigned char *plain,
    size_t plain_len, unsigned char *out, size_t *out_len)
{
    unsigned char nonce[KC_P2P_STREAM_NONCE_SZ];
    size_t ad_len = kc_p2p_stream_pack_header(hdr, out);
    unsigned char *mac = out + ad_len;
    unsigned char *cipher = out + ad_len + KC_P2P_STREAM_TAG_SZ;

    if (ad_len + KC_P2P_STREAM_TAG_SZ + plain_len > KC_P2P_STREAM_MAX_FRAME)
        return 0;
    kc_p2p_stream_nonce(nonce, hdr->session_id, hdr->direction, hdr->seq);
    crypto_aead_lock(cipher, mac, st->crypto.tx_key, nonce, out, ad_len,
        plain, plain_len);
    *out_len = ad_len + KC_P2P_STREAM_TAG_SZ + plain_len;
    return 1;
}

/**
 * Authenticates and decrypts one post-handshake stream packet.
 * @return 1 on success, 0 on authentication failure.
 */
static int kc_p2p_stream_decrypt_packet(kc_p2p_stream_state_t *st,
    const kc_p2p_stream_header_t *hdr, const unsigned char *buf,
    unsigned char *plain)
{
    unsigned char nonce[KC_P2P_STREAM_NONCE_SZ];
    size_t ad_len = 44;
    const unsigned char *mac = buf + ad_len;
    const unsigned char *cipher = buf + ad_len + KC_P2P_STREAM_TAG_SZ;

    kc_p2p_stream_nonce(nonce, hdr->session_id, hdr->direction, hdr->seq);
    return crypto_aead_unlock(plain, mac, st->crypto.rx_key, nonce, buf,
        ad_len, cipher, hdr->payload_len) == 0;
}

/**
 * Finds one receive slot by sequence number.
 * @return Matching slot, or NULL.
 */
static kc_p2p_stream_recv_slot_t *kc_p2p_stream_find_recv_slot(
    kc_p2p_stream_state_t *st, uint32_t seq)
{
    int i;
    for (i = 0; i < KC_P2P_STREAM_RECV_WINDOW; i++) {
        if (st->in.slots[i].used && st->in.slots[i].seq == seq)
            return &st->in.slots[i];
    }
    return NULL;
}

/**
 * Allocates one free receive slot.
 * @return Free slot, or NULL.
 */
static kc_p2p_stream_recv_slot_t *kc_p2p_stream_alloc_recv_slot(
    kc_p2p_stream_state_t *st)
{
    int i;
    for (i = 0; i < KC_P2P_STREAM_RECV_WINDOW; i++) {
        if (!st->in.slots[i].used) return &st->in.slots[i];
    }
    return NULL;
}

/**
 * Allocates one free resend slot.
 * @return Free slot, or NULL.
 */
static kc_p2p_stream_send_slot_t *kc_p2p_stream_alloc_send_slot(
    kc_p2p_stream_state_t *st)
{
    int i;
    for (i = 0; i < KC_P2P_STREAM_SEND_WINDOW; i++) {
        if (!st->out.slots[i].used) return &st->out.slots[i];
    }
    return NULL;
}

/**
 * Drops all resend slots covered by a cumulative ACK.
 * @return None.
 */
static void kc_p2p_stream_ack_until(kc_p2p_stream_state_t *st, uint32_t ack) {
    int i;
    for (i = 0; i < KC_P2P_STREAM_SEND_WINDOW; i++) {
        if (st->out.slots[i].used && st->out.slots[i].seq <= ack) {
            if (st->out.slots[i].type == KC_P2P_STREAM_TYPE_FIN)
                st->out.fin_acked = 1;
            st->out.slots[i].used = 0;
        }
    }
}

/**
 * Sends one encrypted control frame.
 * @return 0 on success, -1 on error.
 */
static int kc_p2p_stream_send_control(kc_p2p_t *ctx, kc_p2p_fd_t fd,
    const struct sockaddr_storage *peer_addr,
    kc_p2p_stream_state_t *st, uint8_t type, uint32_t seq,
    uint32_t gap_start, uint32_t gap_end)
{
    kc_p2p_stream_header_t hdr;
    unsigned char frame[KC_P2P_STREAM_MAX_FRAME];
    size_t frame_len;

    memset(&hdr, 0, sizeof(hdr));
    hdr.type = type;
    hdr.direction = st->tx_direction;
    hdr.seq = seq ? seq : st->ctrl_seq++;
    hdr.ack = st->in.next_expected ? st->in.next_expected - 1 : 0;
    hdr.window = kc_p2p_stream_advertised_window(st);
    hdr.payload_len = 0;
    hdr.gap_start = gap_start;
    hdr.gap_end = gap_end;
    memcpy(hdr.session_id, st->session_id, KC_P2P_STREAM_SESSION_ID_SZ);

    if (!kc_p2p_stream_encrypt_packet(st, &hdr, NULL, 0, frame, &frame_len))
        return -1;
    if (kc_p2p_stream_send_raw(ctx, fd, peer_addr, frame, frame_len) != 0)
        return -1;
    st->last_tx_ms = kc_p2p_now_ms();
    st->last_ack_ms = st->last_tx_ms;
    return 0;
}

/**
 * Sends one plaintext hello or hello-ack frame.
 * @return 0 on success, -1 on error.
 */
static int kc_p2p_stream_send_hello(kc_p2p_t *ctx, kc_p2p_fd_t fd,
    const struct sockaddr_storage *peer_addr,
    kc_p2p_stream_state_t *st, uint8_t type)
{
    unsigned char frame[96];
    size_t frame_len;

    frame_len = kc_p2p_stream_pack_hello(type, st, frame);
    if (kc_p2p_stream_send_raw(ctx, fd, peer_addr, frame, frame_len) != 0)
        return -1;
    st->hello_sent = 1;
    st->last_hello_ms = kc_p2p_now_ms();
    st->last_tx_ms = st->last_hello_ms;
    return 0;
}

/**
 * Queues and transmits one reliable DATA or FIN frame.
 * @return 0 on success, -1 on error.
 */
static int kc_p2p_stream_queue_reliable(kc_p2p_t *ctx, kc_p2p_fd_t fd,
    const struct sockaddr_storage *peer_addr,
    kc_p2p_stream_state_t *st, uint8_t type,
    const unsigned char *plain, size_t plain_len)
{
    kc_p2p_stream_send_slot_t *slot;
    kc_p2p_stream_header_t hdr;
    size_t frame_len;

    if (plain_len > KC_P2P_STREAM_MAX_PAYLOAD) return -1;
    slot = kc_p2p_stream_alloc_send_slot(st);
    if (!slot) return -1;

    memset(&hdr, 0, sizeof(hdr));
    hdr.type = type;
    hdr.direction = st->tx_direction;
    hdr.seq = st->out.next_seq++;
    hdr.ack = st->in.next_expected ? st->in.next_expected - 1 : 0;
    hdr.window = kc_p2p_stream_advertised_window(st);
    hdr.payload_len = (uint16_t)plain_len;
    memcpy(hdr.session_id, st->session_id, KC_P2P_STREAM_SESSION_ID_SZ);

    if (!kc_p2p_stream_encrypt_packet(st, &hdr, plain, plain_len,
        slot->frame, &frame_len))
        return -1;
    slot->used = 1;
    slot->type = type;
    slot->seq = hdr.seq;
    slot->attempts = 1;
    slot->frame_len = frame_len;
    slot->last_tx_ms = kc_p2p_now_ms();

    if (kc_p2p_stream_send_raw(ctx, fd, peer_addr, slot->frame,
        slot->frame_len) != 0) {
        slot->used = 0;
        return -1;
    }
    st->last_tx_ms = slot->last_tx_ms;
    if (type == KC_P2P_STREAM_TYPE_FIN) st->out.fin_sent = 1;
    return 0;
}

/**
 * Delivers newly contiguous inbound data to the local TCP socket.
 * @return 0 on success, -1 on error.
 */
static int kc_p2p_stream_flush_contiguous(kc_p2p_stream_state_t *st,
    kc_p2p_fd_t tcp_fd)
{
    for (;;) {
        kc_p2p_stream_recv_slot_t *slot =
            kc_p2p_stream_find_recv_slot(st, st->in.next_expected);
        if (!slot) break;
        if (slot->type == KC_P2P_STREAM_TYPE_FIN) {
            st->in.remote_fin = 1;
            st->in.next_expected++;
            slot->used = 0;
            kc_p2p_shutdown_write(tcp_fd);
            continue;
        }
        if (slot->len > 0 && kc_p2p_write_all(tcp_fd,
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
static int kc_p2p_stream_store_inbound(kc_p2p_stream_state_t *st,
    uint8_t type, uint32_t seq, const unsigned char *plain, size_t plain_len)
{
    kc_p2p_stream_recv_slot_t *slot;

    if (seq < st->in.next_expected) return 0;
    if (kc_p2p_stream_find_recv_slot(st, seq)) return 0;
    slot = kc_p2p_stream_alloc_recv_slot(st);
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
static int kc_p2p_stream_note_sack(kc_p2p_t *ctx, kc_p2p_fd_t fd,
    const struct sockaddr_storage *peer_addr,
    kc_p2p_stream_state_t *st, uint32_t gap_start, uint32_t gap_end)
{
    int i;

    if (gap_start == 0 || gap_end < gap_start) return 0;
    if (gap_start >= st->out.next_seq) return 0;

    for (i = 0; i < KC_P2P_STREAM_SEND_WINDOW; i++) {
        kc_p2p_stream_send_slot_t *slot = &st->out.slots[i];
        if (!slot->used) continue;
        if (slot->seq < gap_start || slot->seq > gap_end) continue;
        if (slot->attempts >= KC_P2P_STREAM_MAX_RETRIES) continue;

        if (kc_p2p_stream_send_raw(ctx, fd, peer_addr, slot->frame,
            slot->frame_len) == 0) {
            slot->attempts++;
            slot->last_tx_ms = kc_p2p_now_ms();
            st->last_tx_ms = slot->last_tx_ms;
        }
    }
    return 0;
}

/**
 * Processes one inbound stream packet.
 * @return 0 on success, -1 on session failure.
 */
static int kc_p2p_stream_process_packet(kc_p2p_t *ctx, kc_p2p_fd_t fd,
    const struct sockaddr_storage *peer_addr,
    kc_p2p_stream_state_t *st, kc_p2p_fd_t tcp_fd,
    const unsigned char *buf, size_t len)
{
    kc_p2p_stream_header_t hdr;
    unsigned char plain[KC_P2P_STREAM_MAX_PAYLOAD];
    uint8_t hello_type;
    uint8_t hello_dir;
    unsigned char hello_sid[KC_P2P_STREAM_SESSION_ID_SZ];
    unsigned char hello_pub[32];
    unsigned char hello_nonce[KC_P2P_STREAM_HELLO_NONCE_SZ];

    if (kc_p2p_stream_unpack_hello(buf, len, &hello_type, &hello_dir,
        hello_sid, hello_pub, hello_nonce))
    {
        if ((hello_type == KC_P2P_STREAM_TYPE_HELLO ||
            hello_type == KC_P2P_STREAM_TYPE_HELLO_ACK) &&
            memcmp(hello_sid, st->session_id, KC_P2P_STREAM_SESSION_ID_SZ) == 0)
        {
            memcpy(st->crypto.peer_public, hello_pub, 32);
            memcpy(st->crypto.peer_nonce, hello_nonce,
                KC_P2P_STREAM_HELLO_NONCE_SZ);
            st->hello_acked = (hello_type == KC_P2P_STREAM_TYPE_HELLO_ACK);
            st->last_rx_ms = kc_p2p_now_ms();
            kc_p2p_stream_log("p2p: stream selected endpoint %s\n",
                st->session_hex);
            kc_p2p_stream_crypto_ready(st);
            if (hello_type == KC_P2P_STREAM_TYPE_HELLO) {
                if (kc_p2p_stream_send_hello(ctx, fd, peer_addr, st,
                    KC_P2P_STREAM_TYPE_HELLO_ACK) != 0)
                    return -1;
            }
            return 0;
        }
    }

    if (!kc_p2p_stream_unpack_header(buf, len, &hdr)) return 0;
    if (memcmp(hdr.session_id, st->session_id, KC_P2P_STREAM_SESSION_ID_SZ) != 0)
        return 0;
    if (!st->ready) return 0;
    if (hdr.direction != st->rx_direction) return 0;

    if (hdr.payload_len > KC_P2P_STREAM_MAX_PAYLOAD) return 0;
    if (len != 44 + KC_P2P_STREAM_TAG_SZ + (size_t)hdr.payload_len) return 0;
    if (hdr.type != KC_P2P_STREAM_TYPE_DATA && hdr.payload_len != 0) return 0;

    if (!kc_p2p_stream_decrypt_packet(st, &hdr, buf, plain)) return -1;

    st->last_rx_ms = kc_p2p_now_ms();
    kc_p2p_stream_ack_until(st, hdr.ack);

    if (hdr.type == KC_P2P_STREAM_TYPE_SACK) {
        if (hdr.gap_start != 0 && hdr.gap_end >= hdr.gap_start)
            return kc_p2p_stream_note_sack(ctx, fd, peer_addr, st,
                hdr.gap_start, hdr.gap_end);
        return 0;
    }
    if (hdr.type == KC_P2P_STREAM_TYPE_ACK || hdr.type == KC_P2P_STREAM_TYPE_PONG)
        return 0;
    if (hdr.type == KC_P2P_STREAM_TYPE_RESET) {
        st->reset_received = 1;
        return -1;
    }
    if (hdr.type == KC_P2P_STREAM_TYPE_PING) {
        return kc_p2p_stream_send_control(ctx, fd, peer_addr, st,
            KC_P2P_STREAM_TYPE_PONG, 0, 0, 0);
    }
    if (hdr.type != KC_P2P_STREAM_TYPE_DATA && hdr.type != KC_P2P_STREAM_TYPE_FIN)
        return 0;

    kc_p2p_stream_log("p2p: stream rx seq=%u len=%u\n", (unsigned)hdr.seq,
        (unsigned)hdr.payload_len);

    if (hdr.seq > st->in.next_expected) {
        kc_p2p_stream_log("p2p: stream gap detected expected=%u got=%u\n",
            (unsigned)st->in.next_expected, (unsigned)hdr.seq);
        if (kc_p2p_stream_store_inbound(st, hdr.type, hdr.seq, plain,
            hdr.payload_len) != 0)
            return -1;
        return kc_p2p_stream_send_control(ctx, fd, peer_addr, st,
            KC_P2P_STREAM_TYPE_SACK, 0,
            st->in.next_expected, hdr.seq - 1);
    }
    if (hdr.seq < st->in.next_expected) {
        return kc_p2p_stream_send_control(ctx, fd, peer_addr, st,
            KC_P2P_STREAM_TYPE_ACK, 0, 0, 0);
    }

    if (kc_p2p_stream_store_inbound(st, hdr.type, hdr.seq, plain,
        hdr.payload_len) != 0)
        return -1;
    if (kc_p2p_stream_flush_contiguous(st, tcp_fd) != 0) return -1;
    if (hdr.type == KC_P2P_STREAM_TYPE_FIN) {
        if (kc_p2p_stream_send_control(ctx, fd, peer_addr, st,
            KC_P2P_STREAM_TYPE_FIN_ACK, 0,
            0, 0) != 0)
            return -1;
        st->in.remote_fin_acked = 1;
    } else if (kc_p2p_now_ms() - st->last_ack_ms >= KC_P2P_STREAM_ACK_MS) {
        if (kc_p2p_stream_send_control(ctx, fd, peer_addr, st,
            KC_P2P_STREAM_TYPE_ACK, 0,
            0, 0) != 0)
            return -1;
    }
    return 0;
}

/**
 * Reads one local TCP chunk and queues it for reliable transport.
 * @return 0 on success, -1 on session failure.
 */
static int kc_p2p_stream_pump_tcp(kc_p2p_t *ctx, kc_p2p_fd_t fd,
    const struct sockaddr_storage *peer_addr,
    kc_p2p_stream_state_t *st, kc_p2p_fd_t tcp_fd)
{
    unsigned char buf[KC_P2P_STREAM_MAX_PAYLOAD];
    int n;

    if (!kc_p2p_stream_can_send_data(st)) return 0;
    {
        int has_rexmit = 0, j;
        for (j = 0; j < KC_P2P_STREAM_SEND_WINDOW; j++) {
            if (st->out.slots[j].used && st->out.slots[j].attempts > 2) {
                has_rexmit = 1;
                break;
            }
        }
        if (has_rexmit && kc_p2p_stream_inflight(st) >= KC_P2P_STREAM_SEND_WINDOW / 2)
            return 0;
    }
    n = kc_p2p_sock_read(tcp_fd, (char *)buf, (int)sizeof(buf));
    if (n < 0) {
        if (KC_P2P_LASTERR() == KC_P2P_EWOULD) return 0;
        return -1;
    }
    if (n == 0) {
        st->out.local_eof = 1;
        if (!st->out.fin_sent)
            return kc_p2p_stream_queue_reliable(ctx, fd, peer_addr, st,
                KC_P2P_STREAM_TYPE_FIN,
                NULL, 0);
        return 0;
    }
    kc_p2p_stream_log("p2p: stream tx seq=%u len=%d\n",
        (unsigned)st->out.next_seq, n);
    return kc_p2p_stream_queue_reliable(ctx, fd, peer_addr, st,
        KC_P2P_STREAM_TYPE_DATA, buf,
        (size_t)n);
}

/**
 * Advances timers, handshakes, ACKs, and retransmissions.
 * @return 0 on success, -1 on timeout or transport error.
 */
static int kc_p2p_stream_tick(kc_p2p_t *ctx, kc_p2p_fd_t fd,
    const struct sockaddr_storage *peer_addr,
    kc_p2p_stream_state_t *st)
{
    uint64_t now = kc_p2p_now_ms();
    int i;
    int burst = 0;

    if (!st->enabled) return 0;
    if (!st->hello_sent || (!st->ready && now - st->last_hello_ms >= KC_P2P_STREAM_HELLO_MS)) {
        return kc_p2p_stream_send_hello(ctx, fd, peer_addr, st,
            KC_P2P_STREAM_TYPE_HELLO);
    }

    for (i = 0; i < KC_P2P_STREAM_SEND_WINDOW && burst < KC_P2P_STREAM_MAX_BURST; i++) {
        kc_p2p_stream_send_slot_t *slot = &st->out.slots[i];
        if (!slot->used) continue;
        {
            int shift = slot->attempts > 1 ? slot->attempts - 2 : 0;
            unsigned int backoff;
            if (shift > KC_P2P_STREAM_RTO_BACKOFF_SHIFT)
                shift = KC_P2P_STREAM_RTO_BACKOFF_SHIFT;
            backoff = 1u << shift;
            if (now - slot->last_tx_ms < KC_P2P_STREAM_RTO_MS * backoff)
                continue;
        }
        if (slot->attempts >= KC_P2P_STREAM_MAX_RETRIES) {
            kc_p2p_stream_log("p2p: stream retransmit exhausted seq=%u\n",
                (unsigned)slot->seq);
            return -1;
        }
        kc_p2p_stream_log("p2p: stream retransmit seq=%u attempt=%d\n",
            (unsigned)slot->seq, slot->attempts + 1);
        if (kc_p2p_stream_send_raw(ctx, fd, peer_addr, slot->frame,
            slot->frame_len) != 0)
            return -1;
        slot->attempts++;
        slot->last_tx_ms = now;
        st->last_tx_ms = now;
        burst++;
    }

    if (st->ready && now - st->last_ack_ms >= KC_P2P_STREAM_ACK_MS) {
        if (kc_p2p_stream_send_control(ctx, fd, peer_addr, st,
            KC_P2P_STREAM_TYPE_ACK, 0,
            0, 0) != 0)
            return -1;
    }
    if (st->ready && now - st->last_rx_ms >= KC_P2P_STREAM_IDLE_MS)
        return -1;
    if (st->ready && st->out.fin_acked && !st->in.remote_fin) {
        if (now - st->last_tx_ms >= (uint64_t)KC_P2P_HALFCLOSE_S * 1000u)
            return -1;
    }
    if (st->ready && st->in.remote_fin_acked && !st->out.local_eof) {
        if (now - st->last_rx_ms >= (uint64_t)KC_P2P_HALFCLOSE_S * 1000u)
            return -1;
    }
    return 0;
}

/**
 * Reports whether one TCP stream is fully closed on both sides.
 * @return 1 when the stream may be cleaned up, 0 otherwise.
 */
static int kc_p2p_stream_is_done(const kc_p2p_stream_state_t *st) {
    return st->out.local_eof && st->out.fin_acked && st->in.remote_fin &&
        kc_p2p_stream_inflight(st) == 0;
}

/**
 * Wipes all per-session stream material.
 * @return None.
 */
static void kc_p2p_stream_wipe(kc_p2p_stream_state_t *st) {
    crypto_wipe(st, sizeof(*st));
}

/**
 * Closes one publisher-side UDP session and wipes TCP stream state.
 * @return None.
 */
static void kc_p2p_server_session_close(kc_p2p_udp_server_session_t *sess) {
    if (!sess) return;
    if (sess->backend_fd != KC_P2P_FD_INVALID) {
        KC_P2P_FD_CLOSE(sess->backend_fd);
        sess->backend_fd = KC_P2P_FD_INVALID;
    }
    if (sess->tcp_fd != KC_P2P_FD_INVALID) {
        KC_P2P_FD_CLOSE(sess->tcp_fd);
        sess->tcp_fd = KC_P2P_FD_INVALID;
    }
    if (sess->is_tcp) kc_p2p_stream_wipe(&sess->stream);
    sess->active = 0;
}

/**
 * Closes one consumer-side UDP session and wipes TCP stream state.
 * @return None.
 */
static void kc_p2p_consumer_session_close(kc_p2p_udp_consumer_session_t *sess) {
    if (!sess) return;
    if (sess->tcp_fd != KC_P2P_FD_INVALID) {
        KC_P2P_FD_CLOSE(sess->tcp_fd);
        sess->tcp_fd = KC_P2P_FD_INVALID;
    }
    if (!KC_P2P_ISERR(sess->fd)) {
        KC_P2P_FD_CLOSE(sess->fd);
        sess->fd = KC_P2P_FD_INVALID;
    }
    if (sess->is_tcp) kc_p2p_stream_wipe(&sess->stream);
    sess->active = 0;
}

/**
 * signal handler.
 * @return None.
 */

/**
 * Signal handler.
 * @return Status code.
 */
static void kc_p2p_signal_handler(int sig) {
    if (g_signal_ctx) {
        if (kc_p2p_raise_signal(g_signal_ctx, sig) > 0)
            return;
    }
    signal(sig, SIG_DFL);
    raise(sig);
}

/**
 * on signal.
 * @return 0 on success, -1 on error.
 */

/**
 * On signal.
 * @return 0 on success, -1 on error.
 */
int kc_p2p_on_signal(
    kc_p2p_t *ctx,
    int sig,
    kc_p2p_signal_callback_t cb)
{
    kc_p2p_signal_entry_t *new_entries;
    int i;

    if (!ctx) return KC_P2P_ERROR;

    if (!cb) {
        for (i = 0; i < ctx->signal_count; i++) {
            if (ctx->signal_entries[i].sig == sig) {
                ctx->signal_entries[i] =
                    ctx->signal_entries[ctx->signal_count - 1];
                ctx->signal_count--;
                return KC_P2P_OK;
            }
        }
        return KC_P2P_ENOENT;
    }

    if (ctx->signal_count >= ctx->signal_capacity) {
        int new_cap = ctx->signal_capacity
                    ? ctx->signal_capacity * 2
                    : 4;
        new_entries = (kc_p2p_signal_entry_t *)realloc(
            ctx->signal_entries,
            (size_t)new_cap * sizeof(kc_p2p_signal_entry_t));
        if (!new_entries) return KC_P2P_ERROR;
        ctx->signal_entries = new_entries;
        ctx->signal_capacity = new_cap;
    }

    ctx->signal_entries[ctx->signal_count].sig = sig;
    ctx->signal_entries[ctx->signal_count].cb = cb;
    ctx->signal_count++;
    return KC_P2P_OK;
}

/**
 * raise signal.
 * @return 0 on success, -1 on error.
 */

/**
 * Raise signal.
 * @return 0 on success, -1 on error.
 */
int kc_p2p_raise_signal(kc_p2p_t *ctx, int sig) {
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
 * listen signals.
 * @return 0 on success, -1 on error.
 */

/**
 * Listen signals.
 * @return 0 on success, -1 on error.
 */
int kc_p2p_listen_signals(kc_p2p_t *ctx) {
    if (!ctx) return KC_P2P_ERROR;
    g_signal_ctx = ctx;
    return KC_P2P_OK;
}

/**
 * listen signal.
 * @return 0 on success, -1 on error.
 */

/**
 * Listen signal.
 * @return 0 on success, -1 on error.
 */
int kc_p2p_listen_signal(kc_p2p_t *ctx, int sig_id) {
    (void)ctx;
    signal(sig_id, kc_p2p_signal_handler);
    return KC_P2P_OK;
}

/**
 * Signal listener thread entry point.
 * @return NULL.
 */
void *kc_p2p_signal_listener(void *arg) {
    (void)arg;
    return NULL;
}

#ifdef _WIN32

/**
 * platform init.
 * @return 0 on success, -1 on error.
 */

/**
 * Platform init.
 * @return 0 on success, -1 on error.
 */
int kc_p2p_platform_init(void) {
    WSADATA w;
    return WSAStartup(MAKEWORD(2, 2), &w) == 0 ? 0 : -1;
}

/**
 * platform cleanup.
 * @return None.
 */

/**
 * Platform cleanup.
 * @return None.
 */
void kc_p2p_platform_cleanup(void) { WSACleanup(); }

#else

/**
 * Platform init.
 * @return 0 on success, -1 on error.
 */
int kc_p2p_platform_init(void) { return 0; }

/**
 * platform cleanup.
 * @return None.
 */

/**
 * Platform cleanup.
 * @return None.
 */
void kc_p2p_platform_cleanup(void) {}

#endif

/**
 * Set nonblock.
 * @return 0 on success, -1 on error.
 */
int kc_p2p_set_nonblock(kc_p2p_fd_t fd) {
#ifdef _WIN32
    u_long mode = 1;
    return ioctlsocket(fd, FIONBIO, &mode) == 0 ? 0 : -1;
#else
    int flags = fcntl(fd, F_GETFL, 0);
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
#endif
}

/**
 * set block.
 * @return 0 on success, -1 on error.
 */

/**
 * Set block.
 * @return 0 on success, -1 on error.
 */
int kc_p2p_set_block(kc_p2p_fd_t fd) {
#ifdef _WIN32
    u_long mode = 0;
    return ioctlsocket(fd, FIONBIO, &mode) == 0 ? 0 : -1;
#else
    int flags = fcntl(fd, F_GETFL, 0);
    return fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
#endif
}

/**
 * resolve.
 * @return 0 on success, -1 on error.
 */

/**
 * Resolve.
 * @return 0 on success, -1 on error.
 */
int kc_p2p_resolve(
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
static socklen_t kc_p2p_sockaddr_len(const struct sockaddr_storage *addr) {
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
static unsigned short kc_p2p_sockaddr_port(
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
static int kc_p2p_sockaddr_set_port(struct sockaddr_storage *addr,
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
static int kc_p2p_sockaddr_equal(const struct sockaddr_storage *a,
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
static int kc_p2p_sendto_addr(kc_p2p_fd_t fd, const void *buf, size_t len,
    const struct sockaddr_storage *addr)
{
    socklen_t addr_len;

    addr_len = kc_p2p_sockaddr_len(addr);
    if (addr_len == 0) return -1;
    return (int)sendto(fd, buf, len, 0, (const struct sockaddr *)addr,
        addr_len);
}

/**
 * Reports whether a host string is an IPv6 literal.
 * @param host Host string.
 * @return 1 for IPv6 literals, 0 otherwise.
 */
static int kc_p2p_host_is_ipv6_literal(const char *host) {
    struct in6_addr addr;

    return host && inet_pton(AF_INET6, host, &addr) == 1;
}

/**
 * extract addr.
 * @return None.
 */

/**
 * Extract addr.
 * @return None.
 */
void kc_p2p_extract_addr(
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
 * send reply.
 * @return 0 on success, -1 on error.
 */

/**
 * Send reply.
 * @return 0 on success, -1 on error.
 */
int kc_p2p_send_reply(
    kc_p2p_fd_t fd,
    const struct sockaddr_in *to,
    socklen_t tolen,
    const char *msg)
{
    return sendto(fd, msg, strlen(msg), 0,
        (const struct sockaddr *)to, tolen) > 0
        ? KC_P2P_OK : KC_P2P_ENET;
}

/**
 * send recv.
 * @return 0 on success, -1 on error.
 */

/**
 * Send recv.
 * @return 0 on success, -1 on error.
 */
int kc_p2p_send_recv(
    kc_p2p_fd_t fd,
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

    if (kc_p2p_resolve(srv_host, srv_port, SOCK_DGRAM, &srv, &srv_len) != 0)
        return KC_P2P_ENET;

    if (sendto(fd, send_msg, strlen(send_msg), 0,
        (const struct sockaddr *)&srv, srv_len) < 0)
        return KC_P2P_ENET;

    if (!recv_buf || recv_cap == 0) return KC_P2P_OK;

    FD_ZERO(&fds);
    FD_SET(fd, &fds);
    tv.tv_sec = timeout_sec;
    tv.tv_usec = 0;

    n = select((int)(fd + 1), &fds, NULL, NULL, &tv);
    if (n <= 0) return KC_P2P_ETIMEOUT;

    srclen = sizeof(from);
    n = (int)recvfrom(fd, recv_buf, (int)(recv_cap - 1), 0,
        (struct sockaddr *)&from, &srclen);
    if (n < 0) return KC_P2P_ENET;
    recv_buf[n] = '\0';
    return KC_P2P_OK;
}

/**
 * create socket.
 * @return 0 on success, -1 on error.
 */

/**
 * Create socket.
 * @return 0 on success, -1 on error.
 */
kc_p2p_fd_t kc_p2p_create_socket(
    const char *bind_host,
    unsigned short bind_port)
{
    kc_p2p_fd_t fd;
    struct addrinfo hints;
    struct addrinfo *ai;
    struct addrinfo *it;
    char port_str[16];

    if (kc_p2p_platform_init() != 0) return KC_P2P_FD_INVALID;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_PASSIVE;

    snprintf(port_str, sizeof(port_str), "%u", (unsigned)bind_port);
    if (getaddrinfo(bind_host, port_str, &hints, &ai) != 0)
        return KC_P2P_FD_INVALID;

    fd = KC_P2P_FD_INVALID;
    for (it = ai; it; it = it->ai_next) {
        fd = socket(it->ai_family, it->ai_socktype, it->ai_protocol);
        if (KC_P2P_ISERR(fd)) continue;
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
        KC_P2P_FD_CLOSE(fd);
        fd = KC_P2P_FD_INVALID;
    }
    freeaddrinfo(ai);
    return fd;
}

/**
 * create tcp listener.
 * @return 0 on success, -1 on error.
 */

/**
 * Create tcp listener.
 * @return 0 on success, -1 on error.
 */
static kc_p2p_fd_t kc_p2p_create_tcp_listener(
    const char *bind_host,
    unsigned short bind_port)
{
    kc_p2p_fd_t fd;
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
        return KC_P2P_FD_INVALID;
    fd = KC_P2P_FD_INVALID;
    for (it = ai; it; it = it->ai_next) {
        fd = socket(it->ai_family, it->ai_socktype, it->ai_protocol);
        if (KC_P2P_ISERR(fd)) continue;
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
        KC_P2P_FD_CLOSE(fd);
        fd = KC_P2P_FD_INVALID;
    }
    freeaddrinfo(ai);
    return fd;
}

/**
 * connect local tcp.
 * @return 0 on success, -1 on error.
 */

/**
 * Connect local tcp.
 * @return 0 on success, -1 on error.
 */
static kc_p2p_fd_t kc_p2p_connect_local_tcp(unsigned short port) {
    kc_p2p_fd_t fd;
    struct sockaddr_in addr;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (KC_P2P_ISERR(fd)) return KC_P2P_FD_INVALID;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    if (connect(fd, (const struct sockaddr *)&addr, sizeof(addr)) != 0) {
        KC_P2P_FD_CLOSE(fd);
        return KC_P2P_FD_INVALID;
    }
    return fd;
}

/**
 * sock read.
 * @return 0 on success, -1 on error.
 */

/**
 * Sock read.
 * @return 0 on success, -1 on error.
 */
static int kc_p2p_sock_read(kc_p2p_fd_t fd, char *buf, int len) {
#ifdef _WIN32
    return recv(fd, buf, len, 0);
#else
    return (int)read(fd, buf, (size_t)len);
#endif
}

/**
 * sock write.
 * @return 0 on success, -1 on error.
 */

/**
 * Sock write.
 * @return 0 on success, -1 on error.
 */
static int kc_p2p_sock_write(kc_p2p_fd_t fd, const char *buf, int len) {
#ifdef _WIN32
    return send(fd, buf, len, 0);
#else
    return (int)write(fd, buf, (size_t)len);
#endif
}

/**
 * write all.
 * @return 0 on success, -1 on error.
 */

/**
 * Write all.
 * @return 0 on success, -1 on error.
 */
static int kc_p2p_write_all(kc_p2p_fd_t fd, const char *buf, int len) {
    int off;
    int n;

    off = 0;
    while (off < len) {
        n = kc_p2p_sock_write(fd, buf + off, len - off);
        if (n <= 0) return -1;
        off += n;
    }
    return 0;
}

/**
 * Shuts down the local write side of one TCP socket.
 * @return None.
 */
static void kc_p2p_shutdown_write(kc_p2p_fd_t fd) {
#ifdef _WIN32
    shutdown(fd, SD_SEND);
#else
    shutdown(fd, SHUT_WR);
#endif
}

/**
 * tcp connect.
 * @return 0 on success, -1 on error.
 */

/**
 * Tcp connect.
 * @return 0 on success, -1 on error.
 */
static kc_p2p_fd_t kc_p2p_tcp_connect(const char *host, unsigned short port) {
    kc_p2p_fd_t fd;
    struct addrinfo hints;
    struct addrinfo *ai;
    struct addrinfo *it;
    char port_str[16];

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    snprintf(port_str, sizeof(port_str), "%u", (unsigned)port);
    if (getaddrinfo(host, port_str, &hints, &ai) != 0)
        return KC_P2P_FD_INVALID;
    fd = KC_P2P_FD_INVALID;
    for (it = ai; it; it = it->ai_next) {
        fd = socket(it->ai_family, it->ai_socktype, it->ai_protocol);
        if (KC_P2P_ISERR(fd)) continue;
        if (connect(fd, it->ai_addr, (socklen_t)it->ai_addrlen) == 0)
            break;
        KC_P2P_FD_CLOSE(fd);
        fd = KC_P2P_FD_INVALID;
    }
    freeaddrinfo(ai);
    return fd;
}

/**
 * tcp send.
 * @return 0 on success, -1 on error.
 */

/**
 * Tcp send.
 * @return 0 on success, -1 on error.
 */
static int kc_p2p_tcp_send(kc_p2p_fd_t fd, const char *msg) {
    int len = (int)strlen(msg);

    if (kc_p2p_write_all(fd, msg, len) != 0) return KC_P2P_ENET;
    if (kc_p2p_write_all(fd, "\n", 1) != 0) return KC_P2P_ENET;
    return KC_P2P_OK;
}

/**
 * tcp readline.
 * @return 0 on success, -1 on error.
 */

/**
 * Tcp readline.
 * @return 0 on success, -1 on error.
 */
static int kc_p2p_tcp_readline(kc_p2p_fd_t fd, char *buf, int cap, int timeout_sec) {
    int total = 0;
    int n;
    char tmp[KC_P2P_BUF];

    if (cap < 1) return -1;

    while (total < cap - 1) {
        fd_set fds;
        struct timeval tv;

        FD_ZERO(&fds);
        FD_SET(fd, &fds);
        tv.tv_sec = (timeout_sec > 0 && total == 0) ? timeout_sec : 1;
        tv.tv_usec = 0;

        n = select(fd + 1, &fds, NULL, NULL, &tv);
        if (n <= 0) {
            if (total > 0) { buf[total] = '\0'; return total; }
            return -1;
        }

        n = kc_p2p_sock_read(fd, tmp, 1);
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
static kc_p2p_fd_t kc_p2p_control_connect(const char *index_host,
    unsigned short index_port)
{
    kc_p2p_fd_t fd;
    char reply[KC_P2P_BUF];

    fd = kc_p2p_tcp_connect(index_host, index_port);
    if (KC_P2P_ISERR(fd)) return fd;
    if (kc_p2p_tcp_send(fd, KC_P2P_CTRL_HELLO) != KC_P2P_OK ||
        kc_p2p_tcp_readline(fd, reply, (int)sizeof(reply), 5) < 0 ||
        strcmp(reply, KC_P2P_CTRL_HELLO_OK) != 0)
    {
        KC_P2P_FD_CLOSE(fd);
        return KC_P2P_FD_INVALID;
    }
    return fd;
}

/**
 * Returns whether the byte is ASCII whitespace.
 * @param ch Input byte.
 * @return 1 when whitespace, 0 otherwise.
 */
static int kc_p2p_is_space(char ch) {
    return ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r' ||
        ch == '\f' || ch == '\v';
}

/**
 * Returns whether the identifier contains only alphanumeric characters.
 * @param id Identifier to validate.
 * @return 1 when valid, 0 otherwise.
 */
int kc_p2p_is_valid_id(const char *id) {
    size_t i;

    if (!id || !id[0]) return 0;
    for (i = 0; id[i]; i++) {
        if (i >= KC_P2P_ID_MAX) return 0;
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
static int kc_p2p_is_pass_char(char ch) {
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
int kc_p2p_is_valid_pass_token(const char *pass) {
    size_t i;

    if (!pass || !pass[0]) return 0;
    for (i = 0; pass[i]; i++) {
        if (i >= KC_P2P_PASS_MAX) return 0;
        if (!kc_p2p_is_pass_char(pass[i])) return 0;
    }
    return 1;
}

/**
 * Trims leading and trailing ASCII whitespace in place.
 * @param text Mutable string buffer.
 * @return Pointer to the first non-whitespace byte.
 */
static char *kc_p2p_trim(char *text) {
    char *end;

    if (!text) return NULL;
    while (*text && kc_p2p_is_space(*text)) text++;
    end = text + strlen(text);
    while (end > text && kc_p2p_is_space(end[-1])) end--;
    *end = '\0';
    return text;
}

/**
 * Finds one VIP seat by identifier.
 * @param ctx Open context.
 * @param id Reserved seat identifier.
 * @return VIP index on success, -1 when missing.
 */
static int kc_p2p_find_vip(kc_p2p_t *ctx, const char *id) {
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
static void kc_p2p_update_nonvip_cap(kc_p2p_t *ctx) {
    if (!ctx) return;
    ctx->nonvip_cap = ctx->n_peers_cap - ctx->n_vips;
    if (ctx->nonvip_cap < 0) ctx->nonvip_cap = 0;
}

/**
 * Ensures peer storage can hold the requested number of online peers.
 * @param ctx  Open context.
 * @param need Required peer slots.
 * @return KC_P2P_OK on success, KC_P2P_ERROR on allocation failure.
 */
static int kc_p2p_ensure_peer_storage(kc_p2p_t *ctx, int need) {
    kc_p2p_peer_t *peers;
    int cap;

    if (!ctx) return KC_P2P_ERROR;
    if (need <= ctx->peers_alloc) return KC_P2P_OK;
    cap = ctx->peers_alloc > 0 ? ctx->peers_alloc : 8;
    while (cap < need) cap *= 2;
    peers = (kc_p2p_peer_t *)realloc(ctx->peers,
        (size_t)cap * sizeof(kc_p2p_peer_t));
    if (!peers) return KC_P2P_ERROR;
    ctx->peers = peers;
    ctx->peers_alloc = cap;
    return KC_P2P_OK;
}

/**
 * Counts online peers that do not have a reserved VIP seat.
 * @param ctx Open context.
 * @return Number of online non-VIP peers.
 */
static int kc_p2p_count_nonvip_peers(kc_p2p_t *ctx) {
    int i;
    int count;

    if (!ctx) return 0;
    count = 0;
    for (i = 0; i < ctx->n_peers; i++) {
        if (kc_p2p_find_vip(ctx, ctx->peers[i].id) < 0) count++;
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
 * @return KC_P2P_OK on success, KC_P2P_ERROR on validation failure.
 */
static int kc_p2p_add_vip(kc_p2p_t *ctx, const char *id, const char *pass,
    char *err, size_t err_cap)
{
    kc_p2p_vip_entry_t *vips;
    int cap;

    if (!ctx || !id || !pass) return KC_P2P_ERROR;
    if (!kc_p2p_is_valid_id(id)) {
        if (err && err_cap > 0)
            snprintf(err, err_cap, "P2P_VIP invalid id '%s'", id);
        return KC_P2P_ERROR;
    }
    if (!kc_p2p_is_valid_pass_token(pass)) {
        if (err && err_cap > 0)
            snprintf(err, err_cap, "P2P_VIP invalid password for id '%s'", id);
        return KC_P2P_ERROR;
    }
    if (kc_p2p_find_vip(ctx, id) >= 0) {
        if (err && err_cap > 0)
            snprintf(err, err_cap, "P2P_VIP redefines reserved id '%s'", id);
        return KC_P2P_ERROR;
    }
    if (ctx->n_vips >= ctx->vips_cap) {
        cap = ctx->vips_cap > 0 ? ctx->vips_cap * 2 : 8;
        vips = (kc_p2p_vip_entry_t *)realloc(ctx->vips,
            (size_t)cap * sizeof(kc_p2p_vip_entry_t));
        if (!vips) {
            if (err && err_cap > 0)
                snprintf(err, err_cap, "failed to allocate P2P_VIP table");
            return KC_P2P_ERROR;
        }
        ctx->vips = vips;
        ctx->vips_cap = cap;
    }
    strncpy(ctx->vips[ctx->n_vips].id, id, KC_P2P_ID_MAX);
    ctx->vips[ctx->n_vips].id[KC_P2P_ID_MAX] = '\0';
    strncpy(ctx->vips[ctx->n_vips].pass, pass, KC_P2P_PASS_MAX);
    ctx->vips[ctx->n_vips].pass[KC_P2P_PASS_MAX] = '\0';
    ctx->n_vips++;
    return KC_P2P_OK;
}

/**
 * Returns the registration password for one identifier.
 * @param ctx Open context.
 * @param id Service identifier.
 * @return VIP password when reserved, otherwise the global password.
 */
static const char *kc_p2p_get_register_pass(kc_p2p_t *ctx, const char *id) {
    int idx;

    if (!ctx) return "";
    idx = kc_p2p_find_vip(ctx, id);
    if (idx >= 0) return ctx->vips[idx].pass;
    return ctx->pass;
}

/**
 * open.
 * @return 0 on success, -1 on error.
 */

/**
 * Open.
 * @return 0 on success, -1 on error.
 */
int kc_p2p_open(kc_p2p_t **out) {
    kc_p2p_t *ctx;
    kc_p2p_peer_t *p;

    kc_p2p_size_check();
    if (!out) return KC_P2P_ERROR;
    ctx = (kc_p2p_t *)calloc(1, sizeof(kc_p2p_t));
    if (!ctx) return KC_P2P_ERROR;
    p = (kc_p2p_peer_t *)calloc((size_t)KC_P2P_MAX_PEERS, sizeof(kc_p2p_peer_t));
    if (!p) {
        free(ctx);
        return KC_P2P_ERROR;
    }
    ctx->peers = p;
    ctx->n_peers = 0;
    ctx->peers_alloc = KC_P2P_MAX_PEERS;
    ctx->n_peers_cap = KC_P2P_MAX_PEERS;
    ctx->nonvip_cap = KC_P2P_MAX_PEERS;
    ctx->signal_entries = NULL;
    ctx->signal_count = 0;
    ctx->signal_capacity = 0;
    ctx->pass[0] = '\0';
    ctx->pow_bits = 0;
    ctx->bind_port = KC_P2P_BIND_PORT_DEFAULT;
    ctx->proto = KC_P2P_PROTO_TCP;
    ctx->n_pow_challenges = 0;
    ctx->conns = NULL;
    ctx->n_conns = 0;
    ctx->conns_cap = 0;
    ctx->vips = NULL;
    ctx->n_vips = 0;
    ctx->vips_cap = 0;
#ifdef _WIN32
    InitializeCriticalSection(&ctx->mutex);
#else
    pthread_mutex_init(&ctx->mutex, NULL);
#endif

    *out = ctx;
    return KC_P2P_OK;
}

/**
 * close.
 * @return 0 on success, -1 on error.
 */

/**
 * Close.
 * @return 0 on success, -1 on error.
 */
int kc_p2p_close(kc_p2p_t *ctx) {
    int i;
    if (!ctx) return KC_P2P_ERROR;
    for (i = 0; i < ctx->n_conns; i++)
        KC_P2P_FD_CLOSE(ctx->conns[i].fd);
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
    return KC_P2P_OK;
}

/**
 * Return string for status code.
 * @return Status string.
 */
const char *kc_p2p_strerror(int code) {
    switch (code) {
        case KC_P2P_OK:       return "OK";
        case KC_P2P_ERROR:    return "general error";
        case KC_P2P_ENET:     return "network error";
        case KC_P2P_ENOENT:   return "peer not found";
        case KC_P2P_ETIMEOUT: return "timeout";
        case KC_P2P_EFULL:    return "peer table full";
        default:              return "unknown error";
    }
}

/**
 * Options t.
 * @return Status code.
 */
kc_p2p_options_t kc_p2p_options_default(void) {
    kc_p2p_options_t opts;
    memset(&opts, 0, sizeof(opts));
    opts.index_port = KC_P2P_PORT_DEFAULT;
    opts.pow = 0;
    opts.sweep = 20;
    return opts;
}

/**
 * options load env.
 * @return None.
 */

/**
 * Options load env.
 * @return None.
 */
void kc_p2p_options_load_env(kc_p2p_options_t *opts) {
    const char *val;
    char *colon;

    if (!opts) return;

    val = getenv("P2P_INDEX");
    if (val) {
        colon = strchr(val, ':');
        if (colon) {
            size_t len = (size_t)(colon - val);
            if (len >= sizeof(opts->index_host))
                len = sizeof(opts->index_host) - 1;
            memcpy(opts->index_host, val, len);
            opts->index_host[len] = '\0';
            opts->index_port = (unsigned short)atoi(colon + 1);
        }
    }

    val = getenv("P2P_BIND");
    if (val) {
        colon = strchr(val, ':');
        if (colon) {
            size_t len = (size_t)(colon - val);
            if (len >= sizeof(opts->bind_addr))
                len = sizeof(opts->bind_addr) - 1;
            memcpy(opts->bind_addr, val, len);
            opts->bind_addr[len] = '\0';
            opts->bind_port = (unsigned short)atoi(colon + 1);
        }
    }

    val = getenv("P2P_SEATS");
    if (val) opts->seats = atoi(val);

    val = getenv("P2P_POW");
    if (val) opts->pow = atoi(val);

    val = getenv("P2P_PASS");
    if (val) {
        strncpy(opts->pass, val, KC_P2P_PASS_MAX);
        opts->pass[KC_P2P_PASS_MAX] = '\0';
    }

    val = getenv("P2P_VIP");
    if (val) {
        size_t len = strlen(val);
        opts->vip = (char *)malloc(len + 1);
        if (opts->vip) memcpy(opts->vip, val, len + 1);
    }

    val = getenv("P2P_SWEEP");
    if (val) opts->sweep = atoi(val);

    val = getenv("P2P_STUN");
    if (val) {
        strncpy(opts->stun_url, val, sizeof(opts->stun_url) - 1);
        opts->stun_url[sizeof(opts->stun_url) - 1] = '\0';
    }

}

/**
 * options free.
 * @return None.
 */

/**
 * Options free.
 * @return None.
 */
void kc_p2p_options_free(kc_p2p_options_t *opts) {
    if (!opts) return;
    free(opts->vip);
    opts->vip = NULL;
}

/**
 * Set seats.
 * @return 0 on success, -1 on error.
 */
int kc_p2p_set_seats(kc_p2p_t *ctx, int seats) {
    int cap;
    if (!ctx) return KC_P2P_ERROR;
    cap = seats >= 0 ? seats : KC_P2P_MAX_PEERS;
    ctx->n_peers_cap = cap;
    kc_p2p_update_nonvip_cap(ctx);
    return KC_P2P_OK;
}

/**
 * set pow.
 * @return 0 on success, -1 on error.
 */

/**
 * Set pow.
 * @return 0 on success, -1 on error.
 */
int kc_p2p_set_pow(kc_p2p_t *ctx, int bits) {
    if (!ctx) return KC_P2P_ERROR;
    if (bits < 0) bits = 0;
    ctx->pow_bits = bits;
    return KC_P2P_OK;
}

/**
 * set port.
 * @return 0 on success, -1 on error.
 */

/**
 * Set port.
 * @return 0 on success, -1 on error.
 */
int kc_p2p_set_port(kc_p2p_t *ctx, unsigned short port) {
    if (!ctx) return KC_P2P_ERROR;
    ctx->bind_port = port;
    return KC_P2P_OK;
}

/**
 * set protocol.
 * @return 0 on success, -1 on error.
 */

/**
 * Set protocol.
 * @return 0 on success, -1 on error.
 */
int kc_p2p_set_protocol(kc_p2p_t *ctx, int proto) {
    if (!ctx) return KC_P2P_ERROR;
    if (proto != KC_P2P_PROTO_TCP && proto != KC_P2P_PROTO_UDP)
        return KC_P2P_ERROR;
    ctx->proto = proto;
    return KC_P2P_OK;
}

/**
 * Set sweep count.
 * @return Status code.
 */
int kc_p2p_set_sweep(kc_p2p_t *ctx, int sweep) {
    if (!ctx) return KC_P2P_ERROR;
    ctx->sweep = sweep;
    return KC_P2P_OK;
}

/**
 * Stores the shared register password.
 * @param ctx  Open context.
 * @param pass Shared password string.
 * @return 0 on success, -1 on error.
 */
int kc_p2p_set_pass(kc_p2p_t *ctx, const char *pass) {
    if (!ctx || !pass) return KC_P2P_ERROR;
    if (pass[0] && !kc_p2p_is_valid_pass_token(pass)) return KC_P2P_ERROR;
    strncpy(ctx->pass, pass, KC_P2P_PASS_MAX);
    ctx->pass[KC_P2P_PASS_MAX] = '\0';
    return KC_P2P_OK;
}

/**
 * Parses the VIP seat map from one whitespace-separated string.
 * @param ctx Open context.
 * @param vip Whitespace-separated id/pass pairs.
 * @param err Output error buffer.
 * @param err_cap Output error buffer capacity.
 * @return KC_P2P_OK on success, KC_P2P_ERROR on parse failure.
 */
int kc_p2p_set_vip(
kc_p2p_t *ctx,
const char *vip,
char *err,
size_t err_cap
)
{
    char *copy;
    char *cursor;

    if (!ctx) return KC_P2P_ERROR;
    free(ctx->vips);
    ctx->vips = NULL;
    ctx->n_vips = 0;
    ctx->vips_cap = 0;
    kc_p2p_update_nonvip_cap(ctx);
    if (!vip || !vip[0]) return KC_P2P_OK;
    copy = (char *)malloc(strlen(vip) + 1);
    if (!copy) {
        if (err && err_cap > 0)
            snprintf(err, err_cap, "failed to allocate P2P_VIP buffer");
        return KC_P2P_ERROR;
    }
    strcpy(copy, vip);
    cursor = kc_p2p_trim(copy);
    while (cursor && *cursor) {
        char *id;
        char *pass;

        id = cursor;
        while (*cursor && !kc_p2p_is_space(*cursor)) cursor++;
        if (*cursor) *cursor++ = '\0';
        while (*cursor && kc_p2p_is_space(*cursor)) cursor++;
        if (!*cursor) {
            if (err && err_cap > 0)
                snprintf(err, err_cap, "P2P_VIP has odd token count");
            free(copy);
            free(ctx->vips);
            ctx->vips = NULL;
            ctx->n_vips = 0;
            ctx->vips_cap = 0;
            kc_p2p_update_nonvip_cap(ctx);
            return KC_P2P_ERROR;
        }
        pass = cursor;
        while (*cursor && !kc_p2p_is_space(*cursor)) cursor++;
        if (*cursor) *cursor++ = '\0';
        while (*cursor && kc_p2p_is_space(*cursor)) cursor++;
        if (kc_p2p_add_vip(ctx, id, pass, err, err_cap) != KC_P2P_OK) {
            free(copy);
            free(ctx->vips);
            ctx->vips = NULL;
            ctx->n_vips = 0;
            ctx->vips_cap = 0;
            kc_p2p_update_nonvip_cap(ctx);
            return KC_P2P_ERROR;
        }
    }
    free(copy);
    kc_p2p_update_nonvip_cap(ctx);
    return KC_P2P_OK;
}

/**
 * find peer.
 * @return 0 on success, -1 on error.
 */

/**
 * Find peer.
 * @return 0 on success, -1 on error.
 */
static int kc_p2p_find_peer(kc_p2p_t *ctx, const char *id) {
    int i;
    for (i = 0; i < ctx->n_peers; i++) {
        if (strcmp(ctx->peers[i].id, id) == 0)
            return i;
    }
    return -1;
}

/**
 * evict stale.
 * @return None.
 */

/**
 * Evict stale.
 * @return Status code.
 */
static void kc_p2p_evict_stale(kc_p2p_t *ctx) {
    uint64_t now;
    int i;
    now = kc_p2p_now_s();
    for (i = ctx->n_peers - 1; i >= 0; i--) {
        if (now - ctx->peers[i].last_seen > KC_P2P_ETIMEOUT_SEC) {
            if (i < ctx->n_peers - 1) {
                memmove(&ctx->peers[i], &ctx->peers[i + 1],
                    (size_t)(ctx->n_peers - i - 1) * sizeof(ctx->peers[0]));
            }
            ctx->n_peers--;
        }
    }
}

/**
 * generate key.
 * @return None.
 */

/**
 * Generate key.
 * @return Status code.
 */
static int kc_p2p_generate_key(char *out) {
    unsigned char random_bytes[KC_P2P_KEY_SZ / 2];

    if (!out) return 0;
    if (kc_p2p_fill_random(random_bytes, sizeof(random_bytes)) != 0)
        return 0;
    return kc_p2p_hex_encode(random_bytes, sizeof(random_bytes), out,
        KC_P2P_KEY_SZ + 1);
}

/**
 * add peer.
 * @return 0 on success, -1 on error.
 */

/**
 * Add peer.
 * @return 0 on success, -1 on error.
 */
static int kc_p2p_add_peer(kc_p2p_t *ctx, const char *id)
{
    size_t id_len;
    int idx;
    int is_vip;

    idx = kc_p2p_find_peer(ctx, id);
    if (idx >= 0) {
        ctx->peers[idx].last_seen = kc_p2p_now_s();
        if (!kc_p2p_generate_key(ctx->peers[idx].key))
            return KC_P2P_ERROR;
        return KC_P2P_OK;
    }

    is_vip = kc_p2p_find_vip(ctx, id) >= 0;
    if (!is_vip && kc_p2p_count_nonvip_peers(ctx) >= ctx->nonvip_cap)
        return KC_P2P_EFULL;
    if (kc_p2p_ensure_peer_storage(ctx, ctx->n_peers + 1) != KC_P2P_OK)
        return KC_P2P_ERROR;

    id_len = strlen(id);
    if (id_len > KC_P2P_ID_MAX)
        id_len = KC_P2P_ID_MAX;
    memcpy(ctx->peers[ctx->n_peers].id, id, id_len);
    ctx->peers[ctx->n_peers].id[id_len] = '\0';

    ctx->peers[ctx->n_peers].last_seen = kc_p2p_now_s();
    if (!kc_p2p_generate_key(ctx->peers[ctx->n_peers].key))
        return KC_P2P_ERROR;
    ctx->n_peers++;
    return KC_P2P_OK;
}

/**
 * remove peer.
 * @return 0 on success, -1 on error.
 */

/**
 * Remove peer.
 * @return 0 on success, -1 on error.
 */
static int kc_p2p_remove_peer(kc_p2p_t *ctx, const char *id) {
    int idx;
    idx = kc_p2p_find_peer(ctx, id);
    if (idx < 0) return KC_P2P_ENOENT;
    if (idx < ctx->n_peers - 1) {
        memmove(&ctx->peers[idx], &ctx->peers[idx + 1],
            (size_t)(ctx->n_peers - idx - 1) * sizeof(ctx->peers[0]));
    }
    ctx->n_peers--;
    return KC_P2P_OK;
}

/**
 * Refreshes one existing peer entry.
 * @param ctx  Open context.
 * @param id   Peer identifier.
 * @param addr Peer address.
 * @param port Peer port.
 * @return 0 on success, -1 on error.
 */
static int kc_p2p_refresh_peer(kc_p2p_t *ctx, const char *id)
{
    int idx;

    idx = kc_p2p_find_peer(ctx, id);
    if (idx < 0) return KC_P2P_ENOENT;
    ctx->peers[idx].last_seen = kc_p2p_now_s();
    return KC_P2P_OK;
}

/**
 * Finds one pending register challenge.
 * @param ctx     Open context.
 * @param peer_sa Remote peer address.
 * @return Challenge index on success, -1 on failure.
 */
static int kc_p2p_find_pow_challenge(kc_p2p_t *ctx,
    const struct sockaddr_storage *peer_sa)
{
    int i;

    for (i = 0; i < ctx->n_pow_challenges; i++) {
        if (kc_p2p_sockaddr_equal(&ctx->pow_challenges[i].addr, peer_sa))
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
static void kc_p2p_remove_pow_challenge(kc_p2p_t *ctx, int idx) {
    if (!ctx || idx < 0 || idx >= ctx->n_pow_challenges) return;
    if (idx < ctx->n_pow_challenges - 1)
        ctx->pow_challenges[idx] = ctx->pow_challenges[ctx->n_pow_challenges - 1];
    ctx->n_pow_challenges--;
}

/**
 * Stores one pending register challenge.
 * @param ctx       Open context.
 * @param peer_sa   Remote peer address.
 * @param id        Challenged service identifier.
 * @param nonce_hex Challenge nonce in hex.
 * @return 1 on success, 0 on failure.
 */
static int kc_p2p_store_pow_challenge(kc_p2p_t *ctx,
    const struct sockaddr_storage *peer_sa, const char *id, const char *nonce_hex)
{
    int idx;
    size_t id_len;
    size_t nonce_len;

    idx = kc_p2p_find_pow_challenge(ctx, peer_sa);
    if (idx < 0) {
        if (ctx->n_pow_challenges >= KC_P2P_POW_CHALLENGES_MAX) return 0;
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
    ctx->pow_challenges[idx].id[KC_P2P_ID_MAX] = '\0';
    ctx->pow_challenges[idx].addr = *peer_sa;
    ctx->pow_challenges[idx].issued_at = kc_p2p_now_s();
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
static int kc_p2p_format_register_ok(kc_p2p_t *ctx, const char *id,
    char *reply, size_t reply_sz)
{
    int pidx;

    pidx = kc_p2p_find_peer(ctx, id);
    if (pidx < 0) return 0;
    snprintf(reply, reply_sz, "OK:KEY:%s", ctx->peers[pidx].key);
    return 1;
}

/**
 * conn add.
 * @return 0 on success, -1 on error.
 */

/**
 * Conn add.
 * @return 0 on success, -1 on error.
 */
static int kc_p2p_conn_add(kc_p2p_t *ctx, int fd) {
    if (ctx->n_conns >= ctx->conns_cap) {
        int new_cap = ctx->conns_cap == 0 ? 64 : ctx->conns_cap * 2;
        kc_p2p_tcp_conn_t *c = (kc_p2p_tcp_conn_t *)realloc(
            ctx->conns, (size_t)new_cap * sizeof(kc_p2p_tcp_conn_t));
        if (!c) return KC_P2P_ERROR;
        ctx->conns = c;
        ctx->conns_cap = new_cap;
    }
    ctx->conns[ctx->n_conns].fd = fd;
    ctx->conns[ctx->n_conns].buf_len = 0;
    ctx->conns[ctx->n_conns].id[0] = '\0';
    ctx->conns[ctx->n_conns].registered = 0;
    ctx->conns[ctx->n_conns].hello_ok = 0;
    ctx->n_conns++;
    return KC_P2P_OK;
}

/**
 * conn remove.
 * @return None.
 */

/**
 * Conn remove.
 * @return Status code.
 */
static void kc_p2p_conn_remove(kc_p2p_t *ctx, int idx) {
    if (idx < 0 || idx >= ctx->n_conns) return;
    kc_p2p_fd_t fd = ctx->conns[idx].fd;
    KC_P2P_FD_CLOSE(fd);
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
static int kc_p2p_pending_punch_find(kc_p2p_t *ctx, const char *target_id, const char *self_id, const char *sess_id) {
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
static void kc_p2p_pending_punch_remove(kc_p2p_t *ctx, int idx) {
    if (idx >= 0 && idx < ctx->n_pending_punches)
        ctx->pending_punches[idx] = ctx->pending_punches[--ctx->n_pending_punches];
}

/**
 * Pending punch evict stale.
 * @return None.
 */
static void kc_p2p_pending_punch_evict_stale(kc_p2p_t *ctx) {
    uint64_t now = kc_p2p_now_s();
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
static int kc_p2p_append_text(char *out, size_t cap, const char *text) {
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
static int kc_p2p_parse_field(const char **cursor, char *out, size_t cap,
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
static int kc_p2p_is_hex_token(const char *text, size_t len) {
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
static int kc_p2p_is_session_token(const char *text) {
    size_t i;

    if (!text || !text[0]) return 0;
    for (i = 0; text[i]; i++) {
        if (i >= KC_P2P_CTRL_SESSION_MAX) return 0;
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
static int kc_p2p_is_punch_id(const char *text) {
    size_t i;

    if (!text || !text[0]) return 0;
    for (i = 0; text[i]; i++) {
        if (i >= KC_P2P_ID_MAX) return 0;
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
static int kc_p2p_parse_port_token(const char *text, unsigned short *port) {
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
static int kc_p2p_parse_candidate_type(const char *text,
    kc_p2p_candidate_type_t *type)
{
    if (!text || !type) return 0;
    if (strcmp(text, "host") == 0) *type = KC_P2P_CAND_HOST;
    else if (strcmp(text, "lan") == 0) *type = KC_P2P_CAND_LAN;
    else if (strcmp(text, "public") == 0) *type = KC_P2P_CAND_PUBLIC;
    else if (strcmp(text, "srflx") == 0) *type = KC_P2P_CAND_SRFLX;
    else return 0;
    return 1;
}

/**
 * Returns the textual name for one local candidate type.
 * @param type Candidate type.
 * @return Candidate type name.
 */
static const char *kc_p2p_candidate_type_name(kc_p2p_candidate_type_t type) {
    if (type == KC_P2P_CAND_LAN) return "lan";
    if (type == KC_P2P_CAND_PUBLIC) return "public";
    if (type == KC_P2P_CAND_SRFLX) return "srflx";
    return "host";
}

/**
 * Returns the address family for one candidate address.
 * @param candidate Candidate to inspect.
 * @return AF_INET, AF_INET6, or AF_UNSPEC.
 */
static int kc_p2p_candidate_family(const kc_p2p_candidate_t *candidate) {
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
static unsigned int kc_p2p_candidate_priority(
    const kc_p2p_candidate_t *candidate)
{
    int family;
    unsigned int base;

    if (!candidate) return 900u;
    family = kc_p2p_candidate_family(candidate);
    if (family == AF_INET6) base = 100u;
    else if (family == AF_INET) base = 200u;
    else return 900u;
    if (candidate->type == KC_P2P_CAND_HOST) return base;
    if (candidate->type == KC_P2P_CAND_LAN) return base + 10u;
    if (candidate->type == KC_P2P_CAND_PUBLIC) return base + 20u;
    if (candidate->type == KC_P2P_CAND_SRFLX) return base + 30u;
    if (candidate->type == KC_P2P_CAND_PRFLX) return base + 40u;
    if (candidate->type == KC_P2P_CAND_PREDICTED) return base + 50u;
    return 900u;
}

/**
 * Reports whether two candidates describe the same network endpoint.
 * @param a First candidate.
 * @param b Second candidate.
 * @return 1 when equivalent, 0 otherwise.
 */
static int kc_p2p_candidate_same_endpoint(const kc_p2p_candidate_t *a,
    const kc_p2p_candidate_t *b)
{
    struct sockaddr_storage aa;
    struct sockaddr_storage bb;

    if (!a || !b || a->port != b->port) return 0;
    if (kc_p2p_candidate_family(a) != kc_p2p_candidate_family(b)) return 0;
    if (!kc_p2p_candidate_sockaddr(a, &aa)) return 0;
    if (!kc_p2p_candidate_sockaddr(b, &bb)) return 0;
    return kc_p2p_sockaddr_equal(&aa, &bb);
}

/**
 * Compares two candidates by local priority and stable textual fields.
 * @param a First candidate.
 * @param b Second candidate.
 * @return Negative, zero, or positive comparison result.
 */
static int kc_p2p_candidate_compare(const kc_p2p_candidate_t *a,
    const kc_p2p_candidate_t *b)
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
static int kc_p2p_normalize_candidates(kc_p2p_candidate_t *candidates,
    int *count)
{
    int i;
    int n;

    if (!candidates || !count || *count < 0 || *count > KC_P2P_CANDIDATES_MAX)
        return 0;
    n = 0;
    for (i = 0; i < *count; i++) {
        int j;
        if (candidates[i].port == 0) return 0;
        if (kc_p2p_candidate_family(&candidates[i]) == AF_UNSPEC) return 0;
        candidates[i].priority = kc_p2p_candidate_priority(&candidates[i]);
        if (candidates[i].priority >= 900u) return 0;
        for (j = 0; j < n; j++) {
            if (!kc_p2p_candidate_same_endpoint(&candidates[j], &candidates[i]))
                continue;
            if (kc_p2p_candidate_compare(&candidates[i], &candidates[j]) < 0)
                candidates[j] = candidates[i];
            break;
        }
        if (j == n) candidates[n++] = candidates[i];
    }
    for (i = 1; i < n; i++) {
        kc_p2p_candidate_t item = candidates[i];
        int j = i - 1;
        while (j >= 0 && kc_p2p_candidate_compare(&item, &candidates[j]) < 0) {
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
static int kc_p2p_parse_candidate_line(const char *line,
    kc_p2p_candidate_t *out)
{
    const char *cursor;
    const char *end;
    char type_text[16];
    char addr[KC_P2P_ADDR_MAX + 1];
    char port_text[8];
    struct in_addr ipv4;
    struct in6_addr ipv6;
    size_t addr_len;

    if (!line || !out || strncmp(line, "CAND:", 5) != 0) return 0;
    cursor = line + 5;
    if (!kc_p2p_parse_field(&cursor, type_text, sizeof(type_text), ':'))
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
        if (!kc_p2p_parse_field(&cursor, addr, sizeof(addr), ':'))
            return 0;
    }
    if (!kc_p2p_parse_field(&cursor, port_text, sizeof(port_text), '\0'))
        return 0;
    if (*cursor != '\0') return 0;
    if (!kc_p2p_parse_candidate_type(type_text, &out->type)) return 0;
    if (inet_pton(AF_INET, addr, &ipv4) != 1 &&
        inet_pton(AF_INET6, addr, &ipv6) != 1)
        return 0;
    if (!kc_p2p_parse_port_token(port_text, &out->port)) return 0;
    snprintf(out->addr, sizeof(out->addr), "%s", addr);
    out->priority = kc_p2p_candidate_priority(out);
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
static int kc_p2p_find_end_line(char *start, char *limit, char **end) {
    char *cursor;
    char *newline;

    if (!start || !limit || !end) return 0;
    cursor = start;
    while (cursor < limit &&
        (newline = (char *)memchr(cursor, '\n', (size_t)(limit - cursor))) != NULL)
    {
        size_t len = (size_t)(newline - cursor);
        if (len == 3 && memcmp(cursor, "END", 3) == 0) {
            *end = newline + 1;
            return 1;
        }
        cursor = newline + 1;
    }
    return 0;
}

/**
 * serve index.
 * @return 0 on success, -1 on error.
 */

/**
 * Serve index.
 * @return 0 on success, -1 on error.
 */

/**
 * Parse remote candidates.
 * Summary: Parses candidate list from a buffer.
 * @param buf       Input buffer.
 * @param out       Output array.
 * @param out_count Output count.
 * @return 1 on success, 0 on malformed input.
 */
static int kc_p2p_parse_remote_candidates(const char *buf,
    kc_p2p_candidate_t *out, int *out_count)
{
    const char *p;

    if (!buf || !out || !out_count) return 0;
    *out_count = 0;
    p = buf;
    if (strncmp(p, "PUNCH_", 6) == 0) {
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
        if (len == 3 && memcmp(p, "END", 3) == 0)
            return kc_p2p_normalize_candidates(out, out_count);
        if (len >= sizeof(line)) return 0;
        memcpy(line, p, len);
        line[len] = '\0';
        if (strncmp(line, "CAND:", 5) != 0) return 0;
        if (*out_count >= KC_P2P_CANDIDATES_MAX) return 0;
        if (!kc_p2p_parse_candidate_line(line, &out[*out_count])) return 0;
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
static int kc_p2p_append_candidate_line(char *msg, size_t cap,
    const char *line)
{
    kc_p2p_candidate_t candidate;

    if (!kc_p2p_parse_candidate_line(line, &candidate)) return 0;
    if (!kc_p2p_append_text(msg, cap, line)) return 0;
    if (!kc_p2p_append_text(msg, cap, "\n")) return 0;
    return 1;
}

/**
 * Appends a bounded local candidate line.
 * @param msg       Output message buffer.
 * @param cap       Output message capacity.
 * @param candidate Candidate to append.
 * @return 1 on success, 0 on overflow.
 */
static int kc_p2p_append_candidate(char *msg, size_t cap,
    const kc_p2p_candidate_t *candidate)
{
    char cbuf[128];
    int n;

    if (!candidate) return 0;
    if (strchr(candidate->addr, ':')) {
        n = snprintf(cbuf, sizeof(cbuf), "CAND:%s:[%s]:%u\n",
            kc_p2p_candidate_type_name(candidate->type), candidate->addr,
            candidate->port);
    } else {
        n = snprintf(cbuf, sizeof(cbuf), "CAND:%s:%s:%u\n",
            kc_p2p_candidate_type_name(candidate->type), candidate->addr,
            candidate->port);
    }
    if (n < 0 || (size_t)n >= sizeof(cbuf)) return 0;
    return kc_p2p_append_text(msg, cap, cbuf);
}

/**
 * Copies validated CAND lines from one complete END-framed block.
 * @param cursor Input cursor after the command line.
 * @param end    One byte after END line.
 * @param msg    Output control message.
 * @param cap    Output control message capacity.
 * @return 1 on success, 0 on malformed input.
 */
static int kc_p2p_copy_candidate_block(char *cursor, char *end, char *msg,
    size_t cap)
{
    while (cursor < end) {
        char *newline = (char *)memchr(cursor, '\n', (size_t)(end - cursor));
        char line[128];
        size_t len;

        if (!newline) return 0;
        len = (size_t)(newline - cursor);
        if (len == 3 && memcmp(cursor, "END", 3) == 0) {
            return kc_p2p_append_text(msg, cap, "END\n");
        }
        if (len == 0 || len >= sizeof(line)) return 0;
        memcpy(line, cursor, len);
        line[len] = '\0';
        if (!kc_p2p_append_candidate_line(msg, cap, line)) return 0;
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
static int kc_p2p_parse_register_id(const char *line,
    char id[KC_P2P_ID_MAX + 1])
{
    const char *cursor;

    if (!line || strncmp(line, "REGISTER:", 9) != 0) return 0;
    cursor = line + 9;
    if (!kc_p2p_parse_field(&cursor, id, KC_P2P_ID_MAX + 1, '\0'))
        return 0;
    if (*cursor != '\0') return 0;
    return kc_p2p_is_valid_id(id);
}

/**
 * Parses a REGISTER proof command.
 * @param line     Input command line.
 * @param id       Output service id.
 * @param solution Output solution token.
 * @param proof    Output proof token.
 * @return 1 on success, 0 on malformed input.
 */
static int kc_p2p_parse_register_solution(const char *line,
    char id[KC_P2P_ID_MAX + 1], char solution[17], char proof[65])
{
    const char *cursor;

    if (!line || strncmp(line, "REGISTER:", 9) != 0) return 0;
    cursor = line + 9;
    if (!kc_p2p_parse_field(&cursor, id, KC_P2P_ID_MAX + 1, ':'))
        return 0;
    if (strncmp(cursor, "SOLUTION:", 9) != 0) return 0;
    cursor += 9;
    if (!kc_p2p_parse_field(&cursor, solution, 17, ':')) return 0;
    if (strncmp(cursor, "PROOF:", 6) != 0) return 0;
    cursor += 6;
    if (!kc_p2p_parse_field(&cursor, proof, 65, '\0')) return 0;
    if (*cursor != '\0') return 0;
    if (!kc_p2p_is_valid_id(id)) return 0;
    if (strlen(solution) == 0 || strlen(solution) > 16) return 0;
    if (!kc_p2p_is_hex_token(solution, strlen(solution))) return 0;
    if (!kc_p2p_is_hex_token(proof, 64)) return 0;
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
static int kc_p2p_parse_punch_req2(const char *line,
    char self_id[KC_P2P_ID_MAX + 1], char target_id[KC_P2P_ID_MAX + 1],
    char sess_id[KC_P2P_CTRL_SESSION_MAX + 1])
{
    const char *cursor;

    if (!line || strncmp(line, "PUNCH_REQ2:", 11) != 0) return 0;
    cursor = line + 11;
    if (!kc_p2p_parse_field(&cursor, self_id, KC_P2P_ID_MAX + 1, ':'))
        return 0;
    if (!kc_p2p_parse_field(&cursor, target_id, KC_P2P_ID_MAX + 1, ':'))
        return 0;
    if (!kc_p2p_parse_field(&cursor, sess_id, KC_P2P_CTRL_SESSION_MAX + 1,
        '\0'))
        return 0;
    if (*cursor != '\0') return 0;
    return kc_p2p_is_punch_id(self_id) && kc_p2p_is_valid_id(target_id) &&
        kc_p2p_is_session_token(sess_id);
}

/**
 * Parses a PUNCH_ACK2 command line.
 * @param line      Input command line.
 * @param self_id   Output publisher id.
 * @param target_id Output requester id.
 * @param sess_id   Output session id.
 * @return 1 on success, 0 on malformed input.
 */
static int kc_p2p_parse_punch_ack2(const char *line,
    char self_id[KC_P2P_ID_MAX + 1], char target_id[KC_P2P_ID_MAX + 1],
    char sess_id[KC_P2P_CTRL_SESSION_MAX + 1])
{
    const char *cursor;

    if (!line || strncmp(line, "PUNCH_ACK2:", 11) != 0) return 0;
    cursor = line + 11;
    if (!kc_p2p_parse_field(&cursor, self_id, KC_P2P_ID_MAX + 1, ':'))
        return 0;
    if (!kc_p2p_parse_field(&cursor, target_id, KC_P2P_ID_MAX + 1, ':'))
        return 0;
    if (!kc_p2p_parse_field(&cursor, sess_id, KC_P2P_CTRL_SESSION_MAX + 1,
        '\0'))
        return 0;
    if (*cursor != '\0') return 0;
    return kc_p2p_is_valid_id(self_id) && kc_p2p_is_punch_id(target_id) &&
        kc_p2p_is_session_token(sess_id);
}

/**
 * Parses a PUNCH_CALL2 command line.
 * @param line    Input command line.
 * @param peer_id Output peer id.
 * @param sess_id Output session id.
 * @return 1 on success, 0 on malformed input.
 */
static int kc_p2p_parse_punch_call2(const char *line,
    char peer_id[KC_P2P_ID_MAX + 1], char sess_id[KC_P2P_CTRL_SESSION_MAX + 1])
{
    const char *cursor;

    if (!line || strncmp(line, "PUNCH_CALL2:", 12) != 0) return 0;
    cursor = line + 12;
    if (!kc_p2p_parse_field(&cursor, peer_id, KC_P2P_ID_MAX + 1, ':'))
        return 0;
    if (!kc_p2p_parse_field(&cursor, sess_id, KC_P2P_CTRL_SESSION_MAX + 1,
        '\0'))
        return 0;
    if (*cursor != '\0') return 0;
    return kc_p2p_is_punch_id(peer_id) && kc_p2p_is_session_token(sess_id);
}

/**
 * Parses a PUNCH_OK2 command line.
 * @param line    Input command line.
 * @param peer_id Output peer id.
 * @param sess_id Output session id.
 * @return 1 on success, 0 on malformed input.
 */
static int kc_p2p_parse_punch_ok2(const char *line,
    char peer_id[KC_P2P_ID_MAX + 1], char sess_id[KC_P2P_CTRL_SESSION_MAX + 1])
{
    const char *cursor;

    if (!line || strncmp(line, "PUNCH_OK2:", 10) != 0) return 0;
    cursor = line + 10;
    if (!kc_p2p_parse_field(&cursor, peer_id, KC_P2P_ID_MAX + 1, ':'))
        return 0;
    if (!kc_p2p_parse_field(&cursor, sess_id, KC_P2P_CTRL_SESSION_MAX + 1,
        '\0'))
        return 0;
    if (*cursor != '\0') return 0;
    return kc_p2p_is_punch_id(peer_id) && kc_p2p_is_session_token(sess_id);
}

/**
 * Parses a DEREGISTER command line.
 * @param line Input command line.
 * @param id   Output service id.
 * @param key  Output registration key.
 * @return 1 on success, 0 on malformed input.
 */
static int kc_p2p_parse_deregister(const char *line,
    char id[KC_P2P_ID_MAX + 1], char key[KC_P2P_KEY_STR_SZ])
{
    const char *cursor;

    if (!line || strncmp(line, "DEREGISTER:", 11) != 0) return 0;
    cursor = line + 11;
    if (!kc_p2p_parse_field(&cursor, id, KC_P2P_ID_MAX + 1, ':')) return 0;
    if (strncmp(cursor, "KEY:", 4) != 0) return 0;
    cursor += 4;
    if (!kc_p2p_parse_field(&cursor, key, KC_P2P_KEY_STR_SZ, '\0'))
        return 0;
    if (*cursor != '\0') return 0;
    return kc_p2p_is_valid_id(id) && kc_p2p_is_hex_token(key, strlen(key));
}

/**
 * Parses a LOOKUP command line.
 * @param line Input command line.
 * @param id   Output service id.
 * @return 1 on success, 0 on malformed input.
 */
static int kc_p2p_parse_lookup(const char *line,
    char id[KC_P2P_ID_MAX + 1])
{
    const char *cursor;

    if (!line || strncmp(line, "LOOKUP:", 7) != 0) return 0;
    cursor = line + 7;
    if (!kc_p2p_parse_field(&cursor, id, KC_P2P_ID_MAX + 1, '\0'))
        return 0;
    if (*cursor != '\0') return 0;
    return kc_p2p_is_valid_id(id);
}

/**
 * Parses a CHALLENGE response line.
 * @param line Input response line.
 * @param nonce Output nonce token.
 * @param bits Output difficulty bits.
 * @return 1 on success, 0 on malformed input.
 */
static int kc_p2p_parse_challenge(const char *line, char nonce[17],
    unsigned int *bits)
{
    const char *cursor;
    char bits_text[16];
    unsigned long value;
    char *end;

    if (!line || !bits || strncmp(line, "CHALLENGE:", 10) != 0) return 0;
    cursor = line + 10;
    if (!kc_p2p_parse_field(&cursor, nonce, 17, ':')) return 0;
    if (!kc_p2p_parse_field(&cursor, bits_text, sizeof(bits_text), '\0'))
        return 0;
    if (*cursor != '\0') return 0;
    if (!kc_p2p_is_hex_token(nonce, 16)) return 0;
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
static int kc_p2p_parse_ok_key(const char *line, char key[KC_P2P_KEY_STR_SZ]) {
    const char *cursor;

    if (!line || strncmp(line, "OK:KEY:", 7) != 0) return 0;
    cursor = line + 7;
    if (!kc_p2p_parse_field(&cursor, key, KC_P2P_KEY_STR_SZ, '\0'))
        return 0;
    if (*cursor != '\0') return 0;
    return kc_p2p_is_hex_token(key, strlen(key));
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
static int kc_p2p_parse_punch_packet(const char *text, const char *prefix,
    char sess_id[KC_P2P_CTRL_SESSION_MAX + 1],
    char from_id[KC_P2P_ID_MAX + 1], char to_id[KC_P2P_ID_MAX + 1])
{
    const char *cursor;
    size_t prefix_len;

    if (!text || !prefix) return 0;
    prefix_len = strlen(prefix);
    if (strncmp(text, prefix, prefix_len) != 0) return 0;
    cursor = text + prefix_len;
    if (!kc_p2p_parse_field(&cursor, sess_id, KC_P2P_CTRL_SESSION_MAX + 1,
        ':'))
        return 0;
    if (!kc_p2p_parse_field(&cursor, from_id, KC_P2P_ID_MAX + 1, ':'))
        return 0;
    if (!kc_p2p_parse_field(&cursor, to_id, KC_P2P_ID_MAX + 1, '\0'))
        return 0;
    if (*cursor != '\0') return 0;
    while (to_id[0]) {
        size_t len = strlen(to_id);
        if (to_id[len - 1] != '\n' && to_id[len - 1] != '\r') break;
        to_id[len - 1] = '\0';
    }
    return kc_p2p_is_session_token(sess_id) && kc_p2p_is_punch_id(from_id) &&
        kc_p2p_is_punch_id(to_id);
}

#define KC_P2P_STUN_ATTR_DATA 0x0013

/**
 * STUN put16.
 * @return None.
 */
static void kc_p2p_stun_put16(unsigned char *b, int o, int v) {
    b[o] = (unsigned char)(v >> 8); b[o + 1] = (unsigned char)(v);
}

/**
 * STUN length.
 * @return None.
 */
static void kc_p2p_stun_len(unsigned char *buf, int o) {
    kc_p2p_stun_put16(buf, 2, o - 20);
}

/**
 * STUN gen id.
 * @return None.
 */
static int kc_p2p_stun_gen_id(unsigned char id[12]) {
    return kc_p2p_fill_random(id, 12) == 0;
}

/**
 * STUN build.
 * @return offset after header.
 */
static int kc_p2p_stun_build(unsigned char *buf, int mt, const unsigned char id[12]) {
    memset(buf, 0, 20);
    kc_p2p_stun_put16(buf, 0, mt);
    kc_p2p_stun_put16(buf, 4, 0x2112); buf[6] = 0xA4; buf[7] = 0x42;
    memcpy(buf + 8, id, 12);
    return 20;
}

/**
 * STUN hdr.
 * @return message type, or -1 on error.
 */
static int kc_p2p_stun_hdr(const unsigned char *buf, int len, unsigned char id[12]) {
    if (len < 20) return -1;
    uint32_t mg = ((uint32_t)buf[4] << 24) | ((uint32_t)buf[5] << 16) |
        ((uint32_t)buf[6] << 8) | buf[7];
    if (mg != KC_P2P_STUN_MAGIC) return -1;
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
static int kc_p2p_stun_find(const unsigned char *buf, int len, int t, int *al) {
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
static int kc_p2p_stun_rd_xaddr(const unsigned char *buf, int o, int al,
    unsigned char id[12], char *addr, int acap, unsigned short *port)
{
    (void)id;
    if (al < 8) return -1;
    if (buf[o + 1] != 1) return -1;
    unsigned short xp = ((unsigned short)buf[o + 2] << 8) | buf[o + 3];
    uint32_t xa = ((uint32_t)buf[o + 4] << 24) | ((uint32_t)buf[o + 5] << 16) |
        ((uint32_t)buf[o + 6] << 8) | buf[o + 7];
    *port = xp ^ (unsigned short)(KC_P2P_STUN_MAGIC >> 16);
    uint32_t a = xa ^ KC_P2P_STUN_MAGIC;
    snprintf(addr, (size_t)acap, "%u.%u.%u.%u",
        (unsigned)(a >> 24) & 0xff, (unsigned)(a >> 16) & 0xff,
        (unsigned)(a >> 8) & 0xff, (unsigned)(a & 0xff));
    return 0;
}

/**
 * STUN binding.
 * Summary: Sends Binding Request and returns srflx ip:port for udp_fd.
 * @param ctx      P2P context.
 * @param udp_fd   Bound UDP socket.
 * @param out_ip   Output address buffer.
 * @param out_cap  Output address buffer size.
 * @param out_port Output port.
 * @return 0 on success, -1 on error.
 */
static int kc_p2p_stun_binding(kc_p2p_t *ctx, int udp_fd,
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

    if (kc_p2p_resolve(host, port, SOCK_DGRAM, &srv, &srv_len) != 0) return -1;
    if (srv.ss_family != AF_INET) return -1;

    if (!kc_p2p_stun_gen_id(tx_id)) return -1;
    off = kc_p2p_stun_build(tx, KC_P2P_STUN_BINDING, tx_id);
    kc_p2p_stun_len(tx, off);

    if (sendto(udp_fd, (const char *)tx, (size_t)off, 0,
        (const struct sockaddr *)&srv, srv_len) < 0) return -1;

    FD_ZERO(&rfds); FD_SET(udp_fd, &rfds);
    tv.tv_sec = 3; tv.tv_usec = 0;
    n = select(udp_fd + 1, &rfds, NULL, NULL, &tv);
    if (n <= 0) return -1;
    rl = (int)recvfrom(udp_fd, (char *)rx, sizeof(rx), 0, NULL, NULL);
    if (rl < 20) return -1;

    mt = kc_p2p_stun_hdr(rx, rl, rx_id);
    if (mt != KC_P2P_STUN_BINDING_RESP) return -1;
    if (memcmp(tx_id, rx_id, sizeof(tx_id)) != 0) return -1;

    ao = kc_p2p_stun_find(rx, rl, KC_P2P_STUN_ATTR_XOR_MAPPED_ADDR, &al);
    if (ao < 0) return -1;
    if (kc_p2p_stun_rd_xaddr(rx, ao, al, tx_id, out_ip, out_cap, out_port) != 0)
        return -1;
    return 0;
}

/**
 * Set stun url.
 * @return 0 on success, -1 on error.
 */
int kc_p2p_set_stun_url(kc_p2p_t *ctx, const char *url) {
    if (!ctx) return KC_P2P_ERROR;
    if (url) {
        strncpy(ctx->stun_url, url, sizeof(ctx->stun_url) - 1);
        ctx->stun_url[sizeof(ctx->stun_url) - 1] = '\0';
    } else {
        ctx->stun_url[0] = '\0';
    }
    return KC_P2P_OK;
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
int kc_p2p_gather_candidates(kc_p2p_t *ctx, int udp_fd,
    kc_p2p_candidate_t *out, int out_cap, int *out_count) {
    struct sockaddr_storage udp_sa;
    char stun_ip[KC_P2P_ADDR_MAX + 1];
    unsigned short stun_port;
    socklen_t udp_sa_len = sizeof(udp_sa);

    stun_ip[0] = '\0';
    stun_port = 0;
    *out_count = 0;
    if (getsockname(udp_fd, (struct sockaddr *)&udp_sa, &udp_sa_len) == 0) {
        unsigned short udp_port = kc_p2p_sockaddr_port(&udp_sa);
        if (*out_count < out_cap) {
            out[*out_count].type = KC_P2P_CAND_HOST;
            if (udp_sa.ss_family == AF_INET6)
                strcpy(out[*out_count].addr, "::1");
            else
                strcpy(out[*out_count].addr, "127.0.0.1");
            out[*out_count].port = udp_port;
            out[*out_count].priority = kc_p2p_candidate_priority(&out[*out_count]);
            (*out_count)++;
        }
        
        kc_p2p_fd_t test_fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (!KC_P2P_ISERR(test_fd)) {
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
                        out[*out_count].type = KC_P2P_CAND_LAN;
                        strcpy(out[*out_count].addr, local_ip);
                        out[*out_count].port = udp_port;
                        out[*out_count].priority = kc_p2p_candidate_priority(&out[*out_count]);
                        (*out_count)++;
                    }
                }
            }
            KC_P2P_FD_CLOSE(test_fd);
        }

        if (ctx && ctx->stun_url[0]) {
            kc_p2p_stun_binding(ctx, udp_fd, stun_ip, (int)sizeof(stun_ip),
                &stun_port);
        }
        if (stun_ip[0] != '\0' && *out_count < out_cap) {
            unsigned short srflx_port = stun_port ? stun_port : udp_port;
            out[*out_count].type = KC_P2P_CAND_SRFLX;
            snprintf(out[*out_count].addr, sizeof(out[*out_count].addr),
                "%.47s", stun_ip);
            out[*out_count].port = srflx_port;
            out[*out_count].priority = kc_p2p_candidate_priority(&out[*out_count]);
            (*out_count)++;
        }
    }
    if (!kc_p2p_normalize_candidates(out, out_count)) return KC_P2P_ERROR;
    return KC_P2P_OK;
}

/**
 * Converts a candidate into a socket address.
 * @param candidate Candidate to convert.
 * @param out       Output socket address.
 * @return 1 on success, 0 on malformed input.
 */
static int kc_p2p_candidate_sockaddr(const kc_p2p_candidate_t *candidate,
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
static int kc_p2p_punch_send_candidate(int udp_fd,
    const kc_p2p_candidate_t *candidate, const char *ping_msg,
    int *unsupported)
{
    struct sockaddr_storage cand_sa;
    socklen_t cand_len;

    if (!kc_p2p_candidate_sockaddr(candidate, &cand_sa)) {
        if (unsupported) (*unsupported)++;
        return 0;
    }
    cand_len = kc_p2p_sockaddr_len(&cand_sa);
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
 * @return KC_P2P_OK on valid response, KC_P2P_ETIMEOUT otherwise.
 */
static int kc_p2p_punch_wait_response(int udp_fd, const char *session_id,
    const char *from_id, const char *to_id, int wait_ms, uint64_t deadline_ms,
    struct sockaddr_storage *selected_addr, int *malformed, int *mismatched)
{
    uint64_t now;
    int remaining_ms;
    fd_set readfds;
    struct timeval tv;

    now = kc_p2p_now_ms();
    if (now >= deadline_ms) return KC_P2P_ETIMEOUT;
    remaining_ms = (int)(deadline_ms - now);
    if (remaining_ms > wait_ms) remaining_ms = wait_ms;
    if (remaining_ms <= 0) return KC_P2P_ETIMEOUT;
    FD_ZERO(&readfds);
    FD_SET(udp_fd, &readfds);
    tv.tv_sec = remaining_ms / 1000;
    tv.tv_usec = (remaining_ms % 1000) * 1000;
    if (select(udp_fd + 1, &readfds, NULL, NULL, &tv) <= 0)
        return KC_P2P_ETIMEOUT;
    if (FD_ISSET(udp_fd, &readfds)) {
        char recv_buf[1024];
        struct sockaddr_storage src_addr;
        socklen_t src_len = sizeof(src_addr);
        int n;

        n = recvfrom(udp_fd, recv_buf, sizeof(recv_buf) - 1, 0,
            (struct sockaddr *)&src_addr, &src_len);
        if (n > 0) {
            char rx_sess[64] = {0};
            char rx_from[KC_P2P_ID_MAX + 1] = {0};
            char rx_to[KC_P2P_ID_MAX + 1] = {0};
            int is_ping;
            int is_pong;

            recv_buf[n] = '\0';
            is_pong = kc_p2p_parse_punch_packet(recv_buf, "PUNCH_PONG:",
                rx_sess, rx_from, rx_to);
            is_ping = 0;
            if (!is_pong) {
                is_ping = kc_p2p_parse_punch_packet(recv_buf,
                    "PUNCH_PING:", rx_sess, rx_from, rx_to);
            }
            if (!is_ping && !is_pong) {
                if (malformed) (*malformed)++;
                return KC_P2P_ETIMEOUT;
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
                    snprintf(pong_msg, sizeof(pong_msg),
                        "PUNCH_PONG:%s:%s:%s\n", session_id, to_id, from_id);
                    sendto(udp_fd, pong_msg, strlen(pong_msg), 0,
                        (struct sockaddr *)&src_addr, src_len);
                }
                return KC_P2P_OK;
            }
            if (mismatched) (*mismatched)++;
        }
    }
    return KC_P2P_ETIMEOUT;
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
int kc_p2p_punch_select(kc_p2p_t *ctx, int sweep_limit, int udp_fd, const char *session_id, const char *from_id, const char *to_id, const kc_p2p_candidate_t *remote_candidates, int remote_candidate_count, struct sockaddr_storage *selected_addr) {
    char ping_msg[256];
    uint64_t deadline_ms;
    int direct_count;
    int sent_count;
    int malformed_count;
    int mismatch_count;
    int unsupported_count;

    (void)ctx;
    if (remote_candidate_count <= 0) {
        fprintf(stderr, "p2p: punch failed: no candidates\n");
        return KC_P2P_ERROR;
    }
    if (sweep_limit < 0) sweep_limit = 0;
    deadline_ms = kc_p2p_now_ms() + KC_P2P_PUNCH_TOTAL_MS;
    direct_count = 0;
    sent_count = 0;
    malformed_count = 0;
    mismatch_count = 0;
    unsupported_count = 0;
    for (int c = 0; c < remote_candidate_count; c++) {
        if (remote_candidates[c].priority < 300u) direct_count++;
    }
    snprintf(ping_msg, sizeof(ping_msg), "PUNCH_PING:%s:%s:%s\n",
        session_id, from_id, to_id);
    for (int i = 0; direct_count > 0 && i < KC_P2P_PUNCH_DIRECT_ROUNDS; i++) {
        for (int c = 0; c < remote_candidate_count; c++) {
            if (remote_candidates[c].priority >= 300u) continue;
            sent_count += kc_p2p_punch_send_candidate(udp_fd,
                &remote_candidates[c], ping_msg, &unsupported_count);
        }
        if (kc_p2p_punch_wait_response(udp_fd, session_id, from_id, to_id,
            KC_P2P_PUNCH_DIRECT_WAIT_MS, deadline_ms, selected_addr,
            &malformed_count, &mismatch_count) == KC_P2P_OK)
            return KC_P2P_OK;
    }
    for (int sweep = 1; sweep <= sweep_limit && kc_p2p_now_ms() < deadline_ms;
        sweep++)
    {
        for (int sign = -1; sign <= 1 && kc_p2p_now_ms() < deadline_ms;
            sign += 2)
        {
            int offset = sweep * sign;
            for (int c = 0; c < remote_candidate_count; c++) {
                struct sockaddr_storage exact_sa;
                int test_port;

                sent_count += kc_p2p_punch_send_candidate(udp_fd,
                    &remote_candidates[c], ping_msg, &unsupported_count);
                if (!kc_p2p_candidate_sockaddr(&remote_candidates[c], &exact_sa))
                    continue;
                if (exact_sa.ss_family != AF_INET) continue;
                if (remote_candidates[c].type != KC_P2P_CAND_SRFLX &&
                    remote_candidates[c].type != KC_P2P_CAND_PUBLIC)
                    continue;
                test_port = remote_candidates[c].port + offset;
                if (test_port <= 0 || test_port > 65535) continue;
                kc_p2p_sockaddr_set_port(&exact_sa, (unsigned short)test_port);
                if (kc_p2p_sendto_addr(udp_fd, ping_msg, strlen(ping_msg),
                    &exact_sa) >= 0)
                    sent_count++;
            }
            if (kc_p2p_punch_wait_response(udp_fd, session_id, from_id, to_id,
                KC_P2P_PUNCH_SWEEP_WAIT_MS, deadline_ms, selected_addr,
                &malformed_count, &mismatch_count) == KC_P2P_OK)
                return KC_P2P_OK;
        }
    }
    if (sent_count == 0) {
        fprintf(stderr, "p2p: punch failed: all candidates invalid or unsupported\n");
    } else if (malformed_count > 0) {
        fprintf(stderr, "p2p: punch failed: malformed peer packet\n");
    } else if (mismatch_count > 0) {
        fprintf(stderr, "p2p: punch failed: session mismatch\n");
    } else if (unsupported_count > 0) {
        fprintf(stderr, "p2p: punch failed: address family mismatch\n");
    } else if (kc_p2p_now_ms() >= deadline_ms) {
        fprintf(stderr, "p2p: punch failed: timeout\n");
    } else {
        fprintf(stderr, "p2p: punch failed: all attempts exhausted\n");
    }
    return KC_P2P_ERROR;
}

/**
 * Serve index.
 * Summary: Serve the index server.
 * @param ctx Context.
 * @param host Host.
 * @param port Port.
 * @return 0 on success, -1 on error.
 */
int kc_p2p_serve_index(
    kc_p2p_t *ctx,
    const char *host,
    unsigned short port)
{
    kc_p2p_fd_t tcp_fd;
    struct addrinfo hints;
    struct addrinfo *ai;
    struct addrinfo *it;
    char port_str[16];
    fd_set fds;
    struct timeval tv;
    int ret, i, n;
    int maxfd;

    if (kc_p2p_platform_init() != 0)
        return KC_P2P_ENET;

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
    if (ret != 0) { kc_p2p_platform_cleanup(); return KC_P2P_ENET; }
    tcp_fd = KC_P2P_FD_INVALID;
    for (it = ai; it; it = it->ai_next) {
        tcp_fd = socket(it->ai_family, it->ai_socktype, it->ai_protocol);
        if (KC_P2P_ISERR(tcp_fd)) continue;
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
        KC_P2P_FD_CLOSE(tcp_fd);
        tcp_fd = KC_P2P_FD_INVALID;
    }
    freeaddrinfo(ai);
    if (KC_P2P_ISERR(tcp_fd)) { kc_p2p_platform_cleanup(); return KC_P2P_ENET; }

    kc_p2p_set_nonblock(tcp_fd);

    fprintf(stderr, "p2p: index server listening on %s:%u\n",
        host ? host : "*", (unsigned)port);

    while (1) {
        if (kc_p2p_stop_requested) { fprintf(stderr, "p2p: shutdown requested\n"); break; }

        FD_ZERO(&fds);
        FD_SET(tcp_fd, &fds);
        maxfd = (int)tcp_fd;

        kc_p2p_lock(ctx);
        for (i = 0; i < ctx->n_conns; i++) {
            FD_SET(ctx->conns[i].fd, &fds);
            if ((int)ctx->conns[i].fd > maxfd) maxfd = (int)ctx->conns[i].fd;
        }
        kc_p2p_unlock(ctx);

        tv.tv_sec = 1; tv.tv_usec = 0;
        n = select(maxfd + 1, &fds, NULL, NULL, &tv);
        if (n < 0) { if (kc_p2p_stop_requested) break; continue; }
        if (n == 0) continue;

        if (FD_ISSET(tcp_fd, &fds)) {
            struct sockaddr_storage client_addr;
            socklen_t client_len = sizeof(client_addr);
            kc_p2p_fd_t client_fd = accept(tcp_fd, (struct sockaddr *)&client_addr, &client_len);
            if (!KC_P2P_ISERR(client_fd)) {
                kc_p2p_set_nonblock(client_fd);
                kc_p2p_lock(ctx);
                kc_p2p_conn_add(ctx, client_fd);
                kc_p2p_unlock(ctx);
            }
        }

        kc_p2p_lock(ctx);
        for (i = ctx->n_conns - 1; i >= 0; i--) {
            if (!FD_ISSET(ctx->conns[i].fd, &fds)) continue;

            {
                kc_p2p_tcp_conn_t *c = &ctx->conns[i];
                char tmp[KC_P2P_BUF];
                int nr;

                nr = kc_p2p_sock_read(c->fd, tmp, (int)sizeof(tmp) - 1);
                if (nr <= 0) {
                    int cidx;
                    struct sockaddr_storage dead_peer_sa;
                    socklen_t dead_peer_len;

                    memset(&dead_peer_sa, 0, sizeof(dead_peer_sa));
                    dead_peer_len = sizeof(dead_peer_sa);
                    if (getpeername(c->fd, (struct sockaddr *)&dead_peer_sa,
                        &dead_peer_len) == 0)
                    {
                        cidx = kc_p2p_find_pow_challenge(ctx, &dead_peer_sa);
                    } else {
                        cidx = -1;
                    }
                    if (cidx >= 0)
                        kc_p2p_remove_pow_challenge(ctx, cidx);
                    if (c->registered) {
                        kc_p2p_remove_peer(ctx, c->id);
                        fprintf(stderr, "p2p: peer '%s' disconnected\n", c->id);
                    }
                    kc_p2p_conn_remove(ctx, i);
                    continue;
                }

                tmp[nr] = '\0';

                {   int copy = nr;
                    if (c->buf_len + copy > (int)sizeof(c->buf) - 1) {
                        kc_p2p_conn_remove(ctx, i);
                        continue;
                    }
                    if (copy > 0) {
                        memcpy(c->buf + c->buf_len, tmp, copy);
                        c->buf_len += copy;
                    }
                    if (c->buf_len >= KC_P2P_CTRL_LINE_MAX &&
                        !memchr(c->buf, '\n', (size_t)c->buf_len))
                    {
                        kc_p2p_conn_remove(ctx, i);
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
                        char cmd_buf[KC_P2P_BUF];
                        char cmd[32];
                        char id[KC_P2P_ID_MAX + 1];
                        char reply_buf[KC_P2P_BUF];
                        int srv_idx;

                        if (line_len <= 0) {
                            line_start += line_len + 1;
                            continue;
                        }
                        if (line_len > KC_P2P_CTRL_LINE_MAX ||
                            line_len > (int)sizeof(cmd_buf) - 1)
                        {
                            kc_p2p_conn_remove(ctx, i);
                            fatal_frame = 1;
                            break;
                        }
                        memcpy(cmd_buf, line_start, line_len);
                        cmd_buf[line_len] = '\0';
                        line_start += line_len + 1;

                        if (strcmp(cmd_buf, KC_P2P_CTRL_HELLO) == 0) {
                            if (c->hello_ok) {
                                kc_p2p_tcp_send(c->fd,
                                    KC_P2P_CTRL_VERSION_ERROR);
                                kc_p2p_conn_remove(ctx, i);
                                fatal_frame = 1;
                                break;
                            }
                            c->hello_ok = 1;
                            kc_p2p_tcp_send(c->fd, KC_P2P_CTRL_HELLO_OK);
                            continue;
                        }
                        if (strncmp(cmd_buf, "HELLO", 5) == 0 ||
                            !c->hello_ok)
                        {
                            kc_p2p_tcp_send(c->fd,
                                KC_P2P_CTRL_VERSION_ERROR);
                            kc_p2p_conn_remove(ctx, i);
                            fatal_frame = 1;
                            break;
                        }

                        {
                            const char *colon = strchr(cmd_buf, ':');
                            size_t cmd_len = colon ? (size_t)(colon - cmd_buf) : strlen(cmd_buf);
                            if (cmd_len == 0 || cmd_len >= sizeof(cmd)) {
                                kc_p2p_tcp_send(c->fd, "ERROR:malformed");
                                continue;
                            }
                            memcpy(cmd, cmd_buf, cmd_len);
                            cmd[cmd_len] = '\0';
                        }

                        if (strcmp(cmd, "REGISTER") == 0) {
                            struct sockaddr_storage peer_sa;
                            socklen_t peer_len = sizeof(peer_sa);

                            if (getpeername(c->fd, (struct sockaddr *)&peer_sa,
                                &peer_len) != 0)
                                memset(&peer_sa, 0, sizeof(peer_sa));

                            if (strstr(cmd_buf, ":SOLUTION:") == NULL &&
                                !kc_p2p_parse_register_id(cmd_buf, id))
                            {
                                kc_p2p_tcp_send(c->fd, "ERROR:invalid id");
                                continue;
                            }

                            if (strstr(cmd_buf, ":SOLUTION:") != NULL) {
                                char solution[17];
                                char proof[65];
                                int cidx;
                                const char *register_pass;

                                if (kc_p2p_parse_register_solution(cmd_buf, id,
                                    solution, proof))
                                {
                                    register_pass = kc_p2p_get_register_pass(ctx, id);
                                    cidx = kc_p2p_find_pow_challenge(ctx, &peer_sa);
                                    if (cidx < 0 ||
                                        strcmp(ctx->pow_challenges[cidx].id, id) != 0 ||
                                        !kc_p2p_verify_register_pow(register_pass,
                                            ctx->pow_challenges[cidx].nonce_hex, id,
                                            solution, proof, ctx->pow_bits))
                                    {
                                        if (cidx >= 0)
                                            kc_p2p_remove_pow_challenge(ctx, cidx);
                                        kc_p2p_tcp_send(c->fd, "AUTH_FAILED");
                                        continue;
                                    }
                                    kc_p2p_remove_pow_challenge(ctx, cidx);
                                    if (kc_p2p_add_peer(ctx, id) == KC_P2P_OK &&
                                        kc_p2p_format_register_ok(ctx, id,
                                            reply_buf, sizeof(reply_buf)))
                                    {
                                        kc_p2p_tcp_send(c->fd, reply_buf);
                                        strcpy(c->id, id);
                                        c->registered = 1;
                                    } else {
                                        kc_p2p_tcp_send(c->fd, "ERROR:peer table full");
                                    }
                                } else {
                                    kc_p2p_tcp_send(c->fd, "AUTH_FAILED");
                                    continue;
                                }
                            } else if (c->registered && strcmp(c->id, id) == 0) {
                                if (kc_p2p_refresh_peer(ctx, id) == KC_P2P_OK &&
                                    kc_p2p_format_register_ok(ctx, id,
                                        reply_buf, sizeof(reply_buf)))
                                {
                                    kc_p2p_tcp_send(c->fd, reply_buf);
                                } else {
                                    kc_p2p_tcp_send(c->fd, "ERROR:not registered");
                                }
                            } else if (ctx->n_pow_challenges >= KC_P2P_POW_CHALLENGES_MAX &&
                                kc_p2p_find_pow_challenge(ctx, &peer_sa) < 0)
                            {
                                kc_p2p_tcp_send(c->fd, "ERROR:busy");
                            } else {
                                unsigned char nonce[8];
                                char nonce_hex[17];

                                if (kc_p2p_fill_random(nonce, sizeof(nonce)) != 0 ||
                                    !kc_p2p_hex_encode(nonce, sizeof(nonce),
                                        nonce_hex, sizeof(nonce_hex)))
                                {
                                    kc_p2p_tcp_send(c->fd, "ERROR:random");
                                    continue;
                                }
                                snprintf(reply_buf, sizeof(reply_buf),
                                    "CHALLENGE:%s:%d", nonce_hex, ctx->pow_bits);
                                if (!kc_p2p_store_pow_challenge(ctx, &peer_sa, id,
                                    reply_buf + 10))
                                {
                                    kc_p2p_tcp_send(c->fd, "ERROR:busy");
                                } else {
                                    kc_p2p_tcp_send(c->fd, reply_buf);
                                }
                            }

                        } else if (strcmp(cmd, "PUNCH_REQ2") == 0) {
                            char self_id[KC_P2P_ID_MAX + 1] = {0};
                            char target_id[KC_P2P_ID_MAX + 1] = {0};
                            char sess_id[KC_P2P_CTRL_SESSION_MAX + 1] = {0};
                            char *block_end;

                            if (!kc_p2p_find_end_line(line_start,
                                c->buf + c->buf_len, &block_end))
                            {
                                line_start = line_base;
                                break;
                            }
                            if (kc_p2p_parse_punch_req2(cmd_buf, self_id,
                                target_id, sess_id)) {
                                int target_fd = -1;
                                for (int j = 0; j < ctx->n_conns; j++) {
                                    if (ctx->conns[j].registered && strcmp(ctx->conns[j].id, target_id) == 0) {
                                        target_fd = ctx->conns[j].fd;
                                        break;
                                    }
                                }

                                srv_idx = kc_p2p_find_peer(ctx, target_id);

                                if (target_fd != -1 && srv_idx >= 0) {
                                    char msg[KC_P2P_BUF];
                                    snprintf(msg, sizeof(msg), "PUNCH_CALL2:%s:%s\n", self_id, sess_id);

                                    if (!kc_p2p_copy_candidate_block(line_start,
                                        block_end, msg, sizeof(msg)))
                                    {
                                        kc_p2p_tcp_send(c->fd, "ERROR:malformed");
                                        line_start = block_end;
                                        continue;
                                    }
                                    line_start = block_end;
                                    kc_p2p_tcp_send(target_fd, msg);
                                    
                                    kc_p2p_pending_punch_evict_stale(ctx);
                                    if (ctx->n_pending_punches < KC_P2P_MAX_PENDING_PUNCHES) {
                                        kc_p2p_pending_punch_t *pp = &ctx->pending_punches[ctx->n_pending_punches++];
                                        snprintf(pp->self_id, sizeof(pp->self_id), "%s", self_id);
                                        snprintf(pp->target_id, sizeof(pp->target_id), "%s", target_id);
                                        snprintf(pp->sess_id, sizeof(pp->sess_id), "%s", sess_id);
                                        pp->consumer_fd = c->fd;
                                        pp->ts = kc_p2p_now_s();
                                    } else {
                                        kc_p2p_tcp_send(c->fd, "ERROR:busy");
                                    }
                                } else {
                                    kc_p2p_tcp_send(c->fd, "ERROR:offline");
                                    line_start = block_end;
                                }
                            } else {
                                kc_p2p_tcp_send(c->fd, "ERROR:malformed");
                                line_start = block_end;
                            }

                        } else if (strcmp(cmd, "PUNCH_ACK2") == 0) {
                            char ack_self_id[KC_P2P_ID_MAX + 1] = {0};
                            char ack_target_id[KC_P2P_ID_MAX + 1] = {0};
                            char ack_sess_id[KC_P2P_CTRL_SESSION_MAX + 1] = {0};
                            char *block_end;

                            if (!kc_p2p_find_end_line(line_start,
                                c->buf + c->buf_len, &block_end))
                            {
                                line_start = line_base;
                                break;
                            }
                            if (kc_p2p_parse_punch_ack2(cmd_buf, ack_self_id,
                                ack_target_id, ack_sess_id)) {
                                int pp_idx = kc_p2p_pending_punch_find(ctx, ack_self_id, ack_target_id, ack_sess_id);
                                if (pp_idx >= 0) {
                                    char ok2[KC_P2P_BUF];
                                    snprintf(ok2, sizeof(ok2), "PUNCH_OK2:%s:%s\n", ack_self_id, ack_sess_id);
                                    if (!kc_p2p_copy_candidate_block(line_start,
                                        block_end, ok2, sizeof(ok2)))
                                    {
                                        kc_p2p_tcp_send(c->fd, "ERROR:malformed");
                                        line_start = block_end;
                                        continue;
                                    }
                                    kc_p2p_tcp_send(ctx->pending_punches[pp_idx].consumer_fd, ok2);
                                    kc_p2p_pending_punch_remove(ctx, pp_idx);
                                }
                                line_start = block_end;
                            } else {
                                kc_p2p_tcp_send(c->fd, "ERROR:malformed");
                                line_start = block_end;
                            }
                            
                        } else if (strcmp(cmd, "DEREGISTER") == 0) {
                            char dkey[KC_P2P_KEY_STR_SZ];
                            if (kc_p2p_parse_deregister(cmd_buf, id, dkey)) {
                                srv_idx = kc_p2p_find_peer(ctx, id);
                                if (srv_idx >= 0 && strcmp(ctx->peers[srv_idx].key, dkey) == 0) {
                                    kc_p2p_remove_peer(ctx, id);
                                    kc_p2p_tcp_send(c->fd, "OK");
                                } else {
                                    kc_p2p_tcp_send(c->fd, "ERROR:invalid key");
                                }
                            } else {
                                kc_p2p_tcp_send(c->fd, "ERROR:malformed");
                            }

                        } else if (strcmp(cmd, "LIST") == 0) {
                            if (strcmp(cmd_buf, "LIST") != 0) {
                                kc_p2p_tcp_send(c->fd, "ERROR:malformed");
                                continue;
                            }
                            kc_p2p_evict_stale(ctx);
                            for (srv_idx = 0; srv_idx < ctx->n_peers; srv_idx++) {
                                snprintf(reply_buf, sizeof(reply_buf), "PEER:%s",
                                    ctx->peers[srv_idx].id);
                                kc_p2p_tcp_send(c->fd, reply_buf);
                            }
                            kc_p2p_tcp_send(c->fd, "END");

                        } else if (strcmp(cmd, "LOOKUP") == 0) {
                            if (kc_p2p_parse_lookup(cmd_buf, id)) {
                                srv_idx = kc_p2p_find_peer(ctx, id);
                                if (srv_idx >= 0) {
                                    snprintf(reply_buf, sizeof(reply_buf), "PEER:%s",
                                        ctx->peers[srv_idx].id);
                                    kc_p2p_tcp_send(c->fd, reply_buf);
                                } else {
                                    kc_p2p_tcp_send(c->fd, "NOT_FOUND");
                                }
                            } else {
                                kc_p2p_tcp_send(c->fd, "ERROR:malformed");
                            }
                        } else {
                            kc_p2p_tcp_send(c->fd, "ERROR:unknown command");
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
        kc_p2p_unlock(ctx);
    }

    KC_P2P_FD_CLOSE(tcp_fd);
    kc_p2p_platform_cleanup();
    return KC_P2P_OK;
}

/**
 * build candidates.
 * @return 0 on success, -1 on error.
 */

/**
 * Build candidates.
 * @return 0 on success, -1 on error.
 */

/**
 * punch candidates.
 * @return 0 on success, -1 on error.
 */

/**
 * save key.
 * @return None.
 */

/**
 * Save key.
 * @return Status code.
 */
static void kc_p2p_save_key(const char *id, const char *key);

/**
 * Load key.
 * @return Status code.
 */
static void kc_p2p_load_key(const char *id, char *key, size_t cap);

/**
 * Mkdir p.
 * @return Status code.
 */
static void kc_p2p_mkdir_p(char *path) {
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
 * save key.
 * @return None.
 */

/**
 * Save key.
 * @return Status code.
 */
static void kc_p2p_save_key(const char *id, const char *key) {
    const char *home;
    char dir[512];
    char path[576];
    FILE *f;
    home = getenv("HOME");
    if (!home) return;
    snprintf(dir, sizeof(dir), "%s/.local/share/p2p/keys", home);
    kc_p2p_mkdir_p(dir);
    snprintf(path, sizeof(path), "%s/%s", dir, id);
    f = fopen(path, "w");
    if (f) { fprintf(f, "%s\n", key); fclose(f); }
}

/**
 * load key.
 * @return None.
 */

/**
 * Load key.
 * @return Status code.
 */
static void kc_p2p_load_key(const char *id, char *key, size_t cap) {
    const char *home;
    char path[576];
    FILE *f;
    home = getenv("HOME");
    if (!home) return;
    snprintf(path, sizeof(path), "%s/.local/share/p2p/keys/%s", home, id);
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
 * deregister.
 * @return 0 on success, -1 on error.
 */

/**
 * Deregister.
 * @return 0 on success, -1 on error.
 */
int kc_p2p_deregister(
    kc_p2p_t *ctx,
    const char *index_host,
    unsigned short index_port,
    const char *id)
{
    char key[KC_P2P_KEY_STR_SZ] = "";
    char cmd[KC_P2P_BUF];
    char reply[KC_P2P_BUF];

    (void)ctx;
    kc_p2p_load_key(id, key, sizeof(key));
    if (key[0] == '\0') return KC_P2P_ENOENT;

    snprintf(cmd, sizeof(cmd), "DEREGISTER:%s:KEY:%s", id, key);
    {
    kc_p2p_fd_t fd = kc_p2p_control_connect(index_host, index_port);
        if (KC_P2P_ISERR(fd)) return KC_P2P_ENET;
        if (kc_p2p_tcp_send(fd, cmd) != KC_P2P_OK) { KC_P2P_FD_CLOSE(fd); return KC_P2P_ENET; }
        if (kc_p2p_tcp_readline(fd, reply, (int)sizeof(reply), 5) < 0) { KC_P2P_FD_CLOSE(fd); return KC_P2P_ETIMEOUT; }
        KC_P2P_FD_CLOSE(fd);
    }

    if (strcmp(reply, "OK") != 0) return KC_P2P_ERROR;
    return KC_P2P_OK;
}

/**
 * wait.
 * @return 0 on success, -1 on error.
 */

/**
 * Wait.
 * @return 0 on success, -1 on error.
 */
int kc_p2p_wait(
    kc_p2p_t *ctx,
    const char *index_host,
    unsigned short index_port,
    const char *self_id,
    unsigned short bind_port)
{
    kc_p2p_fd_t control_fd;
    char send_buf[KC_P2P_BUF];
    char recv_buf[KC_P2P_BUF];
    kc_p2p_fd_t udp_fd = KC_P2P_FD_INVALID;
    uint64_t last_heartbeat;
    const char *udp_any_host;

    (void)bind_port;
    if (!ctx) return KC_P2P_ERROR;
    if (ctx->proto != KC_P2P_PROTO_TCP && ctx->proto != KC_P2P_PROTO_UDP)
        return KC_P2P_ERROR;
    if (ctx->bind_port == 0) return KC_P2P_ERROR;
    udp_any_host = kc_p2p_host_is_ipv6_literal(index_host) ? "::" : "0.0.0.0";

    control_fd = kc_p2p_control_connect(index_host, index_port);
    if (KC_P2P_ISERR(control_fd)) return KC_P2P_ENET;

    udp_fd = kc_p2p_create_socket(udp_any_host, 0);
    if (KC_P2P_ISERR(udp_fd)) { KC_P2P_FD_CLOSE(control_fd); return KC_P2P_ENET; }

    snprintf(send_buf, sizeof(send_buf), "REGISTER:%s", self_id);
    if (kc_p2p_tcp_send(control_fd, send_buf) != KC_P2P_OK ||
        kc_p2p_tcp_readline(control_fd, recv_buf, (int)sizeof(recv_buf), 10) < 0)
    {
        KC_P2P_FD_CLOSE(control_fd);
        if (!KC_P2P_ISERR(udp_fd)) KC_P2P_FD_CLOSE(udp_fd);
        return KC_P2P_ENET;
    }

    if (strncmp(recv_buf, "CHALLENGE:", 10) == 0) {
        char nonce[17];
        char solution[17];
        char proof[65];
        unsigned int chall_bits;

        if (!kc_p2p_parse_challenge(recv_buf, nonce, &chall_bits)) {
            KC_P2P_FD_CLOSE(control_fd);
            if (!KC_P2P_ISERR(udp_fd)) KC_P2P_FD_CLOSE(udp_fd);
            return KC_P2P_ERROR;
        }
        fprintf(stderr, "p2p: connecting...\n");
        if (!kc_p2p_solve_register_pow(ctx->pass, nonce, self_id,
            (int)chall_bits, solution, sizeof(solution), proof, sizeof(proof)))
        {
            KC_P2P_FD_CLOSE(control_fd);
            if (!KC_P2P_ISERR(udp_fd)) KC_P2P_FD_CLOSE(udp_fd);
            return KC_P2P_ERROR;
        }
        snprintf(send_buf, sizeof(send_buf),
            "REGISTER:%s:SOLUTION:%s:PROOF:%s", self_id, solution, proof);
        if (kc_p2p_tcp_send(control_fd, send_buf) != KC_P2P_OK ||
            kc_p2p_tcp_readline(control_fd, recv_buf, (int)sizeof(recv_buf), 10) < 0)
        {
            KC_P2P_FD_CLOSE(control_fd);
            if (!KC_P2P_ISERR(udp_fd)) KC_P2P_FD_CLOSE(udp_fd);
            return KC_P2P_ENET;
        }
    } else {
        KC_P2P_FD_CLOSE(control_fd);
        if (!KC_P2P_ISERR(udp_fd)) KC_P2P_FD_CLOSE(udp_fd);
        return KC_P2P_ERROR;
    }

    {
        char obs_key[KC_P2P_KEY_STR_SZ];
        if (!kc_p2p_parse_ok_key(recv_buf, obs_key)) {
            fprintf(stderr, "p2p: registration failed: %s\n", recv_buf);
            KC_P2P_FD_CLOSE(control_fd);
            if (!KC_P2P_ISERR(udp_fd)) KC_P2P_FD_CLOSE(udp_fd);
            return KC_P2P_ERROR;
        }
        memcpy(ctx->key, obs_key, KC_P2P_KEY_STR_SZ);
        ctx->key[KC_P2P_KEY_STR_SZ - 1] = '\0';
        kc_p2p_save_key(self_id, ctx->key);
    }

    fprintf(stderr, "p2p: published %s backend 127.0.0.1:%u as '%s'\n",
        ctx->proto == KC_P2P_PROTO_TCP ? "tcp" : "udp",
        (unsigned)ctx->bind_port, self_id);

    {
        kc_p2p_udp_server_session_t *sessions;
        int n_sessions;
        int cap_sessions;
        int n, i;

        sessions = NULL;
        n_sessions = 0;
        cap_sessions = 0;
        last_heartbeat = kc_p2p_now_s();

        kc_p2p_set_nonblock(control_fd);
        kc_p2p_set_nonblock(udp_fd);

        while (!kc_p2p_stop_requested) {
            fd_set fds;
            struct timeval tv;
            int maxfd;

            FD_ZERO(&fds);
            FD_SET(control_fd, &fds);
            FD_SET(udp_fd, &fds);
            maxfd = (int)(control_fd > udp_fd ? control_fd : udp_fd);

            for (i = 0; i < n_sessions; i++) {
                if (!sessions[i].active) continue;
                if (sessions[i].backend_fd != KC_P2P_FD_INVALID) {
                    if (sessions[i].is_tcp &&
                        !kc_p2p_stream_can_send_data(&sessions[i].stream) &&
                        !sessions[i].stream.out.local_eof)
                        continue;
                    FD_SET(sessions[i].backend_fd, &fds);
                    if ((int)sessions[i].backend_fd > maxfd) maxfd = (int)sessions[i].backend_fd;
                }
            }

            tv.tv_sec = 1; tv.tv_usec = 0;
            n = select(maxfd + 1, &fds, NULL, NULL, &tv);
            if (n < 0) continue;
            if (kc_p2p_stop_requested) break;

            if (kc_p2p_now_s() - last_heartbeat >= KC_P2P_HEARTBEAT_S) {
                snprintf(send_buf, sizeof(send_buf), "REGISTER:%s", self_id);
                kc_p2p_tcp_send(control_fd, send_buf);
                last_heartbeat = kc_p2p_now_s();
            }

            if (FD_ISSET(control_fd, &fds)) {
                if (kc_p2p_tcp_readline(control_fd, recv_buf,
                    (int)sizeof(recv_buf), 0) > 0)
                {
                    char conn_id[KC_P2P_ID_MAX + 1];
                    char remote_token[KC_P2P_CTRL_SESSION_MAX + 1];
                    char sess_hex[KC_P2P_STREAM_SESSION_ID_SZ * 2 + 1];
                    unsigned char sess_id[KC_P2P_STREAM_SESSION_ID_SZ];

                    memset(sess_hex, 0, sizeof(sess_hex));

                    if (kc_p2p_parse_punch_call2(recv_buf, conn_id,
                        remote_token))
                    {
                        if (ctx->proto == KC_P2P_PROTO_TCP) {
                            memcpy(sess_hex, remote_token,
                                KC_P2P_STREAM_SESSION_ID_SZ * 2);
                            sess_hex[KC_P2P_STREAM_SESSION_ID_SZ * 2] = '\0';
                            if (!kc_p2p_hex_decode(sess_hex, sess_id, sizeof(sess_id)))
                                continue;
                        }

                        {
                            char lbuf[128];
                            int saw_end = 0;
                            while (kc_p2p_tcp_readline(control_fd, lbuf, sizeof(lbuf), 5) > 0) {
                                if (!kc_p2p_append_text(recv_buf,
                                    sizeof(recv_buf), "\n") ||
                                    !kc_p2p_append_text(recv_buf,
                                        sizeof(recv_buf), lbuf))
                                    break;
                                if (strcmp(lbuf, "END") == 0) {
                                    saw_end = 1;
                                    break;
                                }
                            }
                            if (saw_end && !kc_p2p_append_text(recv_buf,
                                sizeof(recv_buf), "\n"))
                                continue;
                            if (!saw_end) continue;
                        }
                        kc_p2p_candidate_t remote_cands[KC_P2P_CANDIDATES_MAX];
                        int remote_cand_count = 0;
                        if (!kc_p2p_parse_remote_candidates(recv_buf,
                            remote_cands, &remote_cand_count))
                            continue;
                        kc_p2p_candidate_t my_cands[KC_P2P_CANDIDATES_MAX];
                        int my_cand_count = 0;
                        char ack_buf[KC_P2P_BUF];
                        const char *ack_sess = sess_hex[0] ? sess_hex : remote_token;

                        kc_p2p_gather_candidates(ctx, udp_fd, my_cands,
                            KC_P2P_CANDIDATES_MAX, &my_cand_count);
                        snprintf(ack_buf, sizeof(ack_buf), "PUNCH_ACK2:%s:%s:%s\n",
                            self_id, conn_id, ack_sess);
                        for (int ci = 0; ci < my_cand_count; ci++) {
                            if (!kc_p2p_append_candidate(ack_buf,
                                sizeof(ack_buf), &my_cands[ci]))
                                continue;
                        }
                        if (!kc_p2p_append_text(ack_buf, sizeof(ack_buf),
                            "END\n"))
                            continue;
                        kc_p2p_tcp_send(control_fd, ack_buf);
                        
                        struct sockaddr_storage peer;
                        memset(&peer, 0, sizeof(peer));
                        if (kc_p2p_punch_select(ctx, ctx->sweep, udp_fd, ack_sess,
                            self_id, conn_id, remote_cands, remote_cand_count,
                            &peer) != KC_P2P_OK)
                            continue;

                        int found = -1;
                        for (i = 0; i < n_sessions; i++) {
                            if (!sessions[i].active) continue;
                            if (kc_p2p_sockaddr_equal(&sessions[i].peer_addr,
                                &peer)) {
                                found = i; break;
                            }
                        }

                        if (found < 0) {
                            kc_p2p_udp_server_session_t sess;
                            memset(&sess, 0, sizeof(sess));
                            sess.peer_addr = peer;
                            sess.last_rx = kc_p2p_now_s();
                            sess.last_ka = sess.last_rx;
                            sess.is_tcp = (ctx->proto == KC_P2P_PROTO_TCP) ? 1 : 0;
                            sess.tcp_fd = KC_P2P_FD_INVALID;

                            if (sess.is_tcp) {
                                sess.backend_fd = kc_p2p_connect_local_tcp(ctx->bind_port);
                                if (KC_P2P_ISERR(sess.backend_fd)) {
                                    fprintf(stderr, "p2p: local backend connect failed on 127.0.0.1:%u\n",
                                        (unsigned)ctx->bind_port);
                                    continue;
                                }
                                kc_p2p_stream_init(&sess.stream, 0, sess_id, sess_hex);
                                if (!kc_p2p_stream_crypto_init(&sess.stream)) {
                                    KC_P2P_FD_CLOSE(sess.backend_fd);
                                    continue;
                                }
                            } else {
                                sess.backend_fd = kc_p2p_create_socket(udp_any_host, 0);
                                if (KC_P2P_ISERR(sess.backend_fd)) continue;
                            }
                            sess.active = 1;

                            if (n_sessions >= cap_sessions) {
                                int new_cap = cap_sessions == 0 ? 8 : cap_sessions * 2;
                                kc_p2p_udp_server_session_t *new_sessions =
                                    (kc_p2p_udp_server_session_t *)realloc(
                                        sessions, (size_t)new_cap * sizeof(*sessions));
                                if (!new_sessions) {
                                    KC_P2P_FD_CLOSE(sess.backend_fd);
                                    continue;
                                }
                                sessions = new_sessions;
                                cap_sessions = new_cap;
                            }
                            sessions[n_sessions++] = sess;

                            kc_p2p_sendto_addr(udp_fd, "P2P_PUNCH:server", 16,
                                &peer);
                        } else {
                            kc_p2p_sendto_addr(udp_fd, "P2P_PUNCH:server", 16,
                                &peer);
                        }
                    }
                }
            }

            if (FD_ISSET(udp_fd, &fds)) {
                char buf[KC_P2P_BUF + 1];
                struct sockaddr_storage from;
                socklen_t fromlen = sizeof(from);
                int recv_flags = 0;
#ifndef _WIN32
                recv_flags |= MSG_TRUNC;
#endif
                n = (int)recvfrom(udp_fd, buf, KC_P2P_BUF, recv_flags,
                    (struct sockaddr *)&from, &fromlen);
                if (n > 0) {
#ifndef _WIN32
                    if ((size_t)n > KC_P2P_BUF) return -1;
#endif
                    if ((size_t)n >= sizeof(buf)) n = (int)(sizeof(buf) - 1);
                    buf[n] = '\0';

                    int found = -1;
                    for (i = 0; i < n_sessions; i++) {
                        if (!sessions[i].active) continue;
                        if (kc_p2p_sockaddr_equal(&sessions[i].peer_addr,
                            &from)) {
                            found = i; break;
                        }
                    }

                    if (found >= 0) {
                        if (strncmp(buf, "P2P_KA:", 7) == 0 ||
                            strncmp(buf, "P2P_PUNCH:", 10) == 0 ||
                            strncmp(buf, "PUNCH_PING:", 11) == 0 ||
                            strncmp(buf, "PUNCH_PONG:", 11) == 0) {
                            sessions[found].last_rx = kc_p2p_now_s();
                        } else {
                            if (sessions[found].is_tcp) {
                                if (sessions[found].backend_fd != KC_P2P_FD_INVALID &&
                                    kc_p2p_stream_process_packet(ctx, udp_fd,
                                        &sessions[found].peer_addr,
                                        &sessions[found].stream,
                                        sessions[found].backend_fd,
                                        (const unsigned char *)buf,
                                        (size_t)n) != 0)
                                {
                                    kc_p2p_server_session_close(&sessions[found]);
                                }
                            } else {
                                struct sockaddr_in backend_addr;
                                memset(&backend_addr, 0, sizeof(backend_addr));
                                backend_addr.sin_family = AF_INET;
                                backend_addr.sin_port = htons(ctx->bind_port);
                                inet_pton(AF_INET, "127.0.0.1", &backend_addr.sin_addr);
                                sendto(sessions[found].backend_fd, buf, (size_t)n, 0,
                                    (const struct sockaddr *)&backend_addr, sizeof(backend_addr));
                            }
                            sessions[found].last_rx = kc_p2p_now_s();
                        }
                    } else if (strncmp(buf, "PUNCH_PING:", 11) == 0) {
                        char pong[256];
                        char ping_sess[64] = {0}, ping_from[64] = {0}, ping_to[64] = {0};
                        if (kc_p2p_parse_punch_packet(buf, "PUNCH_PING:",
                            ping_sess, ping_from, ping_to))
                        {
                            snprintf(pong, sizeof(pong), "PUNCH_PONG:%s:%s:%s",
                                ping_sess, ping_to, ping_from);
                            sendto(udp_fd, pong, strlen(pong), 0,
                                (const struct sockaddr *)&from, fromlen);
                        }
                    } else {
                        int unset = -1;
                        for (i = 0; i < n_sessions; i++) {
                            if (!sessions[i].active) continue;
                            if (kc_p2p_sockaddr_port(&sessions[i].peer_addr) == 0) { unset = i; break; }
                        }
                        if (unset >= 0) {
                            sessions[unset].peer_addr = from;
                            sessions[unset].last_rx = kc_p2p_now_s();
                            sessions[unset].last_ka = sessions[unset].last_rx;
                            kc_p2p_sendto_addr(udp_fd, buf, (size_t)n, &from);
                            if (strncmp(buf, "P2P_PUNCH:", 10) != 0 &&
                                strncmp(buf, "P2P_KA:", 7) != 0) {
                                if (sessions[unset].is_tcp) {
                                    if (sessions[unset].backend_fd != KC_P2P_FD_INVALID &&
                                        kc_p2p_stream_process_packet(ctx, udp_fd,
                                            &sessions[unset].peer_addr,
                                            &sessions[unset].stream,
                                            sessions[unset].backend_fd,
                                            (const unsigned char *)buf,
                                            (size_t)n) != 0)
                                    {
                                        kc_p2p_server_session_close(&sessions[unset]);
                                    }
                                } else {
                                    struct sockaddr_in backend_addr;
                                    memset(&backend_addr, 0, sizeof(backend_addr));
                                    backend_addr.sin_family = AF_INET;
                                    backend_addr.sin_port = htons(ctx->bind_port);
                                    inet_pton(AF_INET, "127.0.0.1", &backend_addr.sin_addr);
                                    sendto(sessions[unset].backend_fd, buf, (size_t)n, 0,
                                        (const struct sockaddr *)&backend_addr, sizeof(backend_addr));
                                }
                            }
                        } else if (strncmp(buf, "P2P_PUNCH:", 10) == 0) {
                            kc_p2p_sendto_addr(udp_fd, buf, (size_t)n, &from);
                        }
                    }
                }
            }

            for (i = 0; i < n_sessions; i++) {
                if (!sessions[i].active) continue;
                if (sessions[i].backend_fd == KC_P2P_FD_INVALID) continue;
                if (!FD_ISSET(sessions[i].backend_fd, &fds)) continue;

                if (sessions[i].is_tcp) {
                    if (kc_p2p_stream_pump_tcp(ctx, udp_fd,
                        &sessions[i].peer_addr, &sessions[i].stream,
                        sessions[i].backend_fd) != 0)
                    {
                        kc_p2p_server_session_close(&sessions[i]);
                    }
                } else {
                    char buf[KC_P2P_BUF];
                    struct sockaddr_in bfrom;
                    socklen_t bfromlen = sizeof(bfrom);
                    n = (int)recvfrom(sessions[i].backend_fd, buf, sizeof(buf), 0,
                        (struct sockaddr *)&bfrom, &bfromlen);
                    if (n > 0) {
                        kc_p2p_sendto_addr(udp_fd, buf, (size_t)n,
                            &sessions[i].peer_addr);
                        sessions[i].last_rx = kc_p2p_now_s();
                    }
                }
            }

            for (i = 0; i < n_sessions; i++) {
                if (!sessions[i].active) continue;
                if (sessions[i].is_tcp) {
                    if (kc_p2p_stream_tick(ctx, udp_fd,
                        &sessions[i].peer_addr, &sessions[i].stream) != 0)
                    {
                        kc_p2p_server_session_close(&sessions[i]);
                        continue;
                    }
                    if (kc_p2p_stream_is_done(&sessions[i].stream)) {
                        kc_p2p_server_session_close(&sessions[i]);
                        continue;
                    }
                }
                if (kc_p2p_now_s() - sessions[i].last_ka > KC_P2P_KEEPALIVE_S) {
                kc_p2p_sendto_addr(udp_fd, "P2P_KA:", 7,
                    &sessions[i].peer_addr);
                    sessions[i].last_ka = kc_p2p_now_s();
                }
                if (kc_p2p_now_s() - sessions[i].last_rx > KC_P2P_DISCONNECT_S) {
                    kc_p2p_server_session_close(&sessions[i]);
                }
            }
        }

        for (i = 0; i < n_sessions; i++) {
            if (!sessions[i].active) continue;
            kc_p2p_server_session_close(&sessions[i]);
        }
        free(sessions);
    }

    if (ctx->key[0] != '\0')
        kc_p2p_deregister(ctx, index_host, index_port, self_id);

    KC_P2P_FD_CLOSE(control_fd);
    KC_P2P_FD_CLOSE(udp_fd);
    return KC_P2P_OK;
}

/**
 * send punch req.
 * @return 0 on success, -1 on error.
 */

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
static int kc_p2p_send_punch_req_cands(
    kc_p2p_fd_t ctrl_fd,
    const char *self_id,
    const char *target_id,
    const char *session_id,
    kc_p2p_candidate_t *cands,
    int cand_count,
    kc_p2p_candidate_t *remote_cands,
    int *remote_cand_count)
{
    char send_buf[KC_P2P_BUF];
    char recv_buf[KC_P2P_BUF];
    int n;
    
    n = snprintf(send_buf, sizeof(send_buf), "PUNCH_REQ2:%s:%s:%s\n",
        self_id, target_id, session_id ? session_id : "0");
    if (n < 0 || (size_t)n >= sizeof(send_buf)) return KC_P2P_ERROR;
    for (int i = 0; i < cand_count; i++) {
        if (!kc_p2p_append_candidate(send_buf, sizeof(send_buf), &cands[i]))
            return KC_P2P_ERROR;
    }
    if (!kc_p2p_append_text(send_buf, sizeof(send_buf), "END\n"))
        return KC_P2P_ERROR;
    
    if (kc_p2p_tcp_send(ctrl_fd, send_buf) != KC_P2P_OK)
        return KC_P2P_ENET;
    if (kc_p2p_tcp_readline(ctrl_fd, recv_buf, (int)sizeof(recv_buf), 20) < 0)
        return KC_P2P_OK;
    
    if (strncmp(recv_buf, "PUNCH_OK2:", 10) == 0) {
        char lbuf[128];
        char ok_id[KC_P2P_ID_MAX + 1];
        char ok_sess[KC_P2P_CTRL_SESSION_MAX + 1];
        int saw_end = 0;
        if (!kc_p2p_parse_punch_ok2(recv_buf, ok_id, ok_sess))
            return KC_P2P_ERROR;
        while (kc_p2p_tcp_readline(ctrl_fd, lbuf, sizeof(lbuf), 5) > 0) {
            if (!kc_p2p_append_text(recv_buf, sizeof(recv_buf), "\n") ||
                !kc_p2p_append_text(recv_buf, sizeof(recv_buf), lbuf))
                return KC_P2P_ERROR;
            if (strcmp(lbuf, "END") == 0) {
                saw_end = 1;
                break;
            }
        }
        if (saw_end && !kc_p2p_append_text(recv_buf, sizeof(recv_buf), "\n"))
            return KC_P2P_ERROR;
        if (!saw_end) return KC_P2P_ERROR;
        if (!kc_p2p_parse_remote_candidates(recv_buf, remote_cands,
            remote_cand_count))
            return KC_P2P_ERROR;
    }
    return KC_P2P_OK;
}

/**
 * open udp session.
 * @return 0 on success, -1 on error.
 */

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
static int kc_p2p_open_udp_session_cands(
    kc_p2p_t *ctx,
    int sweep_limit,
    int fd,
    const char *self_id,
    const char *target_id,
    const char *session_id,
    kc_p2p_candidate_t *remote_cands,
    int remote_cand_count,
    kc_p2p_fd_t *out_fd,
    struct sockaddr_storage *out_peer,
    kc_p2p_udp_consumer_session_t *sess)
{
    struct sockaddr_storage peer_addr;
    memset(&peer_addr, 0, sizeof(peer_addr));

    int rc = kc_p2p_punch_select(ctx, sweep_limit, fd, session_id ? session_id : "0", self_id, target_id, remote_cands, remote_cand_count, &peer_addr);
    if (rc != KC_P2P_OK) {
        fprintf(stderr, "p2p: udp punch failed\n");
        KC_P2P_FD_CLOSE(fd);
        return rc;
    }

    (void)ctx;
    (void)sess;

    *out_fd = fd;
    *out_peer = peer_addr;
    return KC_P2P_OK;
}

/**
 * connect.
 * @return 0 on success, -1 on error.
 */

/**
 * Connect.
 * @return 0 on success, -1 on error.
 */
int kc_p2p_connect(
    kc_p2p_t *ctx,
    const char *index_host,
    unsigned short index_port,
    const char *self_id,
    const char *target_id,
    unsigned short bind_port)
{
    kc_p2p_fd_t ctrl_fd;
    kc_p2p_fd_t local_fd;
    kc_p2p_fd_t tcp_listen_fd;
    kc_p2p_udp_consumer_session_t *sessions;
    const char *udp_any_host;
    int n_sessions, cap_sessions;

    (void)bind_port;
    if (!ctx) return KC_P2P_ERROR;
    if (ctx->bind_port == 0) return KC_P2P_ERROR;
    if (kc_p2p_platform_init() != 0) return KC_P2P_ENET;
    udp_any_host = kc_p2p_host_is_ipv6_literal(index_host) ? "::" : "0.0.0.0";

    if (ctx->proto == KC_P2P_PROTO_UDP) {
        local_fd = kc_p2p_create_socket("127.0.0.1", ctx->bind_port);
        if (KC_P2P_ISERR(local_fd)) { kc_p2p_platform_cleanup(); return KC_P2P_ENET; }
        tcp_listen_fd = KC_P2P_FD_INVALID;
    } else {
        local_fd = kc_p2p_create_socket(udp_any_host, 0);
        if (KC_P2P_ISERR(local_fd)) { kc_p2p_platform_cleanup(); return KC_P2P_ENET; }
        tcp_listen_fd = kc_p2p_create_tcp_listener("127.0.0.1", ctx->bind_port);
        if (KC_P2P_ISERR(tcp_listen_fd)) {
            KC_P2P_FD_CLOSE(local_fd);
            kc_p2p_platform_cleanup();
            return KC_P2P_ENET;
        }
    }

    ctrl_fd = kc_p2p_control_connect(index_host, index_port);
    if (KC_P2P_ISERR(ctrl_fd)) {
        KC_P2P_FD_CLOSE(local_fd);
        if (!KC_P2P_ISERR(tcp_listen_fd)) KC_P2P_FD_CLOSE(tcp_listen_fd);
        kc_p2p_platform_cleanup();
        return KC_P2P_ENET;
    }
    {
        char recv_buf[KC_P2P_BUF];
        snprintf(recv_buf, sizeof(recv_buf), "LOOKUP:%s", target_id);
        if (kc_p2p_tcp_send(ctrl_fd, recv_buf) != KC_P2P_OK ||
            kc_p2p_tcp_readline(ctrl_fd, recv_buf, (int)sizeof(recv_buf), 5) < 0)
        { KC_P2P_FD_CLOSE(ctrl_fd); KC_P2P_FD_CLOSE(local_fd); if (!KC_P2P_ISERR(tcp_listen_fd)) KC_P2P_FD_CLOSE(tcp_listen_fd); kc_p2p_platform_cleanup(); return KC_P2P_ENET; }
        if (strcmp(recv_buf, "NOT_FOUND") == 0)
        { KC_P2P_FD_CLOSE(ctrl_fd); KC_P2P_FD_CLOSE(local_fd); if (!KC_P2P_ISERR(tcp_listen_fd)) KC_P2P_FD_CLOSE(tcp_listen_fd); kc_p2p_platform_cleanup(); return KC_P2P_ENOENT; }
        if (strcmp(recv_buf, "PEER:") == 0 ||
            strncmp(recv_buf, "PEER:", 5) != 0 ||
            strcmp(recv_buf + 5, target_id) != 0)
        { KC_P2P_FD_CLOSE(ctrl_fd); KC_P2P_FD_CLOSE(local_fd); if (!KC_P2P_ISERR(tcp_listen_fd)) KC_P2P_FD_CLOSE(tcp_listen_fd); kc_p2p_platform_cleanup(); return KC_P2P_ERROR; }
    }
    KC_P2P_FD_CLOSE(ctrl_fd);

    sessions = NULL;
    n_sessions = 0;
    cap_sessions = 0;

    fprintf(stderr, "p2p: %s relay on 127.0.0.1:%u for %s\n",
        ctx->proto == KC_P2P_PROTO_TCP ? "tcp" : "udp",
        (unsigned)ctx->bind_port, target_id);

    kc_p2p_set_nonblock(local_fd);
    if (!KC_P2P_ISERR(tcp_listen_fd)) kc_p2p_set_nonblock(tcp_listen_fd);

    while (!kc_p2p_stop_requested) {
        fd_set fds;
        struct timeval tv;
        int maxfd;
        int n, i;

        FD_ZERO(&fds);
        FD_SET(local_fd, &fds);
        maxfd = (int)local_fd;

        if (!KC_P2P_ISERR(tcp_listen_fd)) {
            FD_SET(tcp_listen_fd, &fds);
            if ((int)tcp_listen_fd > maxfd) maxfd = (int)tcp_listen_fd;
        }

        for (i = 0; i < n_sessions; i++) {
            if (!sessions[i].active) continue;
            FD_SET(sessions[i].fd, &fds);
            if ((int)sessions[i].fd > maxfd) maxfd = (int)sessions[i].fd;
            if (sessions[i].is_tcp && sessions[i].tcp_fd != KC_P2P_FD_INVALID) {
                if (!kc_p2p_stream_can_send_data(&sessions[i].stream) &&
                    !sessions[i].stream.out.local_eof)
                    continue;
                FD_SET(sessions[i].tcp_fd, &fds);
                if ((int)sessions[i].tcp_fd > maxfd) maxfd = (int)sessions[i].tcp_fd;
            }
        }
        tv.tv_sec = 1; tv.tv_usec = 0;
        n = select(maxfd + 1, &fds, NULL, NULL, &tv);
        if (n < 0) continue;
        if (kc_p2p_stop_requested) break;

        if (!KC_P2P_ISERR(tcp_listen_fd) && FD_ISSET(tcp_listen_fd, &fds)) {
            kc_p2p_fd_t client_fd = accept(tcp_listen_fd, NULL, NULL);
            if (!KC_P2P_ISERR(client_fd)) {
                ctrl_fd = kc_p2p_control_connect(index_host, index_port);
                if (!KC_P2P_ISERR(ctrl_fd)) {
                    unsigned char sess_id_bin[KC_P2P_STREAM_SESSION_ID_SZ];
                    
                    kc_p2p_candidate_t cands[KC_P2P_CANDIDATES_MAX];
                    int cand_count = 0;
                    kc_p2p_candidate_t remote_cands[KC_P2P_CANDIDATES_MAX];
                    int remote_cand_count = 0;
                    char sess_id[KC_P2P_STREAM_SESSION_ID_SZ * 2 + 1];
                    if (!kc_p2p_stream_make_session_id(sess_id_bin, sess_id)) {
                        KC_P2P_FD_CLOSE(ctrl_fd);
                        KC_P2P_FD_CLOSE(client_fd);
                        continue;
                    }
                    
                    int temp_udp = kc_p2p_create_socket(udp_any_host, 0);
                    kc_p2p_gather_candidates(ctx, temp_udp, cands,
                        KC_P2P_CANDIDATES_MAX, &cand_count);
                    
                    kc_p2p_send_punch_req_cands(ctrl_fd, self_id, target_id, sess_id, cands, cand_count, remote_cands, &remote_cand_count);
                    KC_P2P_FD_CLOSE(ctrl_fd);

                    {
                        kc_p2p_udp_consumer_session_t sess;
                        memset(&sess, 0, sizeof(sess));
                        if (kc_p2p_open_udp_session_cands(
                            ctx, ctx->sweep, temp_udp, self_id, target_id, sess_id,
                            remote_cands, remote_cand_count,
                            &sess.fd, &sess.peer_addr, &sess) == KC_P2P_OK)
                        {
                            kc_p2p_stream_init(&sess.stream, 1, sess_id_bin, sess_id);
                            if (!kc_p2p_stream_crypto_init(&sess.stream)) {
                                KC_P2P_FD_CLOSE(sess.fd);
                                KC_P2P_FD_CLOSE(client_fd);
                                continue;
                            }
                            sess.tcp_fd = client_fd;
                            sess.active = 1;
                            sess.is_tcp = 1;
                            sess.last_rx = kc_p2p_now_s();
                            sess.last_ka = sess.last_rx;
                            memset(&sess.client_addr, 0, sizeof(sess.client_addr));
                            if (n_sessions >= cap_sessions) {
                                int new_cap = cap_sessions == 0 ? 8 : cap_sessions * 2;
                                kc_p2p_udp_consumer_session_t *new_sessions =
                                    (kc_p2p_udp_consumer_session_t *)realloc(
                                        sessions, (size_t)new_cap * sizeof(*sessions));
                                if (!new_sessions) { KC_P2P_FD_CLOSE(sess.fd); KC_P2P_FD_CLOSE(client_fd); continue; }
                                sessions = new_sessions;
                                cap_sessions = new_cap;
                            }
                            sessions[n_sessions++] = sess;
                        } else {
                            KC_P2P_FD_CLOSE(client_fd);
                        }
                    }
                } else {
                    KC_P2P_FD_CLOSE(client_fd);
                }
            }
        }

        if (!KC_P2P_ISERR(tcp_listen_fd)) {
            for (i = 0; i < n_sessions; i++) {
                if (!sessions[i].active) continue;
                if (!FD_ISSET(sessions[i].tcp_fd, &fds)) continue;
                if (kc_p2p_stream_pump_tcp(ctx, sessions[i].fd,
                    &sessions[i].peer_addr, &sessions[i].stream,
                    sessions[i].tcp_fd) != 0)
                {
                    kc_p2p_consumer_session_close(&sessions[i]);
                }
            }
        } else if (FD_ISSET(local_fd, &fds)) {
            char buf[KC_P2P_BUF];
            struct sockaddr_storage from;
            socklen_t fromlen = sizeof(from);
            int found;

            n = (int)recvfrom(local_fd, buf, sizeof(buf), 0,
                (struct sockaddr *)&from, &fromlen);
            if (n > 0) {
                found = -1;
                for (i = 0; i < n_sessions; i++) {
                    if (!sessions[i].active) continue;
                    if (kc_p2p_sockaddr_equal(&sessions[i].client_addr,
                        &from)) {
                        found = i; break;
                    }
                }
                if (found < 0) {
                    kc_p2p_udp_consumer_session_t sess;
                    memset(&sess, 0, sizeof(sess));

                    ctrl_fd = kc_p2p_control_connect(index_host, index_port);
                    if (!KC_P2P_ISERR(ctrl_fd)) {
                        kc_p2p_candidate_t cands[KC_P2P_CANDIDATES_MAX];
                        int cand_count = 0;
                        kc_p2p_candidate_t remote_cands[KC_P2P_CANDIDATES_MAX];
                        int remote_cand_count = 0;
                        unsigned char sess_random[8];
                        char sess_id[17];
                        if (kc_p2p_fill_random(sess_random, sizeof(sess_random)) != 0 ||
                            !kc_p2p_hex_encode(sess_random, sizeof(sess_random),
                                sess_id, sizeof(sess_id)))
                        {
                            KC_P2P_FD_CLOSE(ctrl_fd);
                            goto udp_skip;
                        }
                        
                        int temp_udp = kc_p2p_create_socket(udp_any_host, 0);
                        kc_p2p_gather_candidates(ctx, temp_udp, cands,
                            KC_P2P_CANDIDATES_MAX, &cand_count);
                        
                        kc_p2p_send_punch_req_cands(ctrl_fd, self_id, target_id, sess_id, cands, cand_count, remote_cands, &remote_cand_count);
                        KC_P2P_FD_CLOSE(ctrl_fd);

                        if (kc_p2p_open_udp_session_cands(
                            ctx, ctx->sweep, temp_udp, self_id, target_id, sess_id,
                            remote_cands, remote_cand_count,
                            &sess.fd, &sess.peer_addr, &sess) == KC_P2P_OK)
                        {
                            sess.client_addr = from;
                            sess.last_rx = kc_p2p_now_s();
                            sess.last_ka = sess.last_rx;
                            sess.active = 1;
                            sess.is_tcp = 0;
                            sess.tcp_fd = KC_P2P_FD_INVALID;
                            if (n_sessions >= cap_sessions) {
                                int new_cap = cap_sessions == 0 ? 8 : cap_sessions * 2;
                                kc_p2p_udp_consumer_session_t *new_sessions =
                                    (kc_p2p_udp_consumer_session_t *)realloc(
                                        sessions, (size_t)new_cap * sizeof(*sessions));
                                if (!new_sessions) { KC_P2P_FD_CLOSE(sess.fd); goto udp_skip; }
                                sessions = new_sessions; cap_sessions = new_cap;
                            }
                            sessions[n_sessions++] = sess;
                            found = n_sessions - 1;
                        }
                    }
                }
udp_skip:
                if (found >= 0) {
                    kc_p2p_sendto_addr(sessions[found].fd, buf, (size_t)n,
                        &sessions[found].peer_addr);
                    sessions[found].last_rx = kc_p2p_now_s();
                }
            }
        }

        for (i = 0; i < n_sessions; i++) {
            if (!sessions[i].active) continue;
            if (!FD_ISSET(sessions[i].fd, &fds)) continue;
            char buf[KC_P2P_BUF];
            struct sockaddr_storage from;
            socklen_t fromlen = sizeof(from);
            n = (int)recvfrom(sessions[i].fd, buf, sizeof(buf), 0,
                (struct sockaddr *)&from, &fromlen);
            if (n > 0) {
                if ((n >= 7 && strncmp(buf, "P2P_KA:", 7) == 0) ||
                    (n >= 10 && strncmp(buf, "P2P_PUNCH:", 10) == 0) ||
                    (n >= 11 && strncmp(buf, "PUNCH_PING:", 11) == 0) ||
                    (n >= 11 && strncmp(buf, "PUNCH_PONG:", 11) == 0)) {
                    sessions[i].last_rx = kc_p2p_now_s();
                } else {
                    if (sessions[i].is_tcp) {
                        if (sessions[i].tcp_fd != KC_P2P_FD_INVALID &&
                            kc_p2p_stream_process_packet(ctx, sessions[i].fd,
                                &sessions[i].peer_addr,
                                &sessions[i].stream, sessions[i].tcp_fd,
                                (const unsigned char *)buf, (size_t)n) != 0)
                        {
                            kc_p2p_consumer_session_close(&sessions[i]);
                        }
                    } else {
                        kc_p2p_sendto_addr(local_fd, buf, (size_t)n,
                            &sessions[i].client_addr);
                    }
                    sessions[i].last_rx = kc_p2p_now_s();
                }
            }
        }

        for (i = 0; i < n_sessions; i++) {
            if (!sessions[i].active) continue;
            if (sessions[i].is_tcp) {
                if (kc_p2p_stream_tick(ctx, sessions[i].fd,
                    &sessions[i].peer_addr, &sessions[i].stream) != 0)
                {
                    kc_p2p_consumer_session_close(&sessions[i]);
                    continue;
                }
                if (kc_p2p_stream_is_done(&sessions[i].stream)) {
                    kc_p2p_consumer_session_close(&sessions[i]);
                    continue;
                }
            }
            if (kc_p2p_now_s() - sessions[i].last_ka > KC_P2P_KEEPALIVE_S) {
                kc_p2p_sendto_addr(sessions[i].fd, "P2P_KA:", 7,
                    &sessions[i].peer_addr);
                sessions[i].last_ka = kc_p2p_now_s();
            }
            if (kc_p2p_now_s() - sessions[i].last_rx > KC_P2P_DISCONNECT_S) {
                kc_p2p_consumer_session_close(&sessions[i]);
            }
        }
    }

    for (int cleanup_i = 0; cleanup_i < n_sessions; cleanup_i++) {
        if (!sessions[cleanup_i].active) continue;
        kc_p2p_consumer_session_close(&sessions[cleanup_i]);
    }
    free(sessions);
    KC_P2P_FD_CLOSE(local_fd);
    if (!KC_P2P_ISERR(tcp_listen_fd)) KC_P2P_FD_CLOSE(tcp_listen_fd);
    kc_p2p_platform_cleanup();
    return KC_P2P_OK;
}

#ifdef KC_P2P_TEST_RANDOM
/**
 * Generates one registration key through the test-visible path.
 * @param out Output key buffer.
 * @return 1 on success, 0 on error.
 */
int kc_p2p_test_generate_key(char *out) {
    return kc_p2p_generate_key(out);
}

/**
 * Generates one STUN transaction identifier through the test-visible path.
 * @param out Output transaction identifier.
 * @return 1 on success, 0 on error.
 */
int kc_p2p_test_stun_gen_id(unsigned char out[12]) {
    return kc_p2p_stun_gen_id(out);
}

/**
 * Generates one stream session identifier through the test-visible path.
 * @param out Output binary identifier.
 * @param hex Output hex identifier.
 * @return 1 on success, 0 on error.
 */
int kc_p2p_test_stream_make_session_id(
unsigned char out[KC_P2P_STREAM_SESSION_ID_SZ],
char hex[KC_P2P_STREAM_SESSION_ID_SZ * 2 + 1]
)
{
    return kc_p2p_stream_make_session_id(out, hex);
}

/**
 * Generates one register challenge nonce through the test-visible path.
 * @param hex Output hex nonce.
 * @return 1 on success, 0 on error.
 */
int kc_p2p_test_pow_nonce(char hex[17]) {
    unsigned char nonce[8];

    if (kc_p2p_fill_random(nonce, sizeof(nonce)) != 0) return 0;
    return kc_p2p_hex_encode(nonce, sizeof(nonce), hex, 17);
}

/**
 * Generates one UDP session identifier through the test-visible path.
 * @param hex Output hex session identifier.
 * @return 1 on success, 0 on error.
 */
int kc_p2p_test_udp_session_id(char hex[17]) {
    unsigned char session_id[8];

    if (kc_p2p_fill_random(session_id, sizeof(session_id)) != 0) return 0;
    return kc_p2p_hex_encode(session_id, sizeof(session_id), hex, 17);
}

/**
 * Compares STUN transaction identifiers through the test-visible path.
 * @param expected Expected transaction identifier.
 * @param actual   Actual transaction identifier.
 * @return 1 when equal, 0 otherwise.
 */
int kc_p2p_test_stun_id_matches(const unsigned char expected[12],
const unsigned char actual[12])
{
    return memcmp(expected, actual, 12) == 0;
}
#endif
