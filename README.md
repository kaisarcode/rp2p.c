# hpm.c - HolePunchMan: General P2P communication

`hpm.c` is a small and portable C library and CLI for exposing local TCP or UDP services over peer-to-peer connections.

---

## CLI

### Examples

Start an index server on port 9876:

```bash
hpm idx 9876
```

Start a public index with registration cost:

```bash
hpm idx 9876 --pow 20
```

Start a publisher-protected index:

```bash
HPM_PASS='password' hpm idx 9876
```

Start a publisher-protected index with registration cost:

```bash
HPM_PASS='password' hpm idx 9876 --pow 20
```

Start an index with reserved seats that override the global password:

```bash
HPM_PASS='global' \
HPM_VIP='web webpass
admin adminpass' \
hpm idx 9876
```

Load the same VIP seat map from a text file:

```bash
HPM_PASS='global' \
HPM_VIP="$(cat ./vip.txt)" \
hpm idx 9876
```

With `vip.txt` containing whitespace-separated `<id> <pass>` pairs:

```text
web webpass
admin adminpass

game gamepass
```

Publish a local TCP service on `127.0.0.1:8080`:

```bash
hpm set web@idx.example.com:9876 --tcp 8080
```

Publish with optional STUN discovery enabled on the publisher side:

```bash
hpm set web@idx.example.com:9876 --tcp 8080 \
  --stun stun:stun.cloudflare.com:3478
```

Publish to a protected index:

```bash
HPM_PASS='password' hpm set web@idx.example.com:9876 --tcp 8080
```

Expose that remote TCP service locally on `127.0.0.1:9000`:

```bash
hpm con web@idx.example.com:9876 --tcp 9000
```

Expose it locally with STUN enabled on the consumer side:

```bash
hpm con web@idx.example.com:9876 --tcp 9000 \
  --stun stun:stun.cloudflare.com:3478
```

Consume the service with any local TCP client:

```bash
printf 'ping' | socat - TCP:127.0.0.1:9000
```

Remove one announced host from the index:

```bash
hpm del web@idx.example.com:9876
```

UDP services are exposed the same way:

```bash
hpm set game@idx.example.com:9876 --udp 7777
hpm con game@idx.example.com:9876 --udp 9000
```

UDP services can use STUN on either side too:

```bash
hpm set game@idx.example.com:9876 --udp 7777 \
  --stun stun:stun.cloudflare.com:3478

hpm con game@idx.example.com:9876 --udp 9000 \
  --stun stun:stun.l.google.com:19302
```

Once connected, the remote service can be used like any local TCP port:

```bash
# Terminal 1 (publisher side)
socat TCP-LISTEN:8080,reuseaddr,fork EXEC:cat &
hpm set web@idx.example.com:9876 --tcp 8080

# Terminal 2 (consumer side)
hpm con web@idx.example.com:9876 --tcp 9000
printf 'ping' | socat - TCP:127.0.0.1:9000
```

---

### Parameters

| Command | Description |
| :--- | :--- |
| `idx <port>` | Start an index server on the given TCP control port. |
| `idx <port> --max <N>` | Start an index server and limit announced hosts to `N`. |
| `idx <port> --pow <N>` | Start an index server with PoW challenge of N bits (default 0). |
| `set <host>@<index[:port]> --tcp <port> [--sweep <n>] [--stun <url>]` | Publish one local TCP backend on `127.0.0.1:<port>`. |
| `set <host>@<index[:port]> --udp <port> [--sweep <n>] [--stun <url>]` | Publish one local UDP backend on `127.0.0.1:<port>`. |
| `del <host>@<index[:port]>` | Remove one host from one index. |
| `con <host>@<index[:port]> --tcp <port> [--sweep <n>] [--stun <url>]` | Expose one remote TCP service on `127.0.0.1:<port>`. |
| `con <host>@<index[:port]> --udp <port> [--sweep <n>] [--stun <url>]` | Expose one remote UDP service on `127.0.0.1:<port>`. |
| `-h`, `--help` | Show help and usage. |
| `-v`, `--version` | Show version. |

---

### Syntax notes

The part before `@` (e.g. `web`, `game`) is an arbitrary label you choose to identify your service in the index.
It is **not** a system username, and the index does **not** create user accounts or store credentials, it is simply a key in a plain lookup table.
If nobody has announced `game`, then `hpm con game@idx.example.com:9876` fails with `NOT_FOUND`.
The form `game@idx.example.com` is **not** a URL; you cannot open it in a browser, ping it, or connect to it directly.
It only has meaning inside hpm commands to refer to a registered host on a specific index.

IDs cannot contain whitespace, `@`, or `:` because those characters conflict with the CLI and wire syntax. Password tokens used by `HPM_PASS` and `HPM_VIP` cannot contain whitespace.

`HPM_VIP` is parsed as whitespace-separated `<id> <pass>` pairs, so spaces, tabs, newlines, and blank lines are all treated the same after trimming the full string.

### How the tunnel works

The index is a **TCP-only control plane**.
It handles registration, lookup, candidate exchange, and punch signaling.
It does **not** bind UDP, perform NAT discovery, relay UDP, or carry application payload.

The inter-peer data channel is **UDP-based**.
By default it tries direct UDP hole punching first.
In `--tcp` mode, HPM wraps that UDP path in an internal encrypted reliable stream so local TCP applications still see ordered, reconstructable, full-duplex byte semantics.
Each TCP client session performs a fresh ephemeral key exchange with the remote peer before application data flows, and those session keys are discarded when the session ends.
The `--tcp` and `--udp` flags control how data enters and leaves the tunnel on each end:

| Flag | Publisher side | Consumer side |
| :--- | :--- | :--- |
| `--tcp` | Connects to local TCP service → chunks into HPM encrypted reliable stream frames → sends through UDP hole-punch tunnel | Receives HPM encrypted reliable stream frames → reconstructs ordered byte stream → writes to local TCP client |
| `--udp` | Receives from local UDP service → forwards directly through hole-punch tunnel | Receives from hole-punch tunnel → forwards directly to local UDP client |

`hpm con` creates a local TCP or UDP listener on `127.0.0.1:<listen_port>`. This listener acts as a transparent bridge to the remote service.
You never connect directly to the remote machine; every connection or datagram goes to `127.0.0.1:<listen_port>`, and hpm forwards it through
the UDP transport path to the publisher's backend. From your perspective, the remote service behaves exactly like a local process on that port.
Any tool that speaks TCP or UDP works against the bridge without modification.

### STUN

STUN remains optional because it is an external resource.
It does not relay or carry application payloads, it only helps peers learn which
direct address and port to try for hole punching.
STUN is performed by publishers and consumers against external STUN servers.
The index is not a STUN server and does not observe or validate peer UDP endpoints.

HPM does not support TURN-style fallback. TURN relays application traffic through
a third party, which changes the model from direct peer-to-peer transport to
server-mediated transport. HPM is designed to preserve direct P2P data paths, so
on restrictive NATs where direct connectivity cannot be established, some
sessions may fail instead of degrading to a relay.

## Public API

```c
#include "hpm.h"

kc_hpm_t *ctx;
kc_hpm_open(&ctx);

kc_hpm_set_pow(ctx, 0);
kc_hpm_set_pass(ctx, "password");

kc_hpm_serve_index(ctx, "0.0.0.0", 9876);

kc_hpm_close(ctx);
```

---

## Lifecycle

- `kc_hpm_open()` - allocates and returns a new context owned by the caller.
- `kc_hpm_options_default()` - returns a default options struct for env-backed CLI/runtime configuration.
- `kc_hpm_options_load_env()` - loads `HPM_*` environment values into an options struct.
- `kc_hpm_serve_index()` - starts the index server. Blocking, never returns on success.
- `kc_hpm_deregister()` - removes one host from an index using the stored key.
- `kc_hpm_connect()` - opens a local TCP listener or UDP bridge and creates one peer session per accepted local client or datagram source.
- `kc_hpm_wait()` - registers one host, waits for incoming punch requests, and bridges each session to one local TCP backend or UDP socket.
- `kc_hpm_set_pow()` - configures the `REGISTER` proof difficulty.
- `kc_hpm_set_pass()` - configures the shared password used to derive `REGISTER` proofs.
- `kc_hpm_set_port()` - sets the local service or bridge port used by `set`/`con`.
- `kc_hpm_set_protocol()` - selects TCP or UDP mode before `kc_hpm_wait()` or `kc_hpm_connect()`.
- `kc_hpm_set_sweep()` - sets the UDP port sweep range used during punch fallback.
- `kc_hpm_set_stun_url()` - enables optional STUN discovery for `srflx` candidates.
- `kc_hpm_close()` - releases the context.

---

## Wire Protocol

Index control messages are plain text over TCP. The inter-peer data channel is UDP-based regardless of the `--tcp`/`--udp` flag.
UDP is used only between peers for hole-punch probes, keepalives, and direct payload transport. In `--tcp` mode, application bytes are carried inside HPM's own encrypted reliable stream frames over that UDP path.

| Request | Response |
| :--- | :--- |
| `REGISTER:id` | `CHALLENGE:nonce:bits` |
| `REGISTER:id:SOLUTION:<hex>:PROOF:<hex>` | `OK:KEY:<hex>` or `AUTH_FAILED` |
| `DEREGISTER:id:KEY:<hex>` | `OK` |
| `LIST` | `PEER:id\n...END` |
| `LOOKUP:id` | `PEER:id` or `NOT_FOUND` |
| `PUNCH_REQ2:me:target:session\nCAND:...\nEND` | `PUNCH_OK2:target:session\nCAND:...\nEND` to initiator |
| forwarded by index | `PUNCH_CALL2:me:session\nCAND:...\nEND` to target |
| `PUNCH_PING:...` | Direct peer STUN-like probe (UDP) |
| `PUNCH_PONG:...` | Direct peer STUN-like reply (UDP) |
| `HPM_KA:` | UDP keepalive over direct path |

### TCP Stream Layer

In `--tcp` mode only, peers run an internal session protocol over the selected UDP endpoint after hole punching succeeds.

- Each accepted local TCP client gets its own `session_id`.
- Each session generates a fresh ephemeral keypair on both sides.
- Peers exchange ephemeral public keys before application data flows.
- Session keys are derived per direction and discarded when the session closes.
- DATA frames are encrypted and authenticated.
- Ordering, retransmission, duplicate suppression, and stream reconstruction happen inside HPM.
- `--udp` mode does not use this layer and keeps plain datagram semantics.

Internal TCP stream frame types:

- `HELLO`
- `HELLO_ACK`
- `DATA`
- `ACK`
- `SACK`
- `FIN`
- `FIN_ACK`
- `RESET`
- `PING`
- `PONG`

The deregistration key is generated by the index automatically and stored locally by the announcing host. The user never sets it manually.

---

## Proof-of-Work

By default, the index is a lightweight public rendezvous server with no authentication. When HPM_PASS is set, REGISTER requires a password-derived proof.
Anyone can send REGISTER and occupy a seat. PoW prevents casual or scripted abuse by requiring a computational cost per registration.
It does not stop a determined attacker (e.g. a botnet), but it raises the cost of filling the peer table from near-zero to hours of CPU time.

Each new publisher registration receives a random 8-byte nonce and must answer a challenge using a proof derived from `nonce_hex || self_id || solution_hex`.
The proof is always HMAC-SHA256 keyed by `HPM_PASS`. On a public index, `HPM_PASS` is the empty string. Heartbeats from already-registered peers skip the challenge.

### Wire

```
I <- C: REGISTER:<self_id>
I -> C: CHALLENGE:<nonce_hex>:<bits>
I <- C: REGISTER:<self_id>:SOLUTION:<solution_hex>:PROOF:<proof_hex>
I -> C: OK:KEY:<hex>
```

### CLI

```bash
hpm idx 9876                      # PoW 0 bits (default)
hpm idx 9876 --pow 20             # PoW 20 bits
HPM_PASS='password' hpm idx 9876
HPM_PASS='password' hpm idx 9876 --pow 20
HPM_PASS='global' HPM_VIP='web webpass admin adminpass' hpm idx 9876
```

### Environment

| Variable | Description |
| :--- | :--- |
| `HPM_POW=0` | PoW bits for index registration (overridden by `--pow` flag). |
| `HPM_PASS=password` | Optional shared password used to protect server registration. |
| `HPM_VIP='id pass id pass ...'` | Reserved seat passwords parsed as whitespace-separated `<id> <pass>` pairs. |
| `HPM_SWEEP=32` | UDP port sweep range used during punch fallback. |
| `HPM_STUN=stun:host:port` | Optional STUN server used to discover `srflx` automatically. |
| `HPM_SEATS=1024` | Max announced peers on the index server (overridden by `--max`). |

Internal debug-only environment knobs used for fault-injection tests:

- `HPM_DEBUG_STREAM=1` enables detailed stream logs.
- `HPM_DEBUG_STREAM_DROP_EVERY=N` drops every Nth TCP stream DATA frame once.
- `HPM_DEBUG_STREAM_REORDER_EVERY=N` delays every Nth TCP stream DATA frame once so the next frame arrives first.

`HPM_INDEX` and `HPM_BIND` are parsed by the options loader internally, but the current CLI still requires explicit positional arguments for the index address and explicit command flags for bind behavior.

When `HPM_VIP` defines a password for one seat, that seat must use its VIP password and no longer accepts the global `HPM_PASS`. Seats not listed in `HPM_VIP` still use the global `HPM_PASS`.
If `HPM_VIP` repeats an ID or contains an invalid ID/password token, `hpm idx` fails at startup.

Examples:

```bash
HPM_PASS='global' HPM_VIP='web webpass' hpm idx 9876

HPM_PASS='webpass' hpm set web@idx.example.com:9876 --tcp 8080
HPM_PASS='global' hpm set blog@idx.example.com:9876 --tcp 8080
```

### API

```c
kc_hpm_set_pow(ctx, 0);
kc_hpm_set_pass(ctx, "password");
```

### Cost reference

| Bits | Avg hashes | Desktop (x86_64) | SBC (Cortex-A53) | 32-bit MCU |
| :--- | :--- | :--- | :--- | :--- |
| 0 | none | instant | instant | instant |
| 16 | 65k | ~50ms | ~500ms | ~3s |
| 20 | 1M | ~200ms | ~2s | ~15s |
| **24** | 16M | ~3s | ~30s | ~4min |
| 28 | 268M | ~50s | ~8min | ~1h |
| 32 | 4G | ~15min | ~2h | ~24h |

`HPM_PASS` only controls who may register services in the index. It does not authenticate consumers, encrypt tunnel traffic, or replace application-level authentication.

---

## Notes

- The index uses TCP only and can sit behind a TCP-only tunnel such as Cloudflare Tunnel, ngrok TCP, reverse SSH, or another TCP forwarder.
- The index does not require a public UDP port.
- The index does not relay application traffic.
- The inter-peer transport is UDP-based and stays peer-to-peer.
- `--tcp` now uses an internal encrypted reliable stream over UDP. Local service still communicates over TCP, but HPM handles ordering, retransmission, reconstruction, and payload encryption inside the tunnel.
- `set --tcp <port>` connects to a real local TCP backend on `127.0.0.1:<port>`.
- `con --tcp <port>` exposes a local TCP listener on `127.0.0.1:<port>`.
- Each accepted local TCP client creates a separate peer session.
- The publisher can serve multiple consumers concurrently.
- `--udp` mode forwards UDP datagrams directly through the tunnel with no protocol conversion, ordering, or retransmission.
- `--stun` is opt-in and used only for endpoint discovery. It does not carry application payloads.
- HPM does not implement TURN or relay application traffic through the index or other third-party servers.
- On restrictive NATs where direct UDP connectivity cannot be established, some sessions may fail by design rather than fall back to relayed transport.

---

## Build

Compiled artifacts are generated under `bin/{arch}/{platform}/` for the host architecture running the build.

```bash
make clean && make
```

### Multiarch Builds

The project is prepared to build artifacts for multiple architectures under `bin/{arch}/{platform}/`. A plain `make` builds only the current host architecture, while the targets below build the full matrix or a specific target.

```bash
make all
make x86_64/linux
make x86_64/windows
make i686/linux
make i686/windows
make aarch64/linux
make aarch64/android
make armv7/linux
make armv7/android
make armv7hf/linux
make riscv64/linux
make powerpc64le/linux
make mips/linux
make mipsel/linux
make mips64el/linux
make s390x/linux
make loongarch64/linux
```

---

## Beta Notice

This is a beta project tested only on Debian x86_64. It was created out of a personal need for these libraries, but no guarantees are provided regarding its stability or future support. You are free to test it, use it, and modify it as you please.

If you'd like to reach out, you can send an email to kaisar@kaisarcode.com. Please note that I do not accept pull requests; the goal is to avoid long-term dependency on platforms like GitHub, and I do not maintain fixed infrastructure to guarantee long-term stability for these projects.

---

## License

[![GPLv3](https://www.gnu.org/graphics/gplv3-127x51.png)](https://www.gnu.org/licenses/gpl-3.0.html)

This project is distributed under the **GNU General Public License version 3 (GPLv3)**.
