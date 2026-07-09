# rp2p.c - RedP2P: Peer-to-peer service tunneling

`rp2p.c` is a small and portable C library and CLI for creating direct encrypted tunnels between peers. A minimal TCP index handles temporary registration, lookup, candidate exchange, and hole-punch coordination, while application data travels directly over UDP. TCP and UDP services are adapted at the edges, keeping the core focused, inspectable, and independent of relays, global identities, or centralized data paths.

---

## CLI

### Examples

Start an index server on port 9876:

```bash
rp2p idx 9876
```

Start a public index with registration cost:

```bash
rp2p idx 9876 --pow 20
```

Start a publisher-protected index:

```bash
RP2P_PASS='password' rp2p idx 9876
```

Start a publisher-protected index with registration cost:

```bash
RP2P_PASS='password' rp2p idx 9876 --pow 20
```

Start an index with reserved seats that override the global password:

```bash
RP2P_PASS='global' \
RP2P_VIP='web webpass
admin adminpass' \
rp2p idx 9876
```

Load the same VIP seat map from a text file:

```bash
RP2P_PASS='global' \
RP2P_VIP="$(cat ./vip.txt)" \
rp2p idx 9876
```

With `vip.txt` containing whitespace-separated `<id> <pass>` pairs:

```text
web webpass
admin adminpass

game gamepass
```

Publish a local TCP service on `127.0.0.1:8080`:

```bash
rp2p set web@idx.example.com:9876 --tcp 8080
```

Publish with optional STUN discovery enabled on the publisher side:

```bash
rp2p set web@idx.example.com:9876 --tcp 8080 \
  --stun stun:stun.cloudflare.com:3478
```

Publish to a protected index:

```bash
RP2P_PASS='password' rp2p set web@idx.example.com:9876 --tcp 8080
```

Expose that remote TCP service locally on `127.0.0.1:9000`:

```bash
rp2p con web@idx.example.com:9876 --tcp 9000
```

Expose it locally with STUN enabled on the consumer side:

```bash
rp2p con web@idx.example.com:9876 --tcp 9000 \
  --stun stun:stun.cloudflare.com:3478
```

Consume the service with any local TCP client:

```bash
printf 'ping' | socat - TCP:127.0.0.1:9000
```

Remove one announced host from the index:

```bash
rp2p del web@idx.example.com:9876
```

UDP services are exposed the same way:

```bash
rp2p set game@idx.example.com:9876 --udp 7777
rp2p con game@idx.example.com:9876 --udp 9000
```

UDP services can use STUN on either side too:

```bash
rp2p set game@idx.example.com:9876 --udp 7777 \
  --stun stun:stun.cloudflare.com:3478

rp2p con game@idx.example.com:9876 --udp 9000 \
  --stun stun:stun.l.google.com:19302
```

Once connected, the remote service can be used like any local TCP port:

```bash
# Terminal 1 (publisher side)
socat TCP-LISTEN:8080,reuseaddr,fork EXEC:cat &
rp2p set web@idx.example.com:9876 --tcp 8080

# Terminal 2 (consumer side)
rp2p con web@idx.example.com:9876 --tcp 9000
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
| `-v`, `--version` | Show build version. |

---

### Syntax notes

The part before `@` (e.g. `web`, `game`) is an arbitrary label you choose to identify your service in the index.
It is **not** a system username, and the index does **not** create user accounts or store credentials, it is simply a key in a plain lookup table.
If nobody has announced `game`, then `rp2p con game@idx.example.com:9876` fails with `RP2P_CTRTOK_NOT_FOUND`.
The form `game@idx.example.com` is **not** a URL; you cannot open it in a browser, ping it, or connect to it directly.
It only has meaning inside rp2p commands to refer to a registered host on a specific index.

IDs may contain only ASCII letters and digits (`A-Z`, `a-z`, `0-9`). Password tokens used by `RP2P_PASS` and `RP2P_VIP` are restricted to terminal-safe bytes: letters, digits, and `._-+=,:@%/`.

`RP2P_VIP` is parsed as whitespace-separated `<id> <pass>` pairs, so spaces, tabs, newlines, and blank lines are all treated the same after trimming the full string.

### How the tunnel works

The index is a **TCP-only control plane**.
It handles registration, lookup, candidate exchange, and punch signaling.
It does **not** bind UDP, perform NAT discovery, relay UDP, or carry application payload.

The inter-peer data channel is **UDP-based**.
By default it tries direct UDP hole punching first.
In `--tcp` mode, RP2P wraps that UDP path in an internal encrypted reliable stream so local TCP applications still see ordered, reconstructable, full-duplex byte semantics.
Each TCP client session performs a fresh ephemeral key exchange with the remote peer before application data flows, and those session keys are discarded when the session ends.
The `--tcp` and `--udp` flags control how data enters and leaves the tunnel on each end:

| Flag | Publisher side | Consumer side |
| :--- | :--- | :--- |
| `--tcp` | Connects to local TCP service → chunks into RP2P encrypted reliable stream frames → sends through UDP hole-punch tunnel | Receives RP2P encrypted reliable stream frames → reconstructs ordered byte stream → writes to local TCP client |
| `--udp` | Receives from local UDP service → forwards directly through hole-punch tunnel | Receives from hole-punch tunnel → forwards directly to local UDP client |

`rp2p con` creates a local TCP or UDP listener on `127.0.0.1:<listen_port>`. This listener acts as a transparent bridge to the remote service.
You never connect directly to the remote machine; every connection or datagram goes to `127.0.0.1:<listen_port>`, and rp2p forwards it through
the UDP transport path to the publisher's backend. From your perspective, the remote service behaves exactly like a local process on that port.
Any tool that speaks TCP or UDP works against the bridge without modification.

### STUN

STUN remains optional because it is an external resource.
It does not relay or carry application payloads, it only helps peers learn which
direct address and port to try for hole punching.
STUN is performed by publishers and consumers against external STUN servers.
The index is not a STUN server and does not observe or validate peer UDP endpoints.

RP2P does not support TURN-style fallback. TURN relays application traffic through
a third party, which changes the model from direct peer-to-peer transport to
server-mediated transport. RP2P is designed to preserve direct peer-to-peer data paths, so
on restrictive NATs where direct connectivity cannot be established, some
sessions may fail instead of degrading to a relay.

## Public API

Start an index server:

```c
#include "librp2p.h"

rp2p_t *ctx;
rp2p_open(&ctx);

rp2p_set_pow(ctx, 0);
rp2p_set_pass(ctx, "password");

rp2p_serve_index(ctx, "0.0.0.0", 9876);

rp2p_close(ctx);
```

List publishers currently registered in an index. Publishers are services registered by `rp2p set`; consumers are clients that use `rp2p con` to look up and connect to those services.

```c
#include "librp2p.h"

#include <stdio.h>

static void on_publisher(const char *id, void *userdata) {
    (void)userdata;
    printf("%s\n", id);
}

rp2p_t *ctx;
rp2p_open(&ctx);
rp2p_list_publishers(ctx, "idx.example.com", 9876, on_publisher, NULL);
rp2p_close(ctx);
```

---

## Lifecycle

- `rp2p_open()` - allocates and returns a new context owned by the caller.
- `rp2p_options_default()` - returns a default options struct for env-backed CLI/runtime configuration.
- `rp2p_options_load_env()` - loads `RP2P_*` environment values into an options struct.
- `rp2p_serve_index()` - starts the index server. Blocking, never returns on success.
- `rp2p_deregister()` - removes one host from an index using the stored key.
- `rp2p_list_publishers()` - lists active publisher IDs registered in an index.
- `rp2p_connect()` - opens a local TCP listener or UDP bridge and creates one peer session per accepted local client or datagram source.
- `rp2p_wait()` - registers one host, waits for incoming punch requests, and bridges each session to one local TCP backend or UDP socket.
- `rp2p_set_pow()` - configures the registration proof difficulty.
- `rp2p_set_pass()` - configures the shared password used to derive registration proofs.
- `rp2p_set_port()` - sets the local service or bridge port used by `set`/`con`.
- `rp2p_set_protocol()` - selects TCP or UDP mode before `rp2p_wait()` or `rp2p_connect()`.
- `rp2p_set_sweep()` - sets the UDP port sweep range used during punch fallback.
- `rp2p_set_stun_url()` - enables optional STUN discovery for `srflx` candidates.
- `rp2p_close()` - releases the context.

---

## Wire Protocol

Index control messages are plain text over TCP. The inter-peer data channel is UDP-based regardless of the `--tcp`/`--udp` flag.
UDP is used only between peers for hole-punch probes, keepalives, and direct payload transport. In `--tcp` mode, application bytes are carried inside RP2P's own encrypted reliable stream frames over that UDP path.

| Request | Response |
| :--- | :--- |
| `RP2P_CTRTOK_REGISTER:id` | `RP2P_CTRTOK_CHALLENGE:nonce:bits` |
| `RP2P_CTRTOK_REGISTER:id:RP2P_CTRTOK_SOLUTION:<hex>:RP2P_CTRTOK_PROOF:<hex>` | `RP2P_CTRTOK_OK:RP2P_CTRTOK_KEY:<hex>` or `RP2P_CTRTOK_AUTH_FAILED` |
| `RP2P_CTRTOK_DEREGISTER:id:RP2P_CTRTOK_KEY:<hex>` | `RP2P_CTRTOK_OK` |
| `RP2P_CTRTOK_LIST_PUBLISHERS` | `RP2P_CTRTOK_PUBLISHER:id\n...RP2P_CTRTOK_END` |
| `RP2P_CTRTOK_LOOKUP:id` | `RP2P_CTRTOK_PUBLISHER:id` or `RP2P_CTRTOK_NOT_FOUND` |
| `RP2P_CTRTOK_PUNCH_REQ2:me:target:session\nRP2P_CTRTOK_CAND:...\nRP2P_CTRTOK_END` | `RP2P_CTRTOK_PUNCH_OK2:target:session\nRP2P_CTRTOK_CAND:...\nRP2P_CTRTOK_END` to initiator |
| forwarded by index | `RP2P_CTRTOK_PUNCH_CALL2:me:session\nRP2P_CTRTOK_CAND:...\nRP2P_CTRTOK_END` to target |
| `RP2P_CTRTOK_PUNCH_PING:...` | Direct peer STUN-like probe (UDP) |
| `RP2P_CTRTOK_PUNCH_PONG:...` | Direct peer STUN-like reply (UDP) |
| `RP2P_CTRTOK_KA:` | UDP keepalive over direct path |

### TCP Stream Layer

In `--tcp` mode only, peers run an internal session protocol over the selected UDP endpoint after hole punching succeeds.

- Each accepted local TCP client gets its own `session_id`.
- Each session generates a fresh ephemeral keypair on both sides.
- Peers exchange ephemeral public keys before application data flows.
- Session keys are derived per direction and discarded when the session closes.
- DATA frames are encrypted and authenticated.
- Ordering, retransmission, duplicate suppression, and stream reconstruction happen inside RP2P.
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

By default, the index is a lightweight public rendezvous server with no authentication. When `RP2P_PASS` is set, registration requires a password-derived proof.
Anyone can attempt a registration and occupy a seat. PoW prevents casual or scripted abuse by requiring a computational cost per registration.
It does not stop a determined attacker (e.g. a botnet), but it raises the cost of filling the peer table from near-zero to hours of CPU time.

Each new publisher registration receives a random 8-byte nonce and must answer a challenge using a proof derived from `nonce_hex || self_id || solution_hex`.
The proof is always HMAC-SHA256 keyed by `RP2P_PASS`. On a public index, `RP2P_PASS` is the empty string. Heartbeats from already-registered publishers skip the challenge.

### Wire

```
I <- C: RP2P_CTRTOK_REGISTER:<self_id>
I -> C: RP2P_CTRTOK_CHALLENGE:<nonce_hex>:<bits>
I <- C: RP2P_CTRTOK_REGISTER:<self_id>:RP2P_CTRTOK_SOLUTION:<solution_hex>:RP2P_CTRTOK_PROOF:<proof_hex>
I -> C: RP2P_CTRTOK_OK:RP2P_CTRTOK_KEY:<hex>
```

### CLI

```bash
rp2p idx 9876                      # PoW 0 bits (default)
rp2p idx 9876 --pow 20             # PoW 20 bits
RP2P_PASS='password' rp2p idx 9876
RP2P_PASS='password' rp2p idx 9876 --pow 20
RP2P_PASS='global' RP2P_VIP='web webpass admin adminpass' rp2p idx 9876
```

### Environment

| Variable | Description |
| :--- | :--- |
| `RP2P_POW=0` | PoW bits for index registration (overridden by `--pow` flag). |
| `RP2P_PASS=password` | Optional shared password used to protect server registration. |
| `RP2P_VIP='id pass id pass ...'` | Reserved seat passwords parsed as whitespace-separated `<id> <pass>` pairs. |
| `RP2P_SWEEP=32` | UDP port sweep range used during punch fallback. |
| `RP2P_STUN=stun:host:port` | Optional STUN server used to discover `srflx` automatically. |
| `RP2P_SEATS=1024` | Max announced publishers on the index server (overridden by `--max`). |

Internal debug-only environment knobs used for fault-injection tests:

- `RP2P_DEBUG_STREAM=1` enables detailed stream logs.
- `RP2P_DEBUG_STREAM_DROP_EVERY=N` drops every Nth TCP stream DATA frame once.
- `RP2P_DEBUG_STREAM_REORDER_EVERY=N` delays every Nth TCP stream DATA frame once so the next frame arrives first.

`RP2P_INDEX` and `RP2P_BIND` are parsed by the options loader internally, but the current CLI still requires explicit positional arguments for the index address and explicit command flags for bind behavior.

When `RP2P_VIP` defines a password for one seat, that seat must use its VIP password and no longer accepts the global `RP2P_PASS`. VIP seats are reserved at index startup and keep their place even while offline.
Seats not listed in `RP2P_VIP` still use the global `RP2P_PASS`, but they may only occupy the non-VIP capacity left after VIP reservations.
The effective non-VIP capacity is `max(0, --max - vip_count)`. `RP2P_VIP` may define more IDs than `--max`; in that case no non-VIP seats remain, but the listed VIP IDs may still register with their own passwords.
If `RP2P_VIP` repeats an ID or contains an invalid ID/password token, `rp2p idx` fails at startup.

Examples:

```bash
RP2P_PASS='global' RP2P_VIP='web webpass' rp2p idx 9876
RP2P_PASS='webpass' rp2p set web@idx.example.com:9876 --tcp 8080
RP2P_PASS='global' rp2p set blog@idx.example.com:9876 --tcp 8080
```

### API

```c
rp2p_set_pow(ctx, 0);
rp2p_set_pass(ctx, "password");
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

`RP2P_PASS` only controls who may register services in the index. It does not authenticate consumers, encrypt tunnel traffic, or replace application-level authentication.

---

## Notes

- The index uses TCP only and can sit behind a TCP-only tunnel such as Cloudflare Tunnel, ngrok TCP, reverse SSH, or another TCP forwarder.
- The index does not require a public UDP port.
- The index does not relay application traffic.
- The inter-peer transport is UDP-based and stays peer-to-peer.
- `--tcp` now uses an internal encrypted reliable stream over UDP. Local service still communicates over TCP, but RP2P handles ordering, retransmission, reconstruction, and payload encryption inside the tunnel.
- `set --tcp <port>` connects to a real local TCP backend on `127.0.0.1:<port>`.
- `con --tcp <port>` exposes a local TCP listener on `127.0.0.1:<port>`.
- Each accepted local TCP client creates a separate peer session.
- The publisher can serve multiple consumers concurrently.
- `--udp` mode forwards UDP datagrams directly through the tunnel with no protocol conversion, ordering, or retransmission.
- `--stun` is opt-in and used only for endpoint discovery. It does not carry application payloads.
- RP2P does not implement TURN or relay application traffic through the index or other third-party servers.
- On restrictive NATs where direct UDP connectivity cannot be established, some sessions may fail by design rather than fall back to relayed transport.

---

## Build

Compiled artifacts are generated under `bin/{arch}/{platform}/` for the host architecture running the build.

```bash
make clean && make
```

### Tests

The portable test entry point is `make test`. Build project artifacts first, then run tests. Tests compile only test executables, link dynamically against the generated shared library, and run through CTest.

```bash
make
make test
```

To run the common `test` target in Windows-through-Wine mode:

```bash
make x86_64/windows
make test wine
```

The portable C test source is `src/test.c`. Test binaries and runtime outputs are build artifacts and are not stored in the project tree.

Build targets such as `make x86_64/windows` compile project artifacts. Tests are run only through `make test` or `make test wine`.

### Multiarch Builds

The project is prepared to build artifacts for multiple architectures under `bin/{arch}/{platform}/`. A plain `make` builds only the current host architecture.

```bash
make all
make x86_64/linux
make x86_64/windows
make x86_64/macos
make x86_64/iossim
make i686/linux
make i686/windows
make aarch64/linux
make aarch64/android
make aarch64/macos
make aarch64/ios
make aarch64/iossim
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

## Project scope

librp2p.c is built around a small and specific goal: coordinate peers, establish a direct connection between them, and keep third-party infrastructure outside the application data path.

Its surface is intentionally limited. There is no large collection of modules to evaluate, no set of interchangeable networking stacks to assemble, and no need to become an expert in a complete ecosystem before establishing a connection. The API exposes a small set of operations, the connection flow is concrete, and the implementation can be inspected directly.

A well-known project in the broader peer-to-peer networking space is [libp2p](https://libp2p.io/). It is an established modular stack designed to support many kinds of peer-to-peer systems through a broad collection of transports, secure channels, stream multiplexers, discovery and routing mechanisms, NAT traversal protocols, relays, and other components.

librp2p.c does not attempt to replace libp2p or reproduce its scope. Applications that need a general, extensible, and interoperable peer-to-peer networking platform may be better served by libp2p. librp2p.c is intended for applications that need direct peer connectivity through a smaller component with fewer concepts, fewer decisions, and a shorter learning curve.

---

## Development Requirements

### Build Tools

- `make` (GNU Make)
- `cmake` >= 3.14
- `ninja`
- `gcc` or `clang` (C11 compatible)

### System Libraries

Linux:
- `libpthread`
- `libm`

Windows (MSVC or MinGW):
- `ws2_32`
- `bcrypt`

macOS / iOS:
- No additional system libraries required.

### Optional Cross-Compilation SDKs

Required only for multiarch builds:

- MinGW (`x86_64-w64-mingw32-gcc`) for Windows cross-compilation from Linux.
- `wine` for running Windows tests on Linux.
- `osxcross` with macOS and iOS SDKs for macOS and iOS targets.
- Android NDK (version 27.2.12479018) for Android targets.

### Test Dependencies

- `ctest` (included with cmake)

---

## Beta Notice

This is a beta project tested only on Debian x86_64. It was created out of a personal need for these libraries, but no guarantees are provided regarding its stability or future support. You are free to test it, use it, and modify it as you please.

If you'd like to reach out, you can send an email to kaisar@kaisarcode.com. Please note that I do not accept pull requests; the goal is to avoid long-term dependency on platforms like GitHub, and I do not maintain fixed infrastructure to guarantee long-term stability for these projects.

---

## License

[![GPLv3](https://www.gnu.org/graphics/gplv3-127x51.png)](https://www.gnu.org/licenses/gpl-3.0.html)

This project is distributed under the **GNU General Public License version 3 (GPLv3)**.
