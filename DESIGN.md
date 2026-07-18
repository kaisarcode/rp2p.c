# rp2p.c Design

## Purpose

`rp2p.c` is a small tunneling primitive for independently operated systems.

It allows one peer to publish a local TCP or UDP service and another peer to expose that service through a local port.

The project is intended for individuals, local communities, small businesses, home systems, workshops, cooperatives, local media, kiosks, events, and other modest deployments.

Small scale is the intended operating model.

The project is not designed as an enterprise networking platform, managed connectivity service, global overlay network, or universal NAT traversal system.

## Architecture

RP2P separates coordination from application transport.

The index is a TCP-only control service.

It handles:

* publisher registration
* deregistration
* publisher lookup
* publisher listing
* candidate exchange
* punch coordination
* temporary registration state

The index does not:

* bind UDP for peer traffic
* relay application payloads
* inspect application protocols
* provide application authentication
* provide consumer identity
* provide global accounts
* maintain a permanent network database
* act as a control plane for managed clients

Application traffic travels directly between peers through UDP.

## Transport Modes

### TCP mode

The local application communicates with RP2P through TCP.

RP2P transports the byte stream between peers using vendored KCP over UDP.

KCP provides:

* ordering
* acknowledgements
* retransmission
* congestion and window state
* stream reconstruction

RP2P adds only the session lifecycle envelope required around KCP:

* `HELLO`
* `HELLO_ACK`
* `KCP`
* `CLOSE`
* `CLOSE_ACK`
* `RESET`
* `KEEPALIVE`

RP2P must not implement a second reliable transport layer around KCP.

### UDP mode

UDP datagrams are transported directly between peers.

Datagram boundaries are preserved.

RP2P does not add:

* ordering
* retransmission
* duplication suppression guarantees
* fragmentation of oversized application datagrams

Applications using UDP remain responsible for their own delivery semantics.

## Direct Connectivity

RP2P attempts to establish a direct UDP path between peers.

Candidate sources may include:

* local host endpoints
* LAN endpoints
* observed public endpoints
* optional STUN-discovered endpoints
* peer-reflexive endpoints
* bounded predicted or swept ports

STUN is optional.

STUN is used only to discover an externally visible endpoint. It does not carry application traffic and does not become part of an established tunnel.

RP2P does not implement TURN or any equivalent application traffic relay.

When a direct path cannot be established, the session may fail.

This is an accepted operational result. It is not automatically missing functionality.

## Security Boundaries

RP2P transports application traffic without defining the application security model.

Application protocols remain responsible for:

* peer authentication
* user authentication
* authorization
* confidentiality
* payload integrity
* application identity
* trust establishment

Protocols such as SSH, HTTPS, TLS-enabled services, or application-specific secure protocols may run through RP2P without duplicating their security layer inside the tunnel.

Plaintext application protocols may also be transported when the operator deliberately accepts that model.

The index control protocol is not an application payload security layer.

`RP2P_PASS`, `RP2P_VIP`, and proof-of-work protect publisher registration and index capacity. They do not authenticate consumers, establish peer identity, or encrypt transported payloads.

## Registration Protection

A public index may allow open registration.

Optional controls include:

* global publisher password
* reserved publisher IDs with individual passwords
* proof-of-work registration cost
* bounded publisher capacity

Registration protection exists to control index use and resource occupation.

It must not expand into:

* user accounts
* consumer permissions
* organization management
* centralized authorization
* persistent identity infrastructure

## State

Index state is temporary.

The index stores only the state required to coordinate active publishers and pending sessions.

It must not become a permanent source of truth.

The design should prefer:

* bounded tables
* fixed limits
* explicit timeouts
* automatic stale-state removal
* clean failure when capacity is exhausted

Persistent storage is outside the project scope.

## Composition

RP2P should compose with existing tools and protocols rather than absorb their responsibilities.

Examples:

* SSH provides authenticated encrypted remote access.
* HTTPS provides application transport security.
* DNS or local catalogs may provide human-facing discovery.
* systemd may supervise a process.
* an external proxy may expose a local bridge.
* separate applications may define users and permissions.

A feature should not be added to RP2P merely because it is commonly bundled into larger networking platforms.

## Portability

The implementation targets portable C11.

Supported build targets may include Linux, Windows, macOS, iOS, Android, and multiple CPU architectures.

Portability exists to support heterogeneous, inexpensive, locally available hardware.

It is not a claim that every target has received equal runtime validation.

Platform-specific behavior must preserve the same public API and protocol semantics.

## Resource Model

The project must remain suitable for modest systems.

Design choices should prefer:

* bounded memory
* bounded pending work
* bounded protocol fields
* bounded candidate lists
* bounded port sweeps
* explicit socket ownership
* deterministic cleanup
* limited background threads
* no mandatory external services

Unbounded queues, hidden persistent state, and infrastructure-dependent behavior should be rejected.

## Inspectability

One person should be able to understand the complete connection path without learning a large framework.

The implementation may be divided into internal units when that improves correctness, but it must not become a generic networking framework.

Internal abstractions must correspond to concrete protocol or platform responsibilities.

Generic extensibility is not a goal.

## Non-goals

RP2P is not intended to provide:

* enterprise network orchestration
* universal connectivity
* application traffic relay
* global peer identity
* user accounts
* organization management
* centralized authorization
* service mesh behavior
* remote fleet management
* hosted control infrastructure
* telemetry collection
* billing
* plugin ecosystems
* generic routing
* distributed consensus
* a permanent distributed network
* replacement application security

These are design exclusions, not an unfinished roadmap.

## Change Criteria

A proposed change should be evaluated with the following questions:

1. What concrete small-scale problem does it solve?
2. Is the problem part of tunneling, or does it belong to another component?
3. Can it be solved through composition with an existing small tool?
4. Does it introduce permanent infrastructure?
5. Does it move application responsibility into RP2P?
6. Does it increase hidden state or operator dependency?
7. Does it make the connection path harder for one person to inspect?
8. Does it preserve direct peer-to-peer application traffic?
9. Does it preserve bounded resource use?
10. Is the added complexity justified by an existing use case?

Changes justified mainly by hypothetical future scale, enterprise readiness, platform growth, managed operation, or ecosystem expectations should be rejected.

## Core Invariants

The following properties define the project:

* the index is coordination infrastructure
* application traffic does not pass through the index
* peer transport is direct UDP
* TCP mode uses KCP over UDP
* UDP mode preserves datagrams
* STUN remains optional
* no TURN-style relay is provided
* application security remains external
* index state remains temporary
* resource use remains bounded
* the implementation remains small and inspectable
* local operation does not require accounts or subscriptions

These constraints define the product.

They are not a roadmap.
