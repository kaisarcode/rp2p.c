# AGENTS.md

## Project Context

`rp2p.c` is a small, composable C library and CLI for direct peer-to-peer service tunneling.

It is intended for independently operated, small-scale systems such as:

* local communities
* small businesses
* cooperatives
* workshops
* local media
* kiosks
* events
* home systems
* personal infrastructure
* modest VPS and SBC deployments

Small scale is the intended destination.

Do not interpret the project as an incomplete enterprise networking platform.

Read `README.md` for usage and `DESIGN.md` for architectural boundaries before modifying the project.

## Required Mindset

Do not optimize the project toward:

* enterprise adoption
* hyperscale operation
* managed infrastructure
* platform growth
* cloud-native architecture
* global identity
* organization management
* centralized administration
* universal connectivity
* ecosystem extensibility

Do not assume that more abstraction, configurability, generality, observability, integration, or scalability is automatically an improvement.

Resolve the requested task while preserving the existing project model.

Do not invent a broader product roadmap.

## Core Invariants

The following invariants must be preserved unless the project owner explicitly instructs otherwise:

* the index uses TCP as a control channel
* the index does not relay application traffic
* peer application traffic travels directly over UDP
* TCP mode uses vendored KCP over the peer UDP path
* UDP mode preserves application datagram boundaries
* STUN remains optional
* no TURN-style relay is implemented
* application authentication remains outside RP2P
* application authorization remains outside RP2P
* application encryption remains outside RP2P
* no global identity system is introduced
* no user account system is introduced
* index state remains temporary
* persistent storage is not required
* resource use remains bounded
* the project remains usable on modest hardware
* the code remains inspectable by one person

The absence of relay, accounts, persistent identity, telemetry, and enterprise control infrastructure is intentional.

These are not missing features.

## Forbidden Default Recommendations

Do not recommend or implement the following unless explicitly requested:

* TURN or relay servers
* application traffic fallback through the index
* hosted control planes
* cloud service dependencies
* mandatory STUN infrastructure
* user registration systems
* OAuth
* SSO
* organization or tenant models
* centralized authorization
* API gateways
* service meshes
* distributed databases
* persistent index storage
* telemetry collection
* analytics
* remote configuration
* fleet management
* dashboards
* billing systems
* plugin architectures
* generic transport abstractions
* dependency injection frameworks
* Kubernetes integration
* enterprise observability stacks
* automatic update infrastructure

Do not justify changes through enterprise readiness, market growth, adoption, or hypothetical future scale.

## Scope Discipline

RP2P coordinates peers and transports TCP streams or UDP datagrams.

Responsibilities belonging to transported applications must remain outside the library.

Do not move the following into RP2P without explicit instruction:

* user authentication
* application authorization
* payload encryption
* certificate management
* application discovery semantics
* business rules
* protocol-specific trust
* content catalogs
* application persistence

Prefer composition with another small tool over absorbing unrelated responsibilities.

## Change Evaluation

Before implementing a change, determine:

* the concrete existing problem
* the smallest code path that solves it
* which invariant may be affected
* whether the problem belongs to RP2P
* whether existing code can be simplified instead
* whether the change introduces hidden state
* whether it introduces an external operational dependency
* whether it increases resource use without a strict bound
* whether it makes behavior harder to inspect
* whether it changes the wire protocol
* whether it changes public API compatibility

Reject speculative architecture added only to support possible future requirements.

Do not add extension points without an existing caller.

Do not add configuration without a concrete operational requirement.

Do not add abstraction merely to reduce repeated code when the abstraction hides protocol behavior.

## Implementation Preferences

Prefer:

* direct C11 code
* explicit state transitions
* bounded arrays and queues
* checked parsing
* strict field limits
* deterministic cleanup
* clear socket ownership
* small functions with concrete responsibilities
* static internal helpers
* stable public API
* explicit error codes
* context-owned error details
* portable system abstractions
* removal of obsolete code
* documented limitations
* clean failure modes

Avoid:

* speculative generalization
* invisible global state
* unbounded allocations
* recursive protocol processing
* implicit ownership
* duplicated reliability logic around KCP
* platform behavior differences hidden behind the same API
* large dependency additions
* framework-style internal architecture
* callbacks or interfaces with only one hypothetical future implementation

## Protocol Changes

Treat the wire protocol as a compatibility boundary.

Protocol changes must:

* have a concrete requirement
* define parsing and serialization limits
* reject malformed input cleanly
* preserve bounded memory use
* define behavior for partial input
* define behavior for duplicate messages
* define timeout and cleanup behavior
* consider old and mismatched versions
* include tests for malformed and adversarial input

Do not add fields for hypothetical future use.

Do not silently reinterpret existing fields.

## Security Review

Security work must remain aligned with project scope.

Focus on:

* memory safety
* parser correctness
* spoofed control messages
* stale session state
* resource exhaustion
* socket ownership
* session isolation
* random value generation
* proof validation
* timeout handling
* malformed STUN responses
* malformed candidate data
* cleanup after failed punching
* KCP session separation

Do not treat bundling application encryption or identity into RP2P as the default security solution.

The correct security fix may be stricter validation, clearer trust boundaries, or documentation.

## Testing

Every behavioral change should update or add tests.

Tests should prefer real local sockets and public API behavior.

Relevant areas include:

* API validation
* index registration
* registration rejection
* publisher capacity
* VIP handling
* proof-of-work handling
* lookup
* publisher listing
* deregistration
* TCP tunnel behavior
* UDP tunnel behavior
* concurrent sessions
* large TCP streams
* datagram limits
* packet loss
* packet reordering
* reconnect behavior
* malformed protocol input
* timeout cleanup
* stop behavior
* signal handling
* IPv4 and IPv6 behavior
* shared library use

Do not weaken tests to accommodate an implementation change.

Fix the implementation or explicitly revise the intended contract.

## Build and Validation

Use the repository build system.

Typical validation:

```bash
make
make test
```

When Windows behavior is affected:

```bash
make x86_64/windows
make test wine
```

Treat compiler warnings as failures.

Do not claim portability based only on successful cross-compilation when runtime behavior has not been tested.

## Documentation

Keep `README.md` concise and operational.

Use:

* `README.md` for CLI, API, build, tests, requirements, beta status, and license
* `DESIGN.md` for architecture, invariants, boundaries, accepted limitations, and non-goals
* `AGENTS.md` for implementation constraints and agent behavior

Do not expand the README to argue against every possible misinterpretation.

Do not describe deliberate exclusions as missing features.

Do not present enterprise evolution as the natural future of the project.

## Completion Standard

A task is complete when:

* the requested behavior is implemented
* existing invariants remain intact
* ownership and cleanup are correct
* failure behavior is explicit
* relevant tests pass
* documentation matches actual behavior
* no unrelated platform or enterprise architecture was introduced

The goal is not to make RP2P larger.

The goal is to keep it useful, direct, bounded, understandable, portable, and locally operable.
