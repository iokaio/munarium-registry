# Munarium Registry development documentation

Start with the [repository README](../README.md) for scope and capability status.
The [public platform plan, revision 4](https://github.com/iokaio/munarium-platform/blob/main/docs/platform-plan.md) is the design baseline;
section 7 covers Registry. A plan or a compiling interface does not establish a capability.

| Document | Purpose |
|---|---|
| [Architecture](architecture.md) | Proposed modules, state ownership, dependencies, threats and open decisions |
| [Implementation plan](implementation-plan.md) | First bounded work item, delivery sequence and acceptance criteria |
| [REG-01 readiness](reg-01-readiness.md) | Pinned proposal inputs, blocking decisions, proposed acceptance cases and local scaffold observations |
| [REG-01 implementation](reg-01-implementation.md) | Candidate contract pin, trusted-host API, local recipe, tests and remaining integration limits |
| [Warden integration review](warden-integration.md) | Pulled revisions, receiving-side verification, interoperability recipe and remaining boundaries |
| [REG-01 build support](reg-01-maintainer-changes.md) | Authorized CI cache preparation, exact fixture exceptions and scanner boundary checks |
| [Validation](validation.md) | Local build recipe, automatic checks and future acceptance specifications |
| [Durable candidate catalog](durable-catalog.md) | SQLite custody, immutable admission, restart, failure behavior and validation |

The [source](../src/lib.rs) includes an experimental in-memory candidate implementation.
Formally accepted contracts, deployment profiles and production capabilities remain **none**.

[Stage 1 service profile](service-profile.md) documents configuration, the authenticated
boundary and separate-process evidence.
