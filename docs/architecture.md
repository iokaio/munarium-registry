# Munarium Registry implementation architecture

**Experimental candidate implementation; other interfaces remain proposed.** Based on section 7 of the
[platform plan, revision 4](https://github.com/iokaio/munarium-platform/blob/main/docs/platform-plan.md), with lifecycle and failure rules in
sections 17–19 and 22. See the hub's
[scaffold decision proposal](https://github.com/iokaio/munarium-platform/blob/main/docs/decisions/0001-scaffold-boundaries.md)
for the distinction between local interfaces and normative contracts.

## Responsibility and current boundary

Inventory of immutable artifacts, inert candidates, and separately authorized activations. Registry belongs to the **authority plane**.
The [candidate module](../src/candidate.rs) implements bounded in-memory storage, signed
manifest validation, tenant-scoped lookup and listing. The trusted host supplies verified
callers and current inventory snapshots. No listener, persistence, service authentication,
activation or target operation exists.

The original traits remain local seams; candidate intake and reading now have concrete
implementations against the [pinned hub candidate](../contracts/README.md).
Activation types remain unspecified. Async runtime, transport and durable storage remain open.

## Module map

| Source | Proposed interface | Responsibility |
|---|---|---|
| [candidate](../src/candidate.rs) | `Registry` host, `Intake` and `Reader` handles | Enforce candidate validation and byte identity in memory; scoped handles cannot activate or replace trust. |
| [identity](../src/identity.rs) | Receiving-side verifier and submit/resolve/list adapters | Reverify original signed chains against current host authority and authenticated peer for every operation. |
| [catalog](../src/catalog.rs) | `CatalogReader` | Readers must distinguish authentic bytes from currently authorized capability. Effective views require activation epoch, freshness, and revocation context. |
| [intake](../src/intake.rs) | `CandidateIntake` | Discovery and agent submission cannot alter the effective catalog; candidate identifiers are not activation attestations. |
| [activation](../src/activation.rs) | `ActivationStore` | Implementations must validate authority, tenant, environment, digest, and expected activation before a durable compare-and-set transition. |

## Planned flow and state ownership

Authenticated read → immutable artifact lookup → effective activation and freshness view. Candidate submission enters a separate inert store. Council or the explicit bootstrap authority supplies an attestation before activation changes the effective pointer.

Own immutable artifact bytes, owner assignments, candidate references, and effective activation pointers. Append activation evidence to Server; retain old artifacts for reconstruction. Consumers may cache verified artifacts only with the declared epoch and revocation bounds.

## Dependencies and failure behavior

| Dependency | Required input or service | Failure rule |
|---|---|---|
| Hub contract work | Manifest and activation schemas, digest rules, and compatibility policy | Do not infer approval from a valid-looking document. |
| Council / bootstrap authority | Verified attestation for a specific transition | No new activation without required authority. |
| Server | Required activation records | A failed required write cannot appear as a completed activation. |
| Gate | Consumer of resolved artifacts and effective state | Unknown, incompatible, expired, or revoked entries must be refused. |

The experiment pins dependencies and an unreleased contract bundle. Formally accepted contract
versions remain **none**. [The implementation record](reg-01-implementation.md) identifies
the exact digest and trust boundary. Future adapters must consume accepted contracts;
a floating hub branch is design context, never deployment authority.

## Threat assumptions

Treat agent code, supplied content and self-reported identity as untrusted.
Host administrators, release roots and required signing authorities remain explicit
trust assumptions of a qualified deployment. Process separation alone does not prove
independent administration.

| Threat | Required control to implement and test |
|---|---|
| Malicious discovery or agent intake | Candidate storage is separate from effective pointers; activation requires distinct authority. |
| Artifact or tenant substitution | Validate signed digest and tenant/environment binding before lookup is used for enforcement. |
| Stale authentic cache | Carry epoch and revocation context; authenticity alone is insufficient. |

The [validation specification](validation.md) connects these requirements to the hub
invariants. No test evidence is implied by this design.

## Decisions needed before implementation

ADR-0006 and the Registry v2 candidate define artifact signatures and host-provided trust
inputs for the local experiment. Warden ADR-0005 defines the receiving-side identity boundary;
[local evidence](warden-integration.md) covers signed chains and the real Warden verifier.
Formal acceptance, authenticated transport/provider integration and trust distribution
remain open. Define activation transactions, record acknowledgements, cache
freshness and revocation delivery before durable activation or consumer caching.

A cross-component semantic change starts in a hub decision record. Keep publication,
activation and component implementation separate. Use expand, migrate, remove for
future breaking contract changes; never duplicate hashing, identity or grant rules.

## Deferred scope

Broad discovery, inventory synchronization, federation, and a catalog UI.

The [implementation plan](implementation-plan.md) sequences the first useful increment.
The local example is in-process only; no service port or live-provider configuration is supplied.
