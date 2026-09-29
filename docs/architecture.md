# Munarium Registry implementation architecture

**Proposed design; scaffold only.** Based on section 7 of the
[platform plan, revision 4](https://github.com/iokaio/munarium-platform/blob/main/docs/platform-plan.md), with lifecycle and failure rules in
sections 17–19 and 22. See the hub's
[scaffold decision proposal](https://github.com/iokaio/munarium-platform/blob/main/docs/decisions/0001-scaffold-boundaries.md)
for the distinction between local interfaces and normative contracts.

## Responsibility and current boundary

Inventory of immutable artifacts, inert candidates, and separately authorized activations. Registry belongs to the **authority plane**.
The crate declares interfaces only: no concrete implementations, serialization,
network listeners, persistence, service authentication or target operations exist.

The associated input, output and error types are intentionally unspecified.
These are proposed in-process seams for implementation work, not a released Rust API
or a second definition of the shared wire contract. A trait signature does not enforce
the trust assumptions below. Async runtime, transport and storage choices remain open.

## Module map

| Source | Proposed interface | Responsibility |
|---|---|---|
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

No dependency is linked into this scaffold. Supported contract versions are **none**.
Future adapters must consume a reviewed, versioned contract and identify its digest;
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

Select the artifact signature envelope and trust distribution; define activation transaction and record acknowledgement; specify cache freshness and revocation inputs before implementing storage.

A cross-component semantic change starts in a hub decision record. Keep publication,
activation and component implementation separate. Use expand, migrate, remove for
future breaking contract changes; never duplicate hashing, identity or grant rules.

## Deferred scope

Broad discovery, inventory synchronization, federation, and a catalog UI.

The [implementation plan](implementation-plan.md) sequences the first useful increment.
No deployment recipe, service port or live-provider configuration is supplied at this stage.
