# Munarium Registry build plan

**REG-01 local candidate implementation present; platform milestone incomplete.** The design baseline is the
[public platform plan, revision 4](https://github.com/iokaio/munarium-platform/blob/main/docs/platform-plan.md), section 7, and its
stage sequence in section 25. Registry's initial delivery belongs to **Stage 1**.
Calendar windows are planning targets; acceptance evidence controls advancement.

## Preparation present in this checkout

- A non-publishable Cargo library with pinned dependencies and candidate read/intake implementation.
- An [architecture map](architecture.md) naming ownership, trust assumptions and failures.
- An [acceptance specification](validation.md) and automatic Rust build checks.
- Existing contribution, security, support and repository-hygiene processes.

These artifacts prepare implementation; they do not complete Stage 0 foundation qualification
or advance this repository beyond the hub's **repository created** catalog state.

## First work packet: REG-01: validate and resolve a candidate manifest without activating it

The [readiness packet](reg-01-readiness.md) preserves the original preparation.
The [implementation record](reg-01-implementation.md) documents the subsequently authorized
local experiment, concrete contract pin, executable component tests and integration gaps.
Formal contract acceptance and the integrated Stage 1 gate remain pending.

**Prerequisites:** accepted hub decisions and the specific contracts named in
[Architecture](architecture.md); record the exact revisions used. All fixtures must be synthetic
or authorized public inputs. The hub [contract backlog](https://github.com/iokaio/munarium-platform/blob/main/docs/architecture/contract-backlog.md)
tracks unresolved cross-component definitions.

**Work:** The authorized local experiment implements validation, immutable lookup and
recipient-bound identity verification using the pinned hub candidates. Formal acceptance
remains open. Intake and activation interfaces remain separate. Tests include two tenants,
unknown/unsigned artifacts, identity reuse with changed bytes, expired authority and
misbound principal chains. See the [Warden review](warden-integration.md).

**Permitted scope:** the relevant modules under `src/`, component-local tests/fixtures,
and their documentation. Add dependencies, runtime wiring, or migrations only when the packet
requires them and its owner has reviewed the design. Do not copy sibling implementations.

**Acceptance:** The accepted fixture resolves exactly its recorded bytes; unknown, incompatible, unsigned, and substituted content is rejected. Submitting a candidate leaves the effective catalog unchanged. A capability listing cannot disclose another tenant's inventory.

**Handoff:** retain commands, exit codes, fixture/contract revisions, limitations and the
diff for review. A test specification is not a passed test. Publishing, deployment, live
provider calls, signing changes and policy activation are separate operations.

## Subsequent packets

| Packet | Implementation scope | Exit condition |
|---|---|---|
| REG-02 | Add durable artifact storage and explicit activation with Council/bootstrap attestations. | Race two activations against the same prior epoch; exactly one wins and the other returns conflict. |
| REG-03 | Add bounded consumer caching and retirement handling. | An authentic retired artifact cannot remain usable past the declared freshness/revocation window. |
| REG-04 | Add discovery imports only after the activation boundary works. | Imports produce candidates and owner tasks; never active capabilities. |

Each packet gets a concrete component issue and links to the coordinating hub issue when
execution begins. The identifiers above are local planning references, not claims that remote
issues or approvals already exist. Work advances one coherent capability slice at a time.

## Integration and operational readiness

Before any runtime capability is advertised, document its supported contracts, immutable source
revision, accepted dependency versions and deployment boundary. Demonstrate relevant failure
paths from [Validation](validation.md), then add the component runbook: required identities,
health and dependency states, migration order, backup/restore, key rotation where applicable,
and unresolved-work investigation.

A component result alone is not platform qualification. The hub's
[delivery sequence](https://github.com/iokaio/munarium-platform/blob/main/docs/build-plan.md) requires composition evidence, including the
Server/Matrix foundation and the authority path required by the selected consequence class.
Broad discovery, inventory synchronization, federation, and a catalog UI.

## Completion criteria for the first functional increment

- The documented local recipe works from a clean clone using bounded disposable inputs.
- The acceptance cases are executable, retain their intended oracle, and include refusal paths.
- Unsupported operations remain explicit; logs and reports expose no credentials or private data.
- The README links the actual evidence before any capability or release label changes.
