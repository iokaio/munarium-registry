# Munarium Registry

**Inventory of agents, tools, manifests, and policy bundles.** Registry is the authority-plane
component of the Munarium Governance Platform that makes the inventory executable: the signed
artifact that describes what a tool is allowed to do is the artifact Munarium Gate accepts when it
decides whether a proposed action may proceed. Discovered is not approved, published is not
activated, and an immutable manifest is not permanently authorized.

> **Status: Stage 1 candidate service implemented.** The authenticated service/client
> profile is implemented and covered by component and separate-process tests.
> See the [service profile](docs/service-profile.md). Candidates remain inactive;
> no execution endpoint is mounted. Human acceptance and production qualification
> remain pending.

Registry is one of nine components built around the existing Munarium foundation, Munarium Server
and Munarium Matrix. Their shared architecture, normative contracts, decision records, roadmap and
composition evidence live in the public hub,
[iokaio/munarium-platform](https://github.com/iokaio/munarium-platform). This repository will hold
Registry's implementation, its unit and component tests, the migrations it owns, operational
diagnostics, package definitions, a local development recipe and release evidence. It is open
source from its first public commit, under the Apache License 2.0, with no proprietary edition.

## Start building

Read the [development index](docs/README.md), then the [architecture](docs/architecture.md),
[implementation plan](docs/implementation-plan.md) and [validation guide](docs/validation.md).
They map the public platform plan to source modules, dependencies and acceptance cases.
The [local recipe](docs/reg-01-implementation.md#local-recipe) runs against a pinned, unreleased
Registry v2 candidate contract. Formally accepted contract versions remain **none**.

## What Registry is for

The platform separates four powers: **read**, **governed write**, **act** and **govern**. A
principal may be permitted to propose a tool manifest without being permitted to activate it, and
an agent's ordinary operating identity must never activate the rules that govern it. Registry's
effective catalog is part of the *govern* power. Agents get no activation authority over it.

Registry stores immutable **agent definitions**, **tool manifests**, **policy-bundle references**,
**owners** and **activation records**.

- An **agent definition** identifies purpose, release, deployment class, permitted tools, model
  allowances, consequence limits, and a responsible human or organizational owner.
- A **tool manifest** identifies a versioned argument schema, target and environment, base
  consequence class, upward-only modifiers, effect semantics, permitted credential audience,
  idempotency behavior, compensation options, data classifications and required obligations. It
  must describe the actual target operation, not a friendly tool name; a connector that silently
  executes broader operations than its manifest advertises fails qualification.
- **Discovery** may create candidate records and owner-assignment tasks. Discovered does not mean
  approved.

Registry is not an identity provider, a secrets vault, an approval service or a policy evaluator.
Those are Warden, Council and Gate. It integrates with the enterprise's existing inventory sources
rather than replacing them.

## The design, as planned

### Three interfaces, not one

The first interface supports resolving an immutable artifact by digest, listing the capabilities
allowed for a principal, and reporting the effective artifact version for a deployment. **Read
APIs are distinct from candidate submission, and both are distinct from activation.** A narrowly
scoped candidate-intake endpoint may accept an agent's proposed manifest as an inert record without
changing the catalog Gate enforces.

### Publication is not activation

CI may build and sign a candidate bundle. Whether a deployment may activate it is decided by
Munarium Council, or by the temporary owner-provisioned bootstrap authority the platform uses
before Council is qualified. Registry validates the attestation, the expected prior state, the
tenant, the environment and the target artifact digest before changing the effective pointer, using
compare-and-set so that a stale expectation returns a conflict rather than overwriting a newer
decision. The old artifact remains available for historical reconstruction. The same identity
with different bytes is rejected; a new version is required.

### Caches carry epoch and revocation

A running Gate may cache a verified bundle within a declared freshness window. The cache includes
its activation epoch and revocation status, not merely the content hash. Immutability of a manifest
does not make it permanently authorized: a retired tool can still have authentic bytes while no
longer being allowed.

### The hub is not the live database

Deployed catalogs consume released artifacts through an authenticated installation or promotion
path. A GitHub outage must not rewrite policy semantics, and a compromised documentation branch
must not become permission to activate new runtime capability.

### What is deferred

Full cloud discovery, organizational asset synchronization and a large catalog UI are deferred.
Registry's first value is a trustworthy manifest and owner inventory that Gate can use; discovery
is built around that contract rather than expanding the contract around every source system.
Deferred is a roadmap state, not a commercial restriction.

## First public increment

**A signed manifest catalog and schema validation.** Registry's catalog, Gate's evaluator, the
action-record shapes, verified principal context and a minimal Harness client together form the
platform's first usable increment: decision-only evaluation against a disposable target, able to
explain and replay a decision without claiming it can govern enterprise effects.

Target window: Stage 1 (months 2–3 of the founder-led roadmap). The window follows founder capacity and evidence; the release gate is a
commitment to evidence, the month range is a target.

## Capability status

The labels are evidence labels, not editions: **Planned** (architecture or work items exist; no
functioning capability is claimed), **Experimental** (a runnable prototype with explicit
limitations), **Conformance-tested** (a named version passes the published suite for a stated
environment and contract), **Reference-qualified** (the integrated composition passes operational,
recovery, authority and deployment tests for a specific profile), **Independently reviewed** (a
named review covers a stated revision and scope). In the hub's component catalog this repository is
at **repository created**.

| Capability | Status | Evidence |
|---|---|---|
| Immutable artifact store: agent definitions, tool manifests, policy-bundle references, owners | Planned | none |
| In-memory immutable tool-manifest candidates | Experimental | [REG-01 component tests](tests/reg_01.rs) |
| Tool-manifest signature and schema validation against the v2 candidate | Experimental | [32 signed vectors and validation tests](docs/reg-01-implementation.md) |
| Schema validation of agent definitions | Planned | none |
| Read API: resolve by digest, list capabilities for a principal, effective version per deployment | Planned | none |
| In-process tenant-scoped candidate resolution and listing | Experimental | [REG-01 component tests](tests/reg_01.rs) |
| Candidate intake for inert proposals, separate from the enforced catalog | Experimental, in memory | [Authority boundary and limitations](docs/reg-01-implementation.md) |
| Recipient-bound principal verification for candidate operations | Experimental, in process | [Identity and current-authority tests](tests/identity.rs); [Warden review](docs/warden-integration.md) |
| Activation with attestation validation and compare-and-set on expected prior state | Planned | none |
| Cache contract for consumers: freshness window, activation epoch, revocation status | Planned | none |
| Activation records in the hub's action-record shapes | Planned | none |
| Discovery import recipes: candidate, active, drifted, unmanaged | Planned, later | none |
| Full cloud discovery, organizational asset synchronization, catalog UI | Deferred | none |

Formally accepted contract versions: **none**. Implementation input:
[unreleased Registry v2 candidate](contracts/README.md). Supported deployment profiles: **none**.
Local library operations: validate/submit an inert candidate, resolve exact bytes, list a
tenant's candidates and refresh host-provided trust. No effective catalog or activation exists.

## Acceptance evidence for the first release

| Required check | Acceptance evidence |
|---|---|
| Unknown, unsigned or mismatched artifacts | Gate refuses them with a typed reason and a recorded decision |
| Same identity with different bytes | Registry rejects the replacement; a new version is required |
| Agent-originated activation attempt | The active catalog remains unchanged |
| Stale expected activation state | A conflict is returned rather than overwriting a newer decision |
| Retired manifest in a local cache | Freshness or revocation rules prevent unauthorized continued use |
| Broad imported API description | Import produces a candidate surface requiring explicit review, not automatic trust |

A blank evidence field means unverified, not passed. Failed tests and unresolved findings are kept
in the record; a release can narrow its scope to exclude an unqualified path, but it cannot relabel
a failure as success.

## Invariants

The hub maintains the platform's invariant catalog with stable identifiers. Each invariant names
its claim, trust assumptions, owner, the tests that exercise it and the release evidence. Registry
owns or shares:

| ID | Required property | Owner and first gate |
|---|---|---|
| INV-02 | A discovered or agent-proposed tool remains inert until authorized activation | Registry; stage 1 |
| INV-04 | Unknown or incompatible manifests fail closed | Registry and Gate; stage 1 |
| INV-20 | A local overlay cannot waive a mandatory parent prohibition | Council, Registry, Gate; stage 5 |
| INV-22 | A release advertises only the profiles and capabilities supported by its evidence | every component; every stage |

## Contracts, dependencies and neighbors

- **Contracts.** The hub's contracts directory is the normative source for wire envelopes and
  cross-component semantics. Registry implements them; it does not define them. A change to a
  contract starts as a hub decision record. Supported contract versions: none yet.
- **Foundation.** Munarium Server 1.3.0 and Munarium Matrix 1.2.0 (source of record
  [iokaio/munarium-matrix](https://github.com/iokaio/munarium-matrix)) are the platform baseline,
  pinned by the hub's foundation qualification record.
- **Gate** resolves signed manifests from Registry and refuses what it cannot resolve.
- **Council** supplies the activation authority; before Council exists, an owner-provisioned,
  non-agent bootstrap attestation with a recorded retirement path does.
- **Warden** takes Registry's maximum delegation depth and per-task scope as explicit inputs to its
  delegation decisions.
- **Matrix** registers its approved query capabilities with Registry.
- **Sentinel** compares registered capabilities with observed activity to identify drift and
  uncovered paths; **Console** lets an operator identify an owner and inspect a manifest without
  editing effective policy.
- **External dependencies.** Pinned Rust cryptography and JSON dependencies are recorded in
  [Cargo.toml](Cargo.toml) and [third-party notices](THIRD_PARTY_NOTICES.md). Persistence
  remains a later packet; the current candidate catalog is in memory.

## Not in scope

- Being a discovery portal before being a trustworthy catalog.
- Acting as Gate's live database over the network from GitHub, or as any remote production-policy
  dependency.
- Approving anything (Council), brokering credentials (Warden), or evaluating policy (Gate).
- Lowering a consequence class because a manifest or an agent calls an operation harmless.
  Modifiers raise the base class; they never quietly downgrade it.
- Promising to find every agent or credential in an enterprise. A count of zero unmanaged paths is
  meaningful only within the declared inventory scope and observation period.

## Roadmap position

| Stage | Registry's part |
|---|---|
| 0 · month 1 | This repository: governance files, scope, status, acceptance items. The hub's invariant catalog and component-status table are published. |
| 1 · months 2–3 | The signed catalog and schema validation, alongside Gate's evaluator, the action-record shapes and a minimal Harness client. Exit evidence: unknown-manifest rejection, deterministic replay, tenant isolation fixtures, contract compatibility. |
| 2 · months 4–6 | Activation through the minimum Council and bootstrap path; the first complete governed action uses a Registry-resolved manifest. |
| 3–4 · months 7–12 | Drift comparison for Sentinel, inventory views for Console, inclusion in the platform composition manifest and evidence packs. |
| 5 · months 13+ | Discovery import recipes and federation constraints, demand-led. |

When capacity is constrained, breadth is reduced first: connector breadth, SDK breadth, UI polish,
packaging variants and simultaneous adopter commitments. Request binding, mandatory evidence,
credential isolation and required distinct authority are never removed to preserve a date.

## Repository layout

| Path | What exists |
|---|---|
| [Cargo.toml](Cargo.toml), [Cargo.lock](Cargo.lock) | Independent library, version 0.1.0-dev, publishing disabled, pinned dependencies |
| [src/lib.rs](src/lib.rs) | Experimental candidate library and separate interface declarations |
| [contracts/](contracts/README.md), [tests/](tests/reg_01.rs) | Pinned hub candidate bundle and behavioral checks |
| [docs/](docs/README.md) | Architecture, implementation sequence and acceptance specifications |
| [CONTRIBUTING.md](CONTRIBUTING.md), [AGENTS.md](AGENTS.md), [CLAUDE.md](CLAUDE.md) | Contribution process and aligned development guidance |
| [.github/workflows/](.github/workflows/) | Automatic Rust, repository-hygiene and DCO checks |
| [scripts/](scripts/), [check_license.py](check_license.py) | Existing documentation, private-material and license checks |
| [LICENSE](LICENSE), [NOTICE](NOTICE), [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) | Licensing and dependency notices |

Subsystem modules: [catalog](src/catalog.rs), [intake](src/intake.rs), [activation](src/activation.rs).
The [candidate module](src/candidate.rs) implements in-memory intake and reads using the
vendored contract. No migration, service binary or deployment asset is supplied; builds do
not require a sibling checkout.

## Development

Use Rust 1.98.1 with rustfmt, Clippy and the platform's native linker. Prime the pinned
dependency cache once with `cargo fetch --locked`, then from this repository root:

```console
cargo fmt --all --check
cargo build --offline --locked
cargo clippy --offline --locked --all-targets -- -D warnings
cargo test --offline --locked
cargo doc --offline --locked --no-deps
```

The tests cover fixed signed fixtures, byte identity, tenant isolation and current-trust
refusals. [Validation](docs/validation.md) and the [REG-01 record](docs/reg-01-implementation.md)
distinguish local component evidence from unimplemented activation and platform integration.

Also run the existing hygiene gates:

```console
py check_license.py
py scripts/private_material_scan.py
py scripts/docs_linkcheck.py
gitleaks dir . --config .gitleaks.toml --no-banner --redact --exit-code 1
git diff --check
```

Use `python` or `python3` where `py` is unavailable. The new
[Rust workflow](.github/workflows/rust.yml) runs on main pushes and pull requests alongside
the existing [repository hygiene](.github/workflows/repo-hygiene.yml) and
[DCO](.github/workflows/dco.yml) workflows. They provide build and repository checks, not a
qualified runtime. No package is published or service deployed by these workflows.
Local checks do not imply hosted CI success. See [CONTRIBUTING.md](CONTRIBUTING.md).

## The platform

| Repository | Plane | Role |
|---|---|---|
| [iokaio/munarium-platform](https://github.com/iokaio/munarium-platform) | hub | Architecture, normative contracts, decision records, roadmap and composition evidence for the whole platform |
| [iokaio/munarium](https://github.com/iokaio/munarium) | foundation (mediation) | Munarium Server: governed memory, the append-only ledger, and the Server client libraries |
| [iokaio/munarium-matrix](https://github.com/iokaio/munarium-matrix) | foundation (mediation) | Munarium Matrix: governed, read-only structured evidence from enterprise data sources |
| [iokaio/munarium-registry](https://github.com/iokaio/munarium-registry) | authority | Inventory of agents, tools, manifests, and policy bundles |
| [iokaio/munarium-harness](https://github.com/iokaio/munarium-harness) | agent | SDKs that make the governed path easy for honest agents |
| [iokaio/munarium-warden](https://github.com/iokaio/munarium-warden) | authority | Workload identity, delegation, just-in-time credentials, kill switches |
| [iokaio/munarium-gate](https://github.com/iokaio/munarium-gate) | mediation | Policy decision and enforcement point for every tool call |
| [iokaio/munarium-gateway](https://github.com/iokaio/munarium-gateway) | mediation | Model-call mediation: routing, BYOK, budgets, screening |
| [iokaio/munarium-council](https://github.com/iokaio/munarium-council) | authority | Approvals, policy lifecycle, ratified governance transitions |
| [iokaio/munarium-sentinel](https://github.com/iokaio/munarium-sentinel) | assurance | Telemetry, anomaly detection, circuit breakers, incident replay |
| [iokaio/munarium-assure](https://github.com/iokaio/munarium-assure) | assurance | Control-framework mapping and evidence packs |
| [iokaio/munarium-console](https://github.com/iokaio/munarium-console) | assurance | One interface for approvers, operators, and auditors |
| [iokaio/munarium-clients-publish](https://github.com/iokaio/munarium-clients-publish) | tooling | The one place Munarium client packages are built for release and published from |
| [iokaio/munarium-demo](https://github.com/iokaio/munarium-demo) | examples | Munarium Demo: working applications and bundled datasets for evaluating the foundation |

The development tool VCP ([iokaio/vcp](https://github.com/iokaio/vcp)) is separate: not one of the
nine components and not a runtime dependency for adopters. Ioka's private repositories hold
planning material awaiting publication review and the proprietary Matrix analytics adapters;
nothing from them is copied into a public repository without that review.

## Licensing

Apache-2.0 ([LICENSE](LICENSE), [NOTICE](NOTICE)). The names are not part of that grant:
[TRADEMARK.md](TRADEMARK.md) says what you may do without asking, which is most things. There is
no proprietary edition of this component and none is planned; a capability that arrives later is
deferred roadmap work, not a commercial restriction.

## Contributing, support, security

Signed-off pull requests, no CLA ([CONTRIBUTING.md](CONTRIBUTING.md)). Questions go to Discussions,
defects and design findings to Issues, and suspected vulnerabilities to the private channel
[SECURITY.md](SECURITY.md) names, never a public issue. What is and is not supported:
[SUPPORT.md](SUPPORT.md). Conduct: [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). Release history,
such as it is: [CHANGELOG.md](CHANGELOG.md).
