# REG-01 readiness and acceptance packet

**Historical design preparation, 6 October 2026.** The subsequent instruction to create the
contracts and proceed authorized the [REG-01 local implementation](reg-01-implementation.md).
The remaining text preserves the original preparation findings and check results; it is
not the current implementation-status record. Formal acceptance remains pending.

This packet makes
[REG-01](implementation-plan.md#first-work-packet-reg-01-validate-and-resolve-a-candidate-manifest-without-activating-it)
reviewable: validate and resolve an immutable candidate manifest without activating it.
Scope is readiness and acceptance preparation. This does not accept hub proposals, approve
a fixture oracle, or advance any capability in the [README](../README.md).

## Scope and immutable inputs

| Item | Recorded boundary |
|---|---|
| Target | `iokaio/munarium-registry`; base `f2efebac7ed1c86e72264a0d7f2b6110fcce212a`, matching freshly fetched `origin/main` |
| Branch | `docs/reg-01-readiness`; local documentation changes only |
| Hub | `iokaio/munarium-platform` at `eaa33e8dfafc53f2874fecaa5b62e69208d45793`; remote main matched when inspected |
| Preparation files | This page, `docs/README.md`, `docs/implementation-plan.md` |
| Unchanged interfaces | `CatalogReader`, `CandidateIntake`, `ActivationStore`; all associated types remain unspecified |
| Preparation limit | One local session, capped at 30 minutes; no paid environment or external test service |
| Evidence destination | Local command observations below; future component evidence belongs with its implementation |
| Accountable acceptance authority | Founder/maintainer under hub governance; no acceptance or human review recorded here |

The pinned [parallel plan][parallel] places Registry beside Warden after initial contract
acceptance and foundation gates. The [foundation observations][foundation] exist, but record
S1 as partial and explicitly do not declare its authority gate complete. No foundation
runtime was inspected or retested for this Registry preparation.

Reviewed design inputs are [ADR-0003][principal], [ADR-0004][decision], the
[decision register][register], and the [candidate definitions][candidates]. They are
proposed inputs, not supported contract versions. Candidate file hashes, with CRLF normalized
to LF as the hub specifies, were independently recomputed and matched [the lock][lock]:

| Input | SHA-256 |
|---|---|
| `foundation.schema.json` | `dbf067bbcd0f708fd37feff581f323dcb2a2222d101af78c5bc34bf30f1881fb` |
| `identity-vectors.json` | `a60f52749ad657fea82abdddc79955b235946391bb1a7a76373a705bba111c2d` |
| `record-vectors.json` | `fbe93424547d4dfc4387823ef2cd28d964ff32027c6af84f07d61a5853142d1b` |
| Aggregate candidate bundle | `5ee201e48a2390b7cf66fdf6aa8750f751f1ec9241e9e04131b6632745612238` |
| [Canonical vectors][canonical], LF-normalized file | `849033a2d90681b378754603b8129866cc28a5fa400996d8b8807b87fd959775` |

These pins identify review material only. No fixtures were copied, generated or reapproved.
The hub's offline checker is a test oracle, not a library to import into Registry.

## Decisions required before implementation

| Gate | Observation at the pinned revision | Required resolution |
|---|---|---|
| Accepted definitions | DEC-01/02 and ADR-0003/0004 remain proposed. | Record maintainer acceptance, versioned contracts, exact bundle/vector digests and compatibility policy. |
| Manifest authenticity | Candidate JWS vectors cover principal/bootstrap assertions. The manifest shape has no artifact signature envelope. | Specify signed artifact bytes, envelope, trusted publisher provisioning and refusal vectors; do not reuse principal signing semantics by inference. |
| Immutable identity and bytes | The proposal supplies manifest `id`, `version` and a canonical manifest hash domain. | Define identity namespace, tenant scope, which bytes are retained/resolved, and how differently encoded but canonically equal submissions interact with the same-identity/different-bytes rejection. |
| Tenant and owner binding | The manifest shape has no tenant or owner field; caller identity and surrounding records carry tenant context. | Specify where authoritative tenant/owner binding lives and how resolve/list/intake authenticate and authorize it. A caller-supplied tenant cannot establish access. |
| Complete manifest contract | Candidate shape pins parameter/result schema digests and effect declarations, but does not include the README's data classifications or required obligations. | Reconcile those requirements in the hub; define supported schema dialect, reference admission, operation binding and incompatible/unknown-field behavior. Do not silently extend the local wire schema. |
| Inert versus effective views | Candidate schemas cannot prove activation. The current reader trait only declares `resolve`; no listing/effective-view API exists. | Define candidate resolution results and the separate active digest/epoch/trust binding consumed by Gate. Decide the local listing seam without giving intake activation authority. |
| Foundation and integration | FOUNDATION-01 records gaps; the first integrated slice requires accepted HUB-01/02, S1 and S2–S4 support. | Supply the relevant evidence and exact Warden/Server/Gate/Harness revisions before integration; a standalone component test cannot close these gates. |

Activation transaction, Council attestations, durable storage, revocation delivery and cache
freshness belong to REG-02/03 and their accepted decisions. REG-01 must preserve those
boundaries, but must not implement placeholder activation to make an effective view appear
available. DEC-03 and minimum DEC-07/08 remain shared Stage 1 integration prerequisites.

## Proposed implementation boundary after acceptance

Limit the next packet to manifest validation, inert intake, immutable candidate lookup and
tenant-scoped listing as required by REG-01. Potential paths are `src/catalog.rs`,
`src/intake.rs`, a component-local validator module exported by `src/lib.rs`, component
tests/fixtures and accompanying documentation. These are proposed paths, not an approved
runtime design. Preserve the distinct activation interface and leave its implementation
unavailable. Select storage and dependencies only in the reviewed implementation packet.

Do not add a listener, deployment, provider call, shared DTO fork, signing-key change,
policy activation, release, protected workflow edit or fixture-baseline rewrite. Do not
edit the hub or Server from this packet. Contract questions return to their hub owner.

Before execution, fill in the component/coordinating issue links, named packet owner and
reviewer, accepted contract and oracle pins, exact permitted files, dependency review,
required environment, implementation/review estimates and an agreed time/model-spend ceiling.
Those implementation intake fields remain pending; the preparation limit above does not
authorize implementation. Stop if a necessary definition is missing, a pin changes, a check
fails, or a proposed change crosses an authority boundary. Retain the gap for review.

## Proposed acceptance cases

All rows below are **unimplemented and unrun**. IDs are local test-planning references,
not hub error codes or approved golden vectors. Exact errors and fixtures follow accepted
contracts. Use fictional tenants `alpha` and `beta`, independently authenticated caller
contexts, immutable artifact bytes, public verification material and controlled invalid
variants. An original accepted artifact must remain readable after each rejected mutation.

| Case / invariant | Setup and operation | Required observation |
|---|---|---|
| REG-01-A / INV-04 | Admit a valid signed candidate for alpha; resolve its exact identity/digest as an authorized alpha reader. | Return exactly the recorded artifact bytes and contract-defined metadata; remain a candidate with no activation authority. |
| REG-01-B / INV-04 | Resolve an unknown digest, or a valid identity paired with another digest. | Typed refusal, no latest-version fallback or substituted bytes. |
| REG-01-C / INV-04 | Submit unsigned content, corrupt its signature, use an unknown publisher, or change covered bytes. | No verified candidate admission; no catalog mutation. Retired/revoked publisher cases follow the accepted trust profile. |
| REG-01-D / INV-04 | Use an incompatible version, missing/unknown field, malformed encoding or over-limit input from accepted vectors. | Fail closed with the defined reason; no dropped fields, inferred defaults or partial admission. |
| REG-01-E / INV-04 | Reuse an admitted identity/version with different bytes, including canonical-equivalent encoding variants per the accepted identity rules. | Reject replacement; original bytes remain unchanged. Identical-byte retry behavior must be specified separately. |
| REG-01-F / INV-02 | Snapshot the effective view and epoch; submit a valid agent/discovery candidate; reread both. | Candidate can be inspected through its authorized path; effective view and epoch remain unchanged. Caller-supplied activation flags/attestations confer no authority. |
| REG-01-G / INV-02, INV-04 | Alpha submits, resolves or lists using beta's identity/digest or a forged tenant context. | No cross-tenant artifact or inventory disclosure and no beta mutation; refusal/absence behavior follows the accepted disclosure contract. |
| REG-01-H / INV-04 | Resolve missing/substituted parameter or result schemas, or mismatch the admitted target/environment/audience. | Reject unsupported or unverified references/bindings; never fetch an arbitrary URL or accept a digest-shaped string as verified content. |
| REG-01-I / INV-04 | Submit a modifier that lowers consequence, or omit a contract-required owner/classification/obligation. | Reject according to the accepted complete manifest contract; no local weakening of mandatory constraints. |
| REG-01-J / INV-02 | Fail validation, or inject a storage failure known to precede candidate commit. | No success-shaped receipt, partial candidate or effective change. Test actual storage and separately define uncertain acknowledgement handling when persistence enters scope. |

Component tests should assert observable bytes, typed failures, tenant isolation and state
before/after, rather than only exercising a fake that was written to return the expected
answer. If an effective-view test uses an in-memory model, label that boundary explicitly;
it does not qualify durable activation or the deployed authority separation.

Integration must also show Gate refusing a candidate as active authority without an admitted
binding, and preserve Stage 1 manifest, tenant and lineage refusal evidence. REF-01 replay
belongs to the integrated slice. Stale activation races and retired-cache behavior stay in
REG-02/03; federation INV-20 remains Stage 5. No local test substitutes for those gates.

## Local preparation checks

Run on Windows with Python 3.13.7. The installed `stable` toolchain reported
`rustc 1.98.1 (48a229cea 2026-09-01)` and `cargo 1.98.1 (797e8a9bc 2026-08-05)`.
Commands used `rustup run stable cargo` after verifying those versions; future runs must
verify again because `stable` is mutable. Cargo's bin directory was added only to the
process PATH. Git used a process-local `safe.directory` exception for this checkout.

| Command from Registry root | Exit / retained observation |
|---|---|
| `rustup run stable cargo fmt --all --check` | 0; no output |
| `rustup run stable cargo build --offline --locked` | 0; `Finished` dev profile |
| `rustup run stable cargo clippy --offline --locked --all-targets -- -D warnings` | 0; `Finished` dev profile, no warnings |
| `rustup run stable cargo test --offline --locked` | 0; unit tests and doc tests each reported `0 passed; 0 failed; 0 ignored` |
| `rustup run stable cargo doc --offline --locked --no-deps`, `RUSTDOCFLAGS=-D warnings` | 0; generated local API documentation |
| Candidate pin verification, read-only Python SHA-256 recomputation | 0; all three file digests and the aggregate matched; canonical-vector file digest recorded above |
| `python check_license.py` | 0; `texts canonical, 9 source files headed -- ok` |
| `python scripts/private_material_scan.py` | 0; `clean across 38 files` |
| `python scripts/docs_linkcheck.py` | 0; `18 markdown files, every link resolves, every page is indexed` |
| `git diff --check` | 0; no output |

Full command output is retained in the task execution transcript. These are scaffold and
input-integrity observations, not manifest validation or contract-conformance evidence.
The named `+1.98.1` probe initially exited 1 because its alias was absent and rustup could
not write its synchronization temporary file; using the installed, version-checked toolchain
required no download. Gitleaks was not found on PATH or in the checked standard install
locations; its probe failed and the secret scan remains unavailable, not passed.

No hosted CI, runtime acceptance or foundation suite was run. Cargo generated only reusable `target/`
build/documentation output. No service, container, database, port or credential was created.

## Implementation handoff requirements

Retain source/contract/vector hashes, commands and exit codes, actual output, tool versions,
fixture identities, expected versus observed results and all failed/unavailable checks in
the implementation evidence. Keep human review and approval fields pending until performed.
Start from a freshly fetched base and reassess this packet against newly accepted inputs.
Runtime implementation remains blocked until the decisions and intake fields above close.

[parallel]: https://github.com/iokaio/munarium-platform/blob/eaa33e8dfafc53f2874fecaa5b62e69208d45793/docs/parallel-build-plan.md
[foundation]: https://github.com/iokaio/munarium-platform/blob/eaa33e8dfafc53f2874fecaa5b62e69208d45793/docs/architecture/foundation-01.md
[principal]: https://github.com/iokaio/munarium-platform/blob/eaa33e8dfafc53f2874fecaa5b62e69208d45793/docs/decisions/0003-bootstrap-principal-context.md
[decision]: https://github.com/iokaio/munarium-platform/blob/eaa33e8dfafc53f2874fecaa5b62e69208d45793/docs/decisions/0004-decision-only-contracts.md
[register]: https://github.com/iokaio/munarium-platform/blob/eaa33e8dfafc53f2874fecaa5b62e69208d45793/docs/architecture/contract-backlog.md
[candidates]: https://github.com/iokaio/munarium-platform/blob/eaa33e8dfafc53f2874fecaa5b62e69208d45793/docs/decisions/candidates/README.md
[lock]: https://github.com/iokaio/munarium-platform/blob/eaa33e8dfafc53f2874fecaa5b62e69208d45793/docs/decisions/candidates/candidate-lock.json
[canonical]: https://github.com/iokaio/munarium-platform/blob/eaa33e8dfafc53f2874fecaa5b62e69208d45793/docs/decisions/decision-json-v1-vectors.json
