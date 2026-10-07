# REG-01 local candidate implementation

**Experimental library, 6 October 2026.** REG-01's local validation/intake/lookup slice is
implemented. Formal contract acceptance, Stage 1 integration and production qualification
remain pending. This is not the later activation, persistence or cache work in REG-02/03.

## Inputs and authority

Registry base: `f2efebac7ed1c86e72264a0d7f2b6110fcce212a`, branch
`experiment/reg-01-candidate-catalog`. Hub base:
`c46f86400732223a6a7c23f5d186250ab4a144eb`, branch `experiment/reg-01-contracts`.
The Registry contract source is published at hub
`dff725159fd02035589ad2f78ce74db7f1bd7329` for draft PR review; it is not merged or
accepted. The Registry consumer is prepared on the branch above. The user explicitly requested contract
creation and implementation after the [readiness packet](reg-01-readiness.md) and Registry ADR
proposal. This authorizes the local experiment; it does not supply a formal acceptance record.
The [Warden review](warden-integration.md) records the subsequent pulled changes, Registry
ADR renumbering to 0006 and receiving-side identity integration.

The [vendored bundle](../contracts/README.md) pins the actual new input independently of the
unchanged hub base. Aggregate SHA-256:
`2e121d86c8dd4061ef1bdbc9dc073dceebfebf7305cf7a50d5d0e59385eaf0fc`.
Its lock covers schemas, signed vectors, fictional trust inventory and semantic profile.
Rust tests verify each file hash and the aggregate against the source constant.

Scope: candidate modules, tests/example, pinned dependencies and notices, vendored contract
and their documentation; corresponding new contract/checker files in the hub. The existing
activation trait, hub foundation candidate, foundation code, operational trust, signing
configuration and release settings remain unchanged. Limit: this local implementation and
validation session, at most two hours, no paid test environment. The maintainer subsequently
authorized the [bounded CI and contributor-documentation repairs](reg-01-maintainer-changes.md).

The diff exceeds 500 non-generated lines because signature parsing, manifest validation,
trust admission, immutable storage and refusal tests form one verifiable boundary. Review
the hub contract and Registry consumer separately, with the exact bundle digest connecting
them. Generated schema/vector files are separate from handwritten runtime/checker code.

## Library boundary

`Registry` is owned by a **trusted embedding host**. That host provisions current
`TrustSnapshot` values. The [identity adapter](../src/identity.rs) verifies original signed
chains on every submit, read or list against current host authority and authenticated peer.
`Caller::from_verified_identity` remains a low-level adapter for already verified contexts,
not authentication or an untrusted request decoder. [Warden compatibility](warden-integration.md)
has local evidence; provider and transport authentication remain host responsibilities.
Untrusted code cannot safely share the host process.

The host borrows `Intake` or `Reader` handles for a caller. Intake implements
`CandidateIntake`; readers implement `CatalogReader` and tenant-scoped listing.
Neither handle can replace trust or activate an artifact. No effective catalog exists here;
a compile-fail test proves the intake handle does not implement `ActivationStore`. That
type boundary is not evidence of deployed process separation or an activation protocol.

Signatures use strict Ed25519 verification over canonical compact JWS input. The pinned
closed manifest schema validates complete fields, supported profile, upward-only modifiers,
classifications and declared obligations. Referenced parameter/result schema bytes are
digest-checked and validated against the bounded vocabulary. Registry does not evaluate
modifier predicates, prove lineage or validate a connector's real behavior; Gate must do so.

Each admitted `(tenant, id, version)` retains exact signed envelope and payload bytes.
Different bytes conflict; identical retries recheck current trust and preserve their original
admission revision. Content lookup accepts an optional exact-envelope digest constraint.
There is no latest-version fallback. Missing and foreign-tenant digests return `NotFound`.
Listing reveals only the caller's tenant, with a separate list permission and capacity bound.

Host snapshot replacement requires an increasing revision. Unavailable trust refuses
submissions, reads, lists and retries; stale revisions cannot restore permission. Mutable
borrowing excludes updates while an operation is using a snapshot. Every successful result
reports both admission and current verification revisions. The host must deliver changes
and enforce caller-context freshness. No clock, distributed revocation deadline, durable
transaction, recovery epoch or remote trust cache is implemented.

## Local recipe

Use Rust 1.98.1, rustfmt, Clippy and a native linker. From the Registry root, first fetch
the exact public crates pinned in `Cargo.lock`:

```console
cargo fetch --locked
cargo fmt --all --check
cargo build --offline --locked
cargo clippy --offline --locked --all-targets -- -D warnings
cargo test --offline --locked
cargo doc --offline --locked --no-deps
cargo run --offline --locked --example candidate_catalog
```

The [example](../examples/candidate_catalog.rs) uses only public fixture signatures and
verification keys. It admits one inert alpha candidate, resolves identical bytes and prints
the digest and inventory count. It opens no port and creates no service, database, container,
operational key or active artifact. Cargo's `target/` directory is reusable build output.
The pinned dependency graph must be cached before any offline check, including clean CI.

## Acceptance coverage and retained results

The [component tests](../tests/reg_01.rs) consume **32 signed cases**: six independently
valid artifacts and 26 refusals. They additionally exercise stateful sequences. The
[parser/schema tests](../src/validation_tests.rs) cover canonical encoding, integer,
Unicode, size/depth boundaries and unsupported schema keywords/references.

| Readiness cases | Observed local coverage |
|---|---|
| A, B | Exact envelope/payload and both digests resolve; unknown and substituted digest pairs refuse. |
| C, D | Unsigned, corrupt, incompatible, unknown-publisher and ambiguous/noncanonical inputs refuse with typed errors. |
| E | Changed payload and re-signing conflict; original remains readable; identical retry adds no entry. |
| F | No activation implementation or effective store is reachable from intake; compile-fail type check. Integrated before/after activation test remains unavailable. |
| G | Two tenants sharing raw verification key bytes remain isolated for submit, read and listing; permissions are independent. |
| H, I | Unsupported schemas, substituted/missing references, wrong operation/audience, missing owner/classification/obligation and lowering modifiers refuse. |
| J | Failed admission and exhausted per-tenant capacity leave existing inventory unchanged; durable failure/recovery is outside this in-memory boundary. |

Retained task output currently records:

| Command | Result |
|---|---|
| `cargo test --offline --locked` | Exit 0: 2 parser/schema tests, 11 candidate tests, 9 identity tests, 1 compile-fail doc test; zero failed or ignored |
| `cargo fmt --all --check`; `cargo build --offline --locked` | Each exit 0 |
| `cargo clippy --offline --locked --all-targets -- -D warnings` | Exit 0 |
| `cargo doc --offline --locked --no-deps` with `RUSTDOCFLAGS=-D warnings` | Exit 0 |
| `cargo run --offline --locked --example candidate_catalog` | Exit 0: exact candidate bytes resolved; one inert candidate, activation unavailable |
| Hub: `python -m unittest discover -s scripts -p "test_*.py"` | Exit 0: 60 tests, including independent OpenSSL signature/vector and bundle checks |
| Hub: `python scripts/check_registry_jsonschema.py` | Exit 0: two meta-valid schemas; 153 positive/negative shape checks using jsonschema 4.25.1 |
| Both repositories: `python check_license.py`, `python scripts/private_material_scan.py`, `python scripts/docs_linkcheck.py`, `git diff --check` | Each exit 0 |

Local Rust commands used `rustup run stable cargo` after checking rustc/cargo 1.98.1.
The mutable alias is not a future toolchain pin. Full output and command exit codes remain
in the task transcript. Initial sandbox lockfile/format writes failed on file permissions;
the authorized retry succeeded. Full offline dependency metadata initially failed because
two target-specific crates were absent; `cargo fetch --locked` populated the cache.
These failures are not relabeled as successful first runs.

Gitleaks was initially unavailable. Subsequent hosted scans reported the public signed
fixtures; the [authorized repair record](reg-01-maintainer-changes.md) documents the exact
exceptions and passing local directory/history scans. Hosted CI is verified separately.
The Python verifier and Rust consumer agree on the fixed candidate, not on all possible
malformed Ed25519 points or a qualified service deployment. No independent human review
or formal contract disposition is claimed.

## Remaining work

The hub source is pinned above; the Registry PR head identifies the consumer revision.
Formal ADR/contract acceptance,
provider and authenticated service-hop integration and the S1/S2–S4 integrated
foundation gates remain open. REF-01 replay belongs to the composition.

REG-02 supplies durable storage, separately authorized activation, compare-and-set and
crash/recovery evidence. REG-03 supplies consumer cache freshness and retirement handling.
This library must not be advertised as completing those packets or the complete Registry
service. Candidate authenticity never grants permission to execute or govern.
