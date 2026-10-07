# Munarium Registry validation

## Build and test the candidate library locally

Use Rust **1.98.1** with Cargo, rustfmt and Clippy, plus the platform's native linker.
The manifest requires Rust 1.98; older toolchains are not qualified by this scaffold.
CI installs 1.98.1 explicitly. Prime dependencies using `cargo fetch --locked`.
No provider account, database, model key, container or sibling checkout is needed:

```console
cargo fmt --all --check
cargo build --offline --locked
cargo clippy --offline --locked --all-targets -- -D warnings
cargo test --offline --locked
cargo doc --offline --locked --no-deps
```

`Cargo.lock` is checked in. Do not regenerate it to bypass a locked-build failure.
The lock pins the complete dependency graph; [third-party notices](../THIRD_PARTY_NOTICES.md)
record its provenance and licenses.

Build and lint validate the library. Tests exercise the [REG-01 candidate implementation](reg-01-implementation.md),
including 32 fixed signed cases, mutation/refusal boundaries and contract-integrity pins.
The receiving-side tests additionally consume 32 unchanged signed principal cases and
exercise current authority, recipient/peer binding and candidate API permissions.
The [Warden probe recipe](warden-integration.md#interoperability-recipe) compiles the
actual pinned Warden library separately; ordinary Registry builds need no sibling checkout.
`cargo doc` produces local API documentation under `target/doc/`.

Run the existing repository checks too:

```console
py check_license.py
py scripts/private_material_scan.py
py scripts/docs_linkcheck.py
gitleaks dir . --config .gitleaks.toml --no-banner --redact --exit-code 1
git diff --check
```

Use `python` or `python3` if the `py` launcher is unavailable. The secret command scans
the working tree; the existing hygiene workflow also scans Git history. No local result
is evidence that hosted CI passed.

## Automatic coverage

The new [Rust workflow](../.github/workflows/rust.yml) runs formatting, build, lint, tests
and warning-free API documentation on pushes to main and pull requests. It uses read-only
repository permissions and has no publishing, deployment or provider steps.
The existing [hygiene workflow](../.github/workflows/repo-hygiene.yml) and
[DCO workflow](../.github/workflows/dco.yml) retain their independent checks.

## Required behavioral acceptance cases

REG-01 candidate refusal cases have local component coverage. Activation races, cached
revocation and federation below remain **unimplemented**. Invariant IDs refer to the catalog in
[platform plan revision 4, Appendix C](https://github.com/iokaio/munarium-platform/blob/main/docs/platform-plan.md) and the
[hub catalog](https://github.com/iokaio/munarium-platform/blob/main/README.md#the-invariant-catalog). No contract bundle has been released.

| Invariant | Scenario | Required observation |
|---|---|---|
| INV-02 | Submit an agent/discovery candidate, then query effective catalog. | No effective capability is added. |
| INV-04 | Use unknown digest, unsigned bundle, incompatible schema, or changed bytes under the same identity. | Typed refusal; no substitution or fallback. |
| INV-02 | Race activations and replay a stale expected epoch. | One durable transition; conflict for stale state. |
| INV-04 | Present a revoked cached artifact after its allowed freshness window. | Consumer refuses new use. |
| INV-20 | Attempt to activate a local overlay that waives a parent prohibition. | Refused when federation is implemented; not a Stage 1 claim. |

INV-21 (protected development authority) and INV-22 (claims bounded by evidence)
apply to every packet in addition to the component-specific cases.

## Evidence to retain when the tests exist

Record source and contract digests, toolchain, fixture identifiers, command/exit status,
environment, declared trust boundary, expected and actual outcome, and remaining gaps.
Concurrency, crash/restart, identity, network and storage claims require their real test
environment; an in-memory fake cannot certify them. A live integration needs its own
authorization and qualification record.

Keep operational credentials and raw private payloads out of test artifacts. Distinguish
a local pass, unavailable coverage, a failing case, and an independently reviewed result.
No capability-status or invariant-evidence field advances from the scaffold checks.
