# Warden review and Registry receiving-side integration

This completes the local REG-01 identity adapter against the pulled **proposed**
platform contracts. It is experimental component evidence, not a qualified deployment.
No activation, persistent catalog, provider federation or network endpoint is supplied.

## Reviewed inputs and resulting changes

- Platform main: `c46f86400732223a6a7c23f5d186250ab4a144eb`, the merged Warden
  identity contract, ADR 0005, admission schema/lock and review tests.
- Warden published main: `e89367ca2ce613760d43ef3ef9139980b41c4dd2`, fetched and
  inspected by exact revision. Its principal verifier is implemented, while its runtime
  documentation explicitly leaves provider enrollment and authenticated topology open.
  Its grant/activation/broker capabilities do not implement Registry's catalog activation.
- Registry: the REG-01 work on `experiment/reg-01-candidate-catalog`,
  base `f2efebac7ed1c86e72264a0d7f2b6110fcce212a`.
- Hub Registry worktree: `experiment/reg-01-contracts` fast-forwarded to the pulled
  platform main while preserving its Registry additions, subsequently published at
  `dff725159fd02035589ad2f78ce74db7f1bd7329` for draft PR review.

The previously unpublished Registry ADR 0005 conflicted with the merged Warden ADR.
It is now ADR **0006** in the hub worktree. Registry's bundle README and lock were
updated for that reference and the recipient adapter. Manifest schema, trust fixture,
signed artifacts and expected outcomes were preserved. [Contract inputs](../contracts/README.md)
record both the prior and current aggregate pins.

The unchanged hub identity/admission bundles are [vendored separately](../contracts/identity-v1/README.md).
There is no production dependency on Warden, its credential broker or its SQLite backend.
No Warden checkout source was edited.

## Receiving-side boundary

[identity.rs](../src/identity.rs) verifies the complete original compact chain on every
candidate operation. It checks canonical JSON/base64url, strict Ed25519 signature, key
purpose, exact issuer/deployment/tenant/recipient, current validity and leaf transport peer.
Every ancestor remains current; scopes/resources and validity fit both the independently
admitted task and target policy. Parent digests, origin, unique actors, depth, exact current
edge registrations and attenuation are checked before returning verification evidence.
Each edge's presenter matches that child's service; only the leaf matches the actual peer.

The host supplies current keys and registrations, task/policy revisions, a clock with at
most two seconds uncertainty, and independently authenticated routing/peer facts.
Unavailable or quarantined authority refuses. This typed context cannot be accepted from
request JSON. Public context fields configure a trusted host adapter; they are not identity
proof. The lower-level `Caller::from_verified_identity` remains a trusted-host escape hatch
for other qualified adapters, not an endpoint for untrusted callers.

Host access rules separately admit submit, resolve and list for an exact registered catalog
resource. Signed `propose` is required for submit; signed `read` is required for resolve/list.
An unrelated target-resource claim does not imply catalog access, and there is no wildcard
or inferred tenant-wide permission. A verified principal proves identity and bounded scope;
the independent host access rule still decides the local operation.

Verification returns exact leaf fields/digest, ordered registration IDs and task/policy
references. That evidence has no caller conversion or deserialization API. Subsequent
operations reverify original evidence and current state rather than trusting an old result.
Key retirement, scope withdrawal, expiry and authority outages therefore affect retries,
reads and lists as well as new submissions when the host supplies current state.

Human/bootstrap/govern/ratify paths refuse. A forwarded attribution record cannot authorize
Registry operations. Gate must use its own separately admitted Registry-bound service
assertion; a Harness-to-Gate assertion cannot be retargeted or reused at Registry.
The library has no transport, provider-subject mapping, policy activation or distributed
freshness mechanism. Those deployment responsibilities remain explicit.

## Interoperability recipe

With Rust 1.98.1, Python 3.12+ and the public Warden Git checkout containing the exact
reviewed commit, run from Registry:

```console
python scripts/verify_warden.py --warden D:/code/Github/munarium-warden --fetch
```

The [probe script](../scripts/verify_warden.py) exports only the pinned commit into a
temporary directory, retains Warden's dependency lock and verifies that no external
dependency version changed when adding the two local crates. `--fetch` primes the public
Warden dependencies; omit it on a cached run. The actual probe builds/runs offline and
locked. It creates no service, provider, credential, database or activation.

The [probe source](../tests/interop/warden.rs) passes the unchanged 32-case signed corpus
to both real verifiers. Two nonhuman cases are accepted; the bootstrap positive case is
explicitly outside both decision-only profiles and the other 29 cases refuse. Accepted
leaf digests, origin/kind, actor, tenant, audience, service, scopes and resources agree.
This establishes agreement on these vectors, not equivalence over all possible inputs
or provider/transport interoperability. The probe is optional local integration coverage,
not a new ordinary CI dependency or a claim that Warden's other suites ran here.

## Retained local results

The task transcript retains full commands, exit codes and output:

| Check | Observed result |
|---|---|
| `cargo test --offline --locked` | Exit 0: 2 parser tests, 11 candidate tests, 9 identity tests, 1 compile-fail doc test; none skipped |
| `cargo fmt --all --check`; `cargo build --offline --locked` | Each exit 0 |
| `cargo clippy --offline --locked --all-targets -- -D warnings` | Exit 0 |
| `cargo doc --offline --locked --no-deps` with warnings denied | Exit 0 |
| `python scripts/verify_warden.py --warden D:/code/Github/munarium-warden --fetch` | Exit 0: compiled actual Warden at the pinned revision; all 32 comparisons agree |
| Probe dependency lock SHA-256 | `ea90fee2ed26e515bf506ac30813b87579dbb9e9ed4853f796b97a0e0f5a7b26` |
| Hub `python -m unittest discover -s scripts -p "test_*.py"` | Exit 0: 60 tests, none skipped |
| Hub `python scripts/check_registry_jsonschema.py` | Exit 0: 153 independent shape checks |
| Both repositories: license, private-material, documentation links and `git diff --check` | Each exit 0 |

The first identity test run had three fixture-setup failures because the pretty-printed
inventory was passed to a canonical-only API; canonicalizing the trusted test setup fixed
the cause without relaxing that API or changing fixtures. The first interoperability
attempt could not reach crates.io in the sandbox; an offline attempt then confirmed
Warden's rusqlite index was absent. Authorized fetching of Warden's exact lock populated
the cache and the probe subsequently passed. These initial failures remain in the record.

Temporary exported checkouts were removed by the probe's scoped cleanup. Only reusable
Cargo caches and `target/warden-interop/` build output remain. Formal ADR acceptance,
service/transport integration and Stage 1 composition gates remain open.

Gitleaks was initially unavailable. Hosted CI then exposed the missing dependency-fetch
step and 31 JWT-rule matches against the public signed-manifest fixtures. The maintainer
subsequently authorized the [build-support repairs](reg-01-maintainer-changes.md):
locked cache preparation, exact fixture exceptions and aligned contributor descriptions.
Local directory/history scans and all eight scanner boundary checks now pass.
The original failures remain recorded; hosted results must be checked at the updated PR heads.
