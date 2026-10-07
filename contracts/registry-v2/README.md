# Registry v2 candidate contract

**Implementation candidate, not an accepted or released contract.** This bundle makes
ADR-0006 (hub `docs/decisions/0006-registry-manifest-admission.md`) concrete for the authorized REG-01
experiment. Formal maintainer disposition and integrated platform qualification remain open.
No artifact in this directory activates policy or provisions a trusted publisher.

## Contents and pins

| File | Role |
|---|---|
| [registry.schema.json](registry.schema.json) | Draft 2020-12 closed definitions for the manifest, protected header and trusted inventory snapshot |
| [capability.schema.json](capability.schema.json) | Closed shape vocabulary for referenced parameter/result schemas |
| [signed-vectors.json](signed-vectors.json) | 32 fixed cases: six valid signed artifacts and 26 refusals |
| [trust.json](trust.json) | Fictional two-tenant inventory and public keys; never production trust configuration |
| [bundle-lock.json](bundle-lock.json) | File hashes and aggregate digest consumed by Registry |

The old foundation candidate remains unchanged. File hashes normalize CRLF to LF; aggregate
SHA-256 covers sorted filename, one NUL byte, lowercase file hash and newline. The lock is
an integrity pin, not a publisher signature or acceptance statement. This README is included
in the pin because it specifies semantic constraints beyond JSON Schema.

## Exact admission contract

ADR-0006 defines compact JWS, canonical JSON, signature coverage, v2 digest domains and
immutable `(tenant, id, version)` identity. This bundle uses its complete required payload;
extra fields, including activation claims, refuse. Unknown/incompatible profiles refuse.
Canonical byte bounds are 512 for the decoded header and 65,536 for the payload; envelope
bound is 90,000 ASCII bytes. Exactly 16 nested JSON containers are permitted.
The protected header contains exactly `alg=Ed25519`, `typ=munarium-manifest+jws` and a
provisioned `kid`. Encode canonical header and payload as unpadded canonical base64url;
sign their ASCII segments joined with a dot, then append a dot and the encoded signature.
Retain the complete envelope without a trailing newline. Manifest content digest covers
UTF-8 `munarium:manifest:v2`, one NUL, and canonical payload bytes. Artifact digest covers
UTF-8 `munarium:manifest-artifact:v2`, one NUL, and the complete ASCII envelope. Both use
SHA-256 rendered as lowercase `sha256:` hexadecimal. A payload never includes its own digest.

Verification checks caller permission, current trusted tenant, envelope/header encoding,
manifest shape and upward-only modifiers, payload tenant, enabled publisher/key, Ed25519
signature, enrolled/authorized owner, operation tuple and classification inventory.
All failures refuse admission. Fixed single-defect cases pin refusal categories; where an
input violates multiple constraints, consumers may report the first applicable refusal.
No refusal exposes another tenant's records.

Artifact verification rejects weak Ed25519 public keys and uses strict signature
verification; the Rust consumer uses ed25519-dalek's strict verifier. The Python oracle
uses OpenSSL on the fixed non-weak public keys. Agreement on these fixtures does not claim
general cryptographic interoperability for all malformed or noncanonical curve points.

Trusted snapshot JSON is also canonical, with a 65,536-byte bound. Its schema version is 2
and revision is a positive safe integer. Tenant IDs, owner IDs, publisher `(id, kid)` pairs,
schema digests and `(target_id, environment, operation_id)` tuples must be unique within
their respective namespaces. Each tenant has at most 32 records in each inventory collection.
Enabled publishers may name only enrolled owners and exact admitted operation records.
These records are manifest-signing authorizations by type; they do not confer principal
issuer purpose. Shared key bytes never share tenant authorization.

Operation bindings compare all seven fields: target, environment, operation, audience,
capability, parameter schema digest and result schema digest. Both schema references must
resolve in that tenant. Classifications must be members of its independently admitted
vocabulary. Required inputs and modifier predicate references are declarations for Gate:
Registry checks their shape and upward-only consequence semantics but does not evaluate
predicates or qualify lineage. Gate must separately verify them before evaluation.

The trusted embedding host adapts verified callers into separate submit/read/list permissions.
The recipient-bound identity adapter follows Warden ADR 0005 and its unchanged foundation
principal/admission candidates. It verifies signatures and current context on every operation.
This experiment supplies no provider or network authentication, snapshot signature transport
or service endpoint. Its entire host process is trusted. Snapshot replacement is a
host-only operation excluded from intake/read handles; revisions strictly increase, even
after an unavailable interval. Mutable borrowing prevents trust replacement during admission
or reads. Revocation is effective at the next operation after host replacement. Delivery of
current snapshots, the actual authenticated transport peer and a clock with at most two
seconds uncertainty remain host responsibilities; no cross-process revocation bound is qualified.

The host explicitly maps each local operation (submit, resolve, list) to an exact registered
resource. Submit requires signed `propose`; resolve and list require signed `read`, with
separate host permissions for each operation. There is no implied wildcard or tenant-wide
permission from an unrelated resource. Task and target-policy caps must both contain every
chain member's scopes/resources and validity. All chain members name the current recipient;
the leaf service matches the actual peer. Each edge has exactly one current registration
with its child's presenter service, preserved origin, task/policy references and bounds.
The result retains the leaf digest and ordered registration IDs. Humans, bootstrap and
forwarded attribution as caller authority refuse. Gate calls Registry under its separately
registered, Registry-bound service identity. Attribution cannot be exchanged for authority.

Identical-envelope retries recheck current trust and keep their original admission revision.
Different envelopes under the same identity conflict, including re-signing with another key.
Read results report both original admission and current verification revisions. Missing
digests and foreign-tenant digests return the same absence category. Listing rechecks every
candidate in the caller's tenant and fails as a whole on an invalid entry. Capacity is bounded
per tenant by the embedding host. Candidate handles expose no activation implementation.
Read/intake Rust types are local interfaces; this bundle does not introduce an HTTP wire API.

## Capability schema profile

Referenced schema digest is lowercase hexadecimal SHA-256 prefixed with `sha256:`, over
UTF-8 `munarium:capability-schema:v1`, one NUL byte, then exact canonical schema bytes.
The same domain applies to parameter and result schemas. Raw bytes are capped at 65,536.
Every schema is a closed object with root `$schema` equal to the Draft 2020-12 URI.
Nested nodes cannot carry `$schema`. The supported types and required keywords are:

| Type | Required keywords besides `type` |
|---|---|
| `boolean` | none |
| `integer` | `minimum`, `maximum`: safe integers, minimum no greater than maximum |
| `string` | `minLength`, `maxLength`: integer bounds from 0 through 4096 |
| `array` | `items`, `minItems`, `maxItems`: item bounds from 0 through 256 |
| `object` | `properties`, `required`, `additionalProperties: false` |

Object property names use the bounded identifier syntax; at most 32 properties. Required
names must be unique and present in properties. At most eight schema-node levels including
the root, and 256 total nodes. All minimums must not exceed maximums. Reject every unsupported
keyword, including `$ref`, `$defs`, `format`, defaults and extensions. Thus the first profile
contains no reference graph or network resolution. This deliberately narrows ADR-0006's
initial local-reference proposal. Registry validates the schema definition and its bytes;
validating invocation arguments/results against it is a consumer responsibility.

## Reproduction and limits

From the hub root:

```console
python -m unittest discover -s scripts -p "test_*.py"
```

The hub's `scripts/test_registry_candidate.py` verifies signatures
with OpenSSL, compares exact bytes/digests and checks the lock and schema references.
Missing OpenSSL is a failed check. Existing CI discovers these tests without new dependencies.
An optional standards-validator check uses `jsonschema` to validate the two schema documents
and fixture shapes; that package is not required by ordinary hub CI.

The hub's `scripts/generate_registry_candidate.py` uses cryptography to create
a fresh ephemeral test key in memory, never serializes private key material, and refuses to
overwrite an existing locked candidate. It is not run by CI. A subsequent candidate requires
a separate reviewed destination and new digest. These fixtures establish no activation,
durability, real identity verification, qualified connector or release authority.
