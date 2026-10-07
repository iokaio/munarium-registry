# Registry identity candidate inputs

These seven JSON files are unchanged copies of the public hub at
[`c46f86400732223a6a7c23f5d186250ab4a144eb`](https://github.com/iokaio/munarium-platform/tree/c46f86400732223a6a7c23f5d186250ab4a144eb/docs/decisions/candidates).
They are proposed, unreleased contracts, not current deployment authority.

| Files | Integrity pin |
|---|---|
| [Foundation schema](foundation.schema.json), [signed identity vectors](identity-vectors.json), [record vectors](record-vectors.json) | [Original candidate lock](candidate-lock.json), aggregate `5ee201e48a2390b7cf66fdf6aa8750f751f1ec9241e9e04131b6632745612238` |
| [Admission schema](warden-admission.schema.json), [admission vectors](warden-admission-vectors.json) | [Original admission lock](warden-admission-lock.json), aggregate `9ed4a12563d064e5d2068658b903a8b8813ffe49e8cd66356931af1447080283` |

Both locks normalize CRLF to LF, then hash sorted filename/NUL/file-hash/newline records.
[Tests](../../tests/identity.rs) verify every locked file. Record/admission vectors are
retained to verify the original complete locks; Registry does not implement every record.
No signed vector, expectation or approval history was regenerated.

The receiving-side rules come from the pinned
[identity consumer specification](https://github.com/iokaio/munarium-platform/blob/c46f86400732223a6a7c23f5d186250ab4a144eb/docs/decisions/warden-identity-contract.md)
and [ADR 0005](https://github.com/iokaio/munarium-platform/blob/c46f86400732223a6a7c23f5d186250ab4a144eb/docs/decisions/0005-warden-identity-admission.md).
Registry narrows them to nonhuman decision assertions, a 512-byte header, at most
128 host-provisioned delegation registrations, and explicit host permission/resource
bindings. Read and list remain separate permissions. It refuses forwarded attribution
as identity, bootstrap, human origins and govern/ratify scopes.

The host supplies actual authenticated peer, trusted routing/clock and current admitted
authority; these fixture contexts must never be accepted as request input. Warden's
provider enrollment, grants and credential broker are not dependencies of this library.
