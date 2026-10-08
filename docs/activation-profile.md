# Experimental Stage 2 activation

The [activation store](../src/activation_store.rs) adds independently authorized
artifact-set application beside the unchanged inert candidate service. It consumes
the [Stage 2 candidate](../contracts/stage2-v1/README.md), bundle
`8aca66588c87107a0c7a7720c68f921dfd2bdcaecf6433728afa4b1c51420aa6`.
The hub's ADR 0014 records the shared experimental boundary. Acceptance, release
and full effect qualification remain pending.

## Service admission

Existing Stage 1 configuration and `/v1/candidates` remain supported. Optional
`council_endpoint` and `gate_endpoint` enable the new `/v1/activation` adapter
when the current Server governing artifact supplies `stage2:<registry-service>`.
The binding names qualified `scope`, enrolled `coordinator`, permitted `readers`,
`initial_epoch`, `initial_artifact_set_digest` and admitted `artifacts`.
An artifact binding contains `kind`, `digest`, compatible `profile`, explicit
`retired` status and optional policy bytes in `policy`.

Manifest activation resolves an actual admitted signed candidate under current
Registry trust. Policy activation hashes the policy bytes independently supplied
by the current signed Server governing artifact. Submitted JSON cannot create its
own compatibility or retirement authority. Gate separately validates and executes
the policy's pinned evaluator profile before any action permission.

The closed request is `{tenant, action}`. Operations are `apply` with a canonical
transition string, `lookup` with `transition_id`, and `head`. Apply requires the
currently enrolled Council peer, exact authenticated Council ratification lookup
and Gate pause lookup. Every receipt binds the complete transition, participant
set, artifact set and prior/successor epochs. Missing required endpoints or
bindings refuse; candidate intake never acquires activation authority.

## Durable state and recovery

Each tenant has a separate activation SQLite file beside its existing candidate
file. WAL/FULL synchronous transactions atomically update the expected head and
retain the transition, original receipt and local outbox. Concurrent transitions
cannot both consume the same prior head. Retry returns the same receipt; lookup
never reactivates or resumes admission. Explicit retirement is retained separately
from supersession, so replacing an artifact does not itself prohibit a later
governed rollback. A retired artifact cannot be silently made eligible by removing
a flag from a later binding.

`head` reports Registry's participant state with `cell_resumed: false`. Complete
cell activation additionally requires Council's matching Gate, Server and Warden
receipts and Gate's conditional resume. The retained local transition outbox is
not a Server acknowledgement; full audit delivery is a composition obligation.

The initial head is operator-enrolled. Reopening cannot replace it with a caller's
prior state. Snapshot restore is unqualified without the complete action-cell
quarantine and reconciliation process; a successful local database open proves
neither current authority nor safe dispatch.

## Validation

Run the existing [validation commands](validation.md). The
[activation tests](../tests/activation.rs) exercise exact candidate receipts,
restart/outbox survival, expected-head races, current authority/compatibility,
pause binding and tenant refusal. Existing signed candidate and identity suites
remain enabled. The service adapter requires actual multi-service composition
tests before the complete barrier is qualified.
