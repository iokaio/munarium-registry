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

## Participant audit delivery

The coordinator may POST `flush` to the existing activation route (Gate uses
`/v1/actions`). Each call delivers at most one pending applied receipt. A reader
cannot flush. The response reports `delivered:1` with the exact Server
acknowledgement, or `delivered:0` when no intent remains pending. Retry until zero;
dependency failure or an invalid acknowledgement keeps the oldest event pending.
Expiry of the transition does not invalidate historical delivery authority.
Current Server identity/stream admission still applies to every append.

Add the optional top-level service configuration `delivery` with `server_service`,
`warden_endpoint` (an HTTPS origin), `provider_id` and absolute
`provider_token_file`. The file is operator-supplied and never logged. Warden's
provider enrollment must bind the actual service peer to the Server audience,
`propose` scope and `action-records:<tenant>` resource. Server must enroll this
peer for recording and admit its current identity in `identity:<Server service>`.
No caller assertion or forwarding header supplies the recorder identity.

The current `action-records:<Server service>` binding must register exactly one
stream for this service/producer with only `activation-applied` in `kinds`.
Source generation and stream are pinned by the first materialized event. A changed
registration refuses rather than rewriting pending history or guessing a new
sequence. The stream must be dedicated to this owner database.

Operational receipts and intent remain atomic. Additive delivery tables retain
canonical event bytes before sending, then the exact acknowledgement after closed
schema, event/payload hash, qualified scope and ledger-position validation. The
event timestamp is the first durable delivery observation. A lost response retries
the same event, source sequence and timestamp; concurrent flushes are duplicates,
not new facts. Receipt intent remains retained after acknowledgement. Server must
already hold the Council transition, normally archived by Server's participant
apply. Gate pause/resume history has no invented candidate event type.

This is audit delivery, not execution admission or snapshot reconciliation. Missing
source history and changed generations fail closed. Component restart/negative
acknowledgement tests and Harness's real-service delivery test exercise this path.
No production trust, target effect or recovery qualification is claimed.
