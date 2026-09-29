# Security

Do not file a vulnerability as an issue or a pull request.

Report a suspected vulnerability in anything in this repository privately, by either route:

- GitHub's private vulnerability reporting ("Report a vulnerability" under the Security tab), or
- email to **info@ioka.io** with "security" in the subject.

Say what you found, where, and how to reproduce it. Do not include live credentials, customer data,
or a proof of concept run against a system you do not operate. You will get an acknowledgement
within two business days, and a fix, or a recorded decision, on the affected path before any related
release. Credit is given if you ask for it.

## Supported versions

Munarium Registry has no release. Until the first tagged release, `main` is the only line and a fix
lands there. Once releases exist, security fixes go to the current minor release and to the previous
one for six months after its successor ships; an older release gets a fix only where the
vulnerability is in a contract it still speaks.

A finding in the design is welcome now, through the same private channel if it has security
consequences and as an ordinary issue otherwise. The threat model this component is built against
is in [README.md](README.md) and, for the platform as a whole, in the hub
([iokaio/munarium-platform](https://github.com/iokaio/munarium-platform)).

## What matters most here

As runtime behavior is implemented, these are the classes of finding taken most seriously and most
quickly:

- **An activation that did not carry the required authority.** An agent-originated request, a CI job, or a compromised documentation branch changing the effective manifest pointer is the finding this component exists to prevent.
- **The same identity with different bytes accepted as a replacement** instead of being refused and requiring a new version.
- **A stale expected activation state that overwrites a newer decision** instead of returning a conflict.
- **A retired or revoked manifest still honored** by a consumer's cache beyond the declared freshness and revocation contract.
- **An imported API description that becomes an approved capability** without explicit review.

## What is deliberate, and is not a defect

- **Discovered is not approved, and published is not activated.** A candidate record that does nothing is the design, not a missing feature.
- **Registry is not a live policy database served from GitHub.** A deployed catalog consumes released artifacts through an authenticated installation or promotion path; a GitHub outage cannot change what a deployment enforces.

When a local development profile exists, its test identity provider, test broker, disposable target
and generated sample credentials are development conveniences confined to that profile. They are
not vulnerabilities in themselves. A path by which they reach a production deployment unnoticed is.

## Findings that cross components

A contract ambiguity that lets two components disagree about authority, a canonicalization
difference between clients, or a gap between what a release advertises and what its evidence
supports is still a security finding. Report it here, or to any other Munarium repository, through
the same private channel; it is routed to the hub and the affected repositories together. Do not
open a public issue for it in the hub.

## Secrets

If you have committed a token or key, treat it as compromised: rotate it first, then report it.
