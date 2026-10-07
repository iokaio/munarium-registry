# Stage 1 candidate service

Build `cargo build --locked` and run `munarium-registry ABSOLUTE_CONFIG_PATH`.
The closed JSON configuration contains `tls`, `server_endpoint`, `deployment`,
the recipient `service`, an existing absolute `database_directory`, and `capacity`
(1–100000 candidates per tenant). SQLite custody is exclusive per tenant file;
candidate bytes and admission revisions survive restart. Keep these files outside
the source checkout and retain them with their lock files when backing up custody.

`tls` contains `listen`, PEM `certificate_file`, `private_key_file`, `ca_file` and
`peers`, mapping lowercase SHA-256 client leaf fingerprints to `{service, tenants}`.
Registry fetches Server's fenced authority with its own certificate on each call.
It selects current `registry` publisher/schema inventory and
`identity:<service>` Warden policy from that operator-admitted artifact.

`POST /v1/candidates` accepts `{tenant, chain, action}`. Actions are:

- `{operation: "submit", envelope}` for the exact signed manifest JWS;
- `{operation: "resolve", manifest_digest, artifact_digest}` (artifact digest optional);
- `{operation: "list"}` for the authenticated tenant's readable candidates.

Submission requires `propose` on `registry:<tenant>`; reads require `read`.
Each receiving hop checks the original signature, actual certificate presenter,
tenant, recipient and current restrictions. Responses retain exact envelope bytes,
digests and admission/verification revisions, with `status: "candidate"` and
`active: false`. Re-reading a durable candidate checks current publisher trust.
Neither submission nor resolution activates a manifest. Dependency outage is 503;
identity or candidate refusal is a sanitized 403. Bodies are limited to 128 KiB.

The [durability guide](durable-catalog.md) and
[Harness service tests](https://github.com/iokaio/munarium-harness/blob/main/docs/service-profile.md)
cover restart, exact retry, malformed signatures, tenant isolation and loss of current
authority. Warden's shared verifier and transport are exported through its publisher
scripts into `vendor/`, with original licenses and source locks. Do not hand-edit them.
Formal contract acceptance and production qualification remain pending.
