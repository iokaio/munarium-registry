# Durable candidate catalog

`Registry::open(path, trust, capacity)` uses SQLite with WAL and FULL synchronous
commits. A candidate acknowledgement follows the committed insert. Exact signed
bytes, tenant/ID/version uniqueness and the original admission revision survive
restart. SQL triggers refuse candidate updates and deletion. A file lock gives
one process custody of each database; concurrent openers fail closed.

Resolution and listing reverify publisher signatures, current publisher status,
classification and schema references. Persisted bytes never establish activation.
The highest observed trust revision is retained to reject an older snapshot after
restart. The caller must still obtain fresh governing authority independently;
restoring the database and its revision floor together cannot establish freshness.
Server's separately retained authority checkpoint supplies that deployment boundary.

The default `sqlite` feature includes persistence. Consumers needing only the
in-memory verifier can disable default features; this avoids native SQLite link
conflicts in the existing in-process composition. The service will use persistence.
Network admission and deployment composition remain separate implementation work.

Run `cargo test --offline --locked --test reg_01` for restart, exact retry, current
revocation, tenant isolation, immutable SQL history, exclusive custody and a blocked
write that returns no acknowledgement. The ordinary candidate/identity suites remain
enabled. Local tests do not establish remote CI or release qualification.

Trust revision digests are persisted atomically with the monotonic revision floor.
Reopening the same revision with different bytes refuses, including after restart.
The additive pin-table upgrade requires a newer operator trust revision when an
older database has a floor but no corresponding digest; it cannot silently bless
substituted bytes for that old revision. Existing candidates remain untouched.
