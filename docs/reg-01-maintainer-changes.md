# REG-01 maintainer-controlled changes

Pending specific authorization under AGENTS.md's protected-file boundary.
The implementation and contract are already prepared; these changes complete integration.

| File | Exact intended change |
|---|---|
| `.github/workflows/rust.yml` | Insert `Fetch locked public dependencies`, running `cargo +1.98.1 fetch --locked`, immediately before the existing offline Build step. Keep all permissions, triggers, pins and checks unchanged. |
| `CONTRIBUTING.md` | Replace the obsolete no-dependencies/no-tests paragraph with the pinned dependency-cache recipe and the distinction between local candidate tests and unavailable integration coverage. |
| `AGENTS.md` and `CLAUDE.md` | Update only Current state and the Rust checks table to describe the experimental candidate library, host trust boundary, pinned dependency fetch and behavioral tests; keep the files identical and all authority/protection rules unchanged. |

No runtime service, package publication, activation, key/publisher change or check bypass is included.
