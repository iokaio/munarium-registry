# REG-01 build-support changes

The maintainer explicitly authorized these CI repairs and the paired contributor guidance
updates on 6 October 2026. The changes preserve all existing checks and workflow permissions.

| File | Applied change |
|---|---|
| `.github/workflows/rust.yml` | Insert `Fetch locked public dependencies`, running `cargo +1.98.1 fetch --locked`, immediately before the existing offline Build step. Keep all permissions, triggers, pins and checks unchanged. |
| `CONTRIBUTING.md` | Replace the obsolete no-dependencies/no-tests paragraph with the pinned dependency-cache recipe and the distinction between local candidate tests and unavailable integration coverage. |
| `AGENTS.md` and `CLAUDE.md` | Update only Current state and the Rust checks table to describe the experimental candidate library, host trust boundary, pinned dependency fetch and behavioral tests; keep the files identical and all authority/protection rules unchanged. |
| `.gitleaks.toml` in Registry and the companion hub PR | Limit the JWT exception to the exact 31 public fictional signed-manifest values AND their respective signed-vectors.json path. New values, other paths and other rules remain scanned. |

AGENTS.md and CLAUDE.md additionally record this bounded authorization. No runtime service,
publication, activation, operational key/publisher change or broad scanner exclusion is included.

Gitleaks 8.30.1 originally reported 31 compact manifest fixture occurrences (30 distinct
strings, because two cases reuse an envelope) as JWT credentials in
both repositories. These are inert public test artifacts generated using a disposable key,
not principal assertions or deployment credentials. The exception records exact strings;
the deliberately malformed trailing-newline fixture uses its JSON-escaped file spelling.
No fixture bytes, expected results, contract digests or history were rewritten.

Local validation after the repair:

- Gitleaks directory and Git-history scans: exit 0, no findings in both repositories.
- [Scanner boundary checks](../scripts/check_fixture_exceptions.py): four checks per
  repository passed with the real scanner. The original fixtures pass; a changed token,
  a token in another file and a synthetic credential of another type still report.
- Locked dependency fetch followed by formatting, build, lint, all 23 Rust tests and
  documentation: each exit 0.

Reproduce the boundary checks from Registry, using the pinned scanner executable:

```console
python scripts/check_fixture_exceptions.py --gitleaks <gitleaks-executable> --fixture contracts/registry-v2/signed-vectors.json
python scripts/check_fixture_exceptions.py --gitleaks <gitleaks-executable> --repository ../munarium-platform --fixture docs/decisions/registry-v2/signed-vectors.json
```

Use the companion hub PR checkout for the second command. Synthetic inputs live only in
scoped temporary directories and are removed on completion; the probe reports no values.
Hosted results belong to the exact updated PR heads and are recorded in their descriptions.
