#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise the exact public-fixture exceptions with the real pinned scanner."""
import argparse
import json
from pathlib import Path
import secrets
import string
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gitleaks", type=Path, required=True)
    parser.add_argument("--repository", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--fixture", required=True, help="Repository-relative signed-vector path")
    args = parser.parse_args()
    root = args.repository.resolve()
    relative = Path(args.fixture)
    if relative.is_absolute() or ".." in relative.parts:
        raise SystemExit("Fixture must stay within the repository")
    corpus = json.loads((root / relative).read_text(encoding="utf-8"))
    token = corpus["cases"][0]["envelope"]
    changed = token[:-1] + ("A" if token[-1] != "A" else "B")
    synthetic_pat = "ghp_" + "".join(secrets.choice(string.ascii_letters + string.digits)
                                    for _ in range(36))
    cases = [
        ("exact fixture", relative, json.dumps(corpus), None),
        ("changed token", relative, json.dumps({"envelope": changed}), "jwt"),
        ("different file", Path("other.json"), json.dumps({"envelope": token}), "jwt"),
        ("other credential rule", relative, json.dumps({"credential": synthetic_pat}), "github-pat"),
    ]
    for label, path, contents, expected_rule in cases:
        with tempfile.TemporaryDirectory(prefix="registry-scanner-") as directory:
            work = Path(directory)
            target = work / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(contents, encoding="utf-8")
            report = work / "report.json"
            result = subprocess.run(
                [str(args.gitleaks.resolve()), "dir", str(work), "--config", str(root / ".gitleaks.toml"),
                 "--no-banner", "--redact=100", "--report-format", "json", "--report-path", str(report),
                 "--exit-code", "1"], capture_output=True, text=True, timeout=30, check=False)
            findings = json.loads(report.read_text(encoding="utf-8")) if report.exists() else []
            expected_exit = 1 if expected_rule else 0
            if result.returncode != expected_exit or (
                    expected_rule and not any(f["RuleID"] == expected_rule for f in findings)):
                raise SystemExit(f"{label}: scanner boundary failed (exit {result.returncode})")
            print(f"{label}: expected scanner outcome verified")
    print("Four scanner boundary checks passed; temporary synthetic inputs removed.")


if __name__ == "__main__":
    main()
