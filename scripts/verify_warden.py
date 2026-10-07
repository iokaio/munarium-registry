#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Compile a bounded identity interoperability probe against an exact Warden commit."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import tomllib

WARDEN = "e89367ca2ce613760d43ef3ef9139980b41c4dd2"
ROOT = Path(__file__).resolve().parents[1]


def run(command, **kwargs):
    print("+ " + " ".join(map(str, command)), flush=True)
    subprocess.run(command, check=True, **kwargs)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--warden", type=Path, required=True, help="Public Warden Git checkout")
    parser.add_argument("--fetch", action="store_true", help="Fetch missing locked public crates")
    args = parser.parse_args()
    checkout = args.warden.resolve()
    git = ["git", "-C", str(checkout), "-c", f"safe.directory={checkout.as_posix()}"]
    remote = subprocess.check_output(git + ["remote", "get-url", "origin"], text=True).strip()
    if remote not in ("https://github.com/iokaio/munarium-warden.git",
                      "git@github.com:iokaio/munarium-warden.git"):
        raise SystemExit("Expected the public iokaio/munarium-warden checkout")
    archive = subprocess.check_output(git + ["archive", "--format=tar", WARDEN])
    with tempfile.TemporaryDirectory(prefix="registry-warden-") as directory:
        work = Path(directory)
        source = work / "warden"
        source.mkdir()
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as tar:
            tar.extractall(source, filter="data")
        probe = work / "probe"
        (probe / "src").mkdir(parents=True)
        manifest = (
            '[package]\nname="registry-warden-probe"\nversion="0.0.0"\nedition="2024"\n'
            'publish=false\n[dependencies]\n'
            f'munarium-registry={{path={json.dumps(ROOT.as_posix())}}}\n'
            f'munarium-warden={{path={json.dumps(source.as_posix())}}}\n'
            'serde_json="=1.0.149"\nbase64="=0.22.1"\n'
        )
        (probe / "Cargo.toml").write_text(manifest, encoding="utf-8")
        shutil.copyfile(source / "Cargo.lock", probe / "Cargo.lock")
        shutil.copyfile(ROOT / "tests" / "interop" / "warden.rs", probe / "src" / "main.rs")
        env = dict(os.environ)
        env["REGISTRY_IDENTITY_VECTORS"] = str(ROOT / "contracts/identity-v1/identity-vectors.json")
        env["CARGO_TARGET_DIR"] = str(ROOT / "target/warden-interop")
        env["CARGO_NET_RETRY"] = "0"
        env["CARGO_HTTP_TIMEOUT"] = "30"
        if args.fetch:
            run(["cargo", "fetch", "--locked"], cwd=source, env=env)
        # Only add the probe and local Registry root to Warden's pinned lock.
        run(["cargo", "update", "--offline", "--workspace"], cwd=probe, env=env)
        def external_packages(lock):
            data = tomllib.loads(lock.read_text(encoding="utf-8"))
            return {(p["name"], p["version"], p["source"], p.get("checksum"))
                    for p in data["package"] if "source" in p}
        if not external_packages(probe / "Cargo.lock") <= external_packages(source / "Cargo.lock"):
            raise SystemExit("Probe attempted to change Warden's pinned dependency versions")
        print(f"Warden revision: {WARDEN}", flush=True)
        print("Probe lock SHA-256: " + hashlib.sha256((probe / "Cargo.lock").read_bytes()).hexdigest(),
              flush=True)
        run(["cargo", "run", "--offline", "--locked"], cwd=probe, env=env)
    print("Removed only the temporary probe checkout; reusable Cargo output remains in target/.")


if __name__ == "__main__":
    main()
