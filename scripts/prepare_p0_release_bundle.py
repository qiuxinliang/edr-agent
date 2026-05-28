#!/usr/bin/env python3
"""Regenerate and encrypt the Agent P0 rule bundle before building or packaging."""

from __future__ import annotations

import hashlib
import pathlib
import subprocess
import sys


def run(cmd: list[str], cwd: pathlib.Path) -> None:
    print("+ " + " ".join(str(x) for x in cmd), flush=True)
    subprocess.run(cmd, cwd=str(cwd), check=True)


def sha256_file(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    script = pathlib.Path(__file__).resolve()
    agent_root = script.parents[1]
    repo_root = agent_root.parent
    backend_config = repo_root / "edr-backend" / "platform" / "config"

    sync_script = backend_config / "sync_behavior_rules_bundle.py"
    export_script = backend_config / "export_p0_rule_manifest.py"
    encrypt_script = agent_root / "scripts" / "encrypt_p0_rules.py"
    plain = agent_root / "config" / "p0_rule_bundle_ir_v1.json"
    enc = agent_root / "config" / "p0_rule_bundle_ir_v1.json.enc"
    backend_enc = backend_config / "p0_rule_bundle_ir_v1.json.enc"
    sensor = agent_root / "config" / "sensor_interest_manifest.json"

    for required in (sync_script, export_script, encrypt_script):
        if not required.is_file():
            raise SystemExit(f"missing required script: {required}")

    run([sys.executable, str(sync_script)], repo_root)
    run([sys.executable, str(export_script)], repo_root)
    if not plain.is_file():
        raise SystemExit(f"missing generated P0 IR JSON: {plain}")

    run([sys.executable, str(encrypt_script), "--input", str(plain), "--output", str(enc)], agent_root)
    backend_enc.write_bytes(enc.read_bytes())

    for required in (plain, enc, backend_enc, sensor):
        if not required.is_file():
            raise SystemExit(f"missing generated release artifact: {required}")

    plain_size = plain.stat().st_size
    enc_size = enc.stat().st_size
    plain_sha = sha256_file(plain)
    enc_sha = sha256_file(enc)
    print(
        "P0 release bundle ready: "
        f"plain_size={plain_size} plain_sha256={plain_sha} "
        f"enc_size={enc_size} enc_sha256={enc_sha} "
        f"backend_enc={backend_enc} sensor={sensor.name}",
        flush=True,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
