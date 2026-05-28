#!/usr/bin/env python3
"""Regenerate and encrypt the Agent P0 rule bundle before building or packaging."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import subprocess
import sys
from typing import Optional


def run(cmd: list[str], cwd: pathlib.Path) -> None:
    print("+ " + " ".join(str(x) for x in cmd), flush=True)
    subprocess.run(cmd, cwd=str(cwd), check=True)


def sha256_file(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def is_backend_config_dir(path: pathlib.Path) -> bool:
    return (
        (path / "sync_behavior_rules_bundle.py").is_file()
        and (path / "export_p0_rule_manifest.py").is_file()
    )


def resolve_backend_config(agent_root: pathlib.Path) -> Optional[pathlib.Path]:
    override = os.environ.get("EDR_BACKEND_CONFIG_DIR", "").strip()
    if override:
        candidate = pathlib.Path(override).expanduser().resolve()
        if is_backend_config_dir(candidate):
            return candidate
        print(
            f"[prepare-p0] backend config override is not usable: {candidate}; "
            "falling back to standalone agent artifacts",
            file=sys.stderr,
            flush=True,
        )
        return None

    candidates = (
        agent_root.parent / "edr-backend" / "platform" / "config",
        agent_root / "edr-backend" / "platform" / "config",
    )
    for candidate in candidates:
        if is_backend_config_dir(candidate):
            return candidate
    return None


def json_field(path: pathlib.Path, name: str) -> Optional[str]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    value = data.get(name)
    return str(value) if value is not None else None


def verify_standalone_bundle(plain: pathlib.Path, manifest: pathlib.Path, sensor: pathlib.Path) -> None:
    for required in (plain, manifest, sensor):
        if not required.is_file():
            raise SystemExit(
                "missing standalone P0 release artifact: "
                f"{required} (checkout edr-backend too, or regenerate and commit edr-agent/config artifacts)"
            )

    ir_version = json_field(plain, "rules_bundle_version")
    manifest_version = json_field(manifest, "rules_bundle_version")
    if ir_version and manifest_version and ir_version != manifest_version:
        raise SystemExit(
            "P0 bundle version mismatch: "
            f"{plain.name}={ir_version} {manifest.name}={manifest_version}"
        )


def main() -> int:
    script = pathlib.Path(__file__).resolve()
    agent_root = script.parents[1]
    repo_root = agent_root.parent
    backend_config = resolve_backend_config(agent_root)

    encrypt_script = agent_root / "scripts" / "encrypt_p0_rules.py"
    plain = agent_root / "config" / "p0_rule_bundle_ir_v1.json"
    enc = agent_root / "config" / "p0_rule_bundle_ir_v1.json.enc"
    manifest = agent_root / "config" / "p0_rule_bundle_manifest.json"
    sensor = agent_root / "config" / "sensor_interest_manifest.json"

    for required in (encrypt_script,):
        if not required.is_file():
            raise SystemExit(f"missing required script: {required}")

    backend_enc: Optional[pathlib.Path] = None
    if backend_config is not None:
        sync_script = backend_config / "sync_behavior_rules_bundle.py"
        export_script = backend_config / "export_p0_rule_manifest.py"
        backend_enc = backend_config / "p0_rule_bundle_ir_v1.json.enc"
        run([sys.executable, str(sync_script)], repo_root)
        run([sys.executable, str(export_script)], repo_root)
    else:
        print(
            "[prepare-p0] edr-backend config not found; using checked-in "
            "edr-agent/config P0 artifacts for standalone agent build",
            flush=True,
        )
        verify_standalone_bundle(plain, manifest, sensor)

    if not plain.is_file():
        raise SystemExit(f"missing generated P0 IR JSON: {plain}")

    run([sys.executable, str(encrypt_script), "--input", str(plain), "--output", str(enc)], agent_root)
    if backend_enc is not None:
        backend_enc.write_bytes(enc.read_bytes())

    for required in (plain, enc, sensor):
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
        f"backend_enc={backend_enc or '<standalone-skip>'} sensor={sensor.name}",
        flush=True,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
