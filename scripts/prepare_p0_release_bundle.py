#!/usr/bin/env python3
"""Generate, validate, and transactionally publish the Agent P0 release bundle."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import shutil
import stat
import subprocess
import sys
import tempfile
from typing import Optional


FilePair = tuple[pathlib.Path, pathlib.Path]


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


def verify_bundle(plain: pathlib.Path, manifest: pathlib.Path, sensor: pathlib.Path) -> str:
    for required in (plain, manifest, sensor):
        if not required.is_file():
            raise RuntimeError(
                "missing P0 release artifact: "
                f"{required} (checkout edr-backend too, or regenerate and commit edr-agent/config artifacts)"
            )

    ir_version = json_field(plain, "rules_bundle_version")
    manifest_version = json_field(manifest, "rules_bundle_version")
    if not ir_version or not manifest_version or ir_version != manifest_version:
        raise RuntimeError(
            "P0 bundle version mismatch: "
            f"{plain.name}={ir_version} {manifest.name}={manifest_version}"
        )
    return ir_version


def _copy_file(source: pathlib.Path, target: pathlib.Path) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    with source.open("rb") as reader, target.open("wb") as writer:
        shutil.copyfileobj(reader, writer)


def _require_descendant(path: pathlib.Path, root: pathlib.Path, label: str) -> None:
    try:
        path.resolve().relative_to(root.resolve())
    except ValueError as exc:
        raise RuntimeError(f"{label} escapes its allowed root: {path}") from exc


def _append_pair(
    pairs: list[FilePair],
    staged: pathlib.Path,
    final: pathlib.Path,
    *,
    stage_root: pathlib.Path,
    repo_root: pathlib.Path,
) -> None:
    _require_descendant(staged, stage_root, "staged P0 output")
    _require_descendant(final, repo_root, "P0 publication output")
    if not staged.is_file():
        raise RuntimeError(f"staged P0 output is missing: {staged}")
    if final.exists() and not final.is_file():
        raise RuntimeError(f"P0 publication target is not a regular file: {final}")
    if any(existing_final == final for _, existing_final in pairs):
        raise RuntimeError(f"duplicate P0 publication target: {final}")
    pairs.append((staged, final))


def _same_bytes(source: pathlib.Path, target: pathlib.Path) -> bool:
    return target.is_file() and source.read_bytes() == target.read_bytes()


def _write_sibling_copy(source: pathlib.Path, final: pathlib.Path, purpose: str) -> pathlib.Path:
    if not final.parent.is_dir():
        raise RuntimeError(f"P0 publication target directory does not exist: {final.parent}")
    fd, raw_path = tempfile.mkstemp(prefix=f".{final.name}.{purpose}-", dir=final.parent)
    temporary = pathlib.Path(raw_path)
    try:
        with source.open("rb") as reader, os.fdopen(fd, "wb") as writer:
            shutil.copyfileobj(reader, writer)
            writer.flush()
            os.fsync(writer.fileno())
        mode = stat.S_IMODE(final.stat().st_mode) if final.exists() else 0o644
        os.chmod(temporary, mode)
        return temporary
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def publish_staged_files(pairs: list[FilePair]) -> int:
    """Publish all staged files, restoring every prior target if a rename fails.

    Generation never writes a real artifact.  Only after every generator and
    staged validator succeeds do sibling replacement files enter this commit
    section.  A failed replacement restores prior bytes for already committed
    files, so a failed prepare cannot leave a mixed rule/matrix release.
    """
    changed = [(staged, final) for staged, final in pairs if not _same_bytes(staged, final)]
    if not changed:
        return 0

    replacements: dict[pathlib.Path, pathlib.Path] = {}
    backups: dict[pathlib.Path, pathlib.Path] = {}
    committed: list[pathlib.Path] = []
    try:
        for staged, final in changed:
            replacements[final] = _write_sibling_copy(staged, final, "p0-stage")
            if final.exists():
                backups[final] = _write_sibling_copy(final, final, "p0-backup")

        for _, final in changed:
            os.replace(replacements[final], final)
            committed.append(final)
    except Exception as exc:
        rollback_errors: list[str] = []
        for final in reversed(committed):
            try:
                backup = backups.get(final)
                if backup is None:
                    final.unlink(missing_ok=True)
                else:
                    os.replace(backup, final)
            except Exception as rollback_exc:
                rollback_errors.append(f"{final}: {rollback_exc}")
        if rollback_errors:
            raise RuntimeError(
                "P0 release publication failed and rollback was incomplete: "
                + "; ".join(rollback_errors)
            ) from exc
        raise RuntimeError(f"P0 release publication failed; prior files restored: {exc}") from exc
    finally:
        for path in [*replacements.values(), *backups.values()]:
            try:
                path.unlink(missing_ok=True)
            except OSError:
                # The publication already committed or rolled back.  A stale
                # sibling temp is safe to remove on the next run and must not
                # misreport that durable artifact transaction as failed.
                pass
    return len(changed)


def _load_staged_outputs(path: pathlib.Path) -> list[pathlib.Path]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"read staged compatibility output manifest: {exc}") from exc
    if not isinstance(raw, list) or not raw:
        raise RuntimeError("staged compatibility sync produced no outputs")
    outputs: list[pathlib.Path] = []
    for value in raw:
        if not isinstance(value, str):
            raise RuntimeError(f"invalid staged compatibility output: {value!r}")
        relative = pathlib.Path(value)
        if relative.is_absolute() or ".." in relative.parts or relative == pathlib.Path("."):
            raise RuntimeError(f"invalid staged compatibility output: {value!r}")
        outputs.append(relative)
    return outputs


def _copy_stage_mirror(source: pathlib.Path, target: pathlib.Path) -> None:
    if not source.is_file():
        raise RuntimeError(f"cannot mirror missing staged P0 artifact: {source}")
    _copy_file(source, target)


def prepare_backend_bundle(agent_root: pathlib.Path, backend_config: pathlib.Path) -> tuple[str, str, str, int]:
    repo_root = backend_config.parents[2].resolve()
    expected_agent_root = repo_root / "edr-agent"
    if expected_agent_root.resolve() != agent_root.resolve():
        raise RuntimeError(
            "backend config and prepare script must belong to the same monorepo: "
            f"config={backend_config} agent={agent_root}"
        )

    sync_script = backend_config / "sync_behavior_rules_bundle.py"
    export_script = backend_config / "export_p0_rule_manifest.py"
    matrix_script = repo_root / "edr-backend" / "scripts" / "generate_p0_validation_matrix.py"
    encrypt_script = agent_root / "scripts" / "encrypt_p0_rules.py"
    for required in (sync_script, export_script, matrix_script, encrypt_script):
        if not required.is_file():
            raise RuntimeError(f"missing required P0 release generator: {required}")

    stage_root = pathlib.Path(tempfile.mkdtemp(prefix="edr-p0-release-"))
    try:
        sync_manifest = stage_root / "sync-outputs.json"
        run(
            [
                sys.executable,
                str(sync_script),
                "--stage-root",
                str(stage_root),
                "--outputs-manifest",
                str(sync_manifest),
            ],
            repo_root,
        )
        sync_outputs = _load_staged_outputs(sync_manifest)

        staged_config = stage_root / "edr-backend" / "platform" / "config"
        staged_manifest = staged_config / "p0_rule_bundle_manifest.json"
        staged_ir = staged_config / "p0_rule_bundle_ir_v1.json"
        staged_sensor = staged_config / "sensor_interest_manifest.json"
        run(
            [
                sys.executable,
                str(export_script),
                "--json",
                str(staged_config / "dynamic_rules_v1.json"),
                "--ids",
                str(backend_config / "p0_rule_ids_v1.txt"),
                "--out",
                str(staged_manifest),
                "--ir-out",
                str(staged_ir),
                "--sensor-out",
                str(staged_sensor),
                "--no-agent-mirror",
            ],
            repo_root,
        )

        staged_agent_config = stage_root / "edr-agent" / "config"
        staged_agent_manifest = staged_agent_config / staged_manifest.name
        staged_agent_ir = staged_agent_config / staged_ir.name
        staged_agent_sensor = staged_agent_config / staged_sensor.name
        for source, target in (
            (staged_manifest, staged_agent_manifest),
            (staged_ir, staged_agent_ir),
            (staged_sensor, staged_agent_sensor),
        ):
            _copy_stage_mirror(source, target)

        staged_matrix = stage_root / "edr-backend" / "platform" / "testdata" / "p0_validation_matrix_v1.json"
        staged_matrix_c = stage_root / "edr-agent" / "src" / "preprocess" / "p0_validation_matrix_data.inc"
        matrix_cmd = [
            sys.executable,
            str(matrix_script),
            "--bundle",
            str(staged_ir),
            "--output",
            str(staged_matrix),
            "--c-output",
            str(staged_matrix_c),
        ]
        run(matrix_cmd, repo_root)
        run([*matrix_cmd, "--check"], repo_root)

        staged_agent_enc = staged_agent_config / "p0_rule_bundle_ir_v1.json.enc"
        run(
            [sys.executable, str(encrypt_script), "--input", str(staged_agent_ir), "--output", str(staged_agent_enc)],
            agent_root,
        )
        staged_platform_enc = staged_config / "p0_rule_bundle_ir_v1.json.enc"
        _copy_stage_mirror(staged_agent_enc, staged_platform_enc)

        version = verify_bundle(staged_agent_ir, staged_agent_manifest, staged_agent_sensor)
        for platform_artifact, agent_artifact in (
            (staged_manifest, staged_agent_manifest),
            (staged_ir, staged_agent_ir),
            (staged_sensor, staged_agent_sensor),
        ):
            if platform_artifact.read_bytes() != agent_artifact.read_bytes():
                raise RuntimeError(f"staged Agent mirror differs from platform artifact: {platform_artifact.name}")

        pairs: list[FilePair] = []
        for relative in sync_outputs:
            _append_pair(
                pairs,
                stage_root / relative,
                repo_root / relative,
                stage_root=stage_root,
                repo_root=repo_root,
            )
        for relative in (
            pathlib.Path("edr-backend/platform/config/p0_rule_bundle_manifest.json"),
            pathlib.Path("edr-backend/platform/config/p0_rule_bundle_ir_v1.json"),
            pathlib.Path("edr-backend/platform/config/sensor_interest_manifest.json"),
            pathlib.Path("edr-agent/config/p0_rule_bundle_manifest.json"),
            pathlib.Path("edr-agent/config/p0_rule_bundle_ir_v1.json"),
            pathlib.Path("edr-agent/config/sensor_interest_manifest.json"),
            pathlib.Path("edr-backend/platform/testdata/p0_validation_matrix_v1.json"),
            pathlib.Path("edr-agent/src/preprocess/p0_validation_matrix_data.inc"),
            pathlib.Path("edr-agent/config/p0_rule_bundle_ir_v1.json.enc"),
            pathlib.Path("edr-backend/platform/config/p0_rule_bundle_ir_v1.json.enc"),
        ):
            _append_pair(
                pairs,
                stage_root / relative,
                repo_root / relative,
                stage_root=stage_root,
                repo_root=repo_root,
            )

        published = publish_staged_files(pairs)
        return version, sha256_file(staged_agent_ir), sha256_file(staged_agent_enc), published
    finally:
        shutil.rmtree(stage_root, ignore_errors=True)


def prepare_standalone_bundle(agent_root: pathlib.Path) -> tuple[str, str, str, int]:
    encrypt_script = agent_root / "scripts" / "encrypt_p0_rules.py"
    plain = agent_root / "config" / "p0_rule_bundle_ir_v1.json"
    enc = agent_root / "config" / "p0_rule_bundle_ir_v1.json.enc"
    manifest = agent_root / "config" / "p0_rule_bundle_manifest.json"
    sensor = agent_root / "config" / "sensor_interest_manifest.json"
    if not encrypt_script.is_file():
        raise RuntimeError(f"missing required script: {encrypt_script}")
    version = verify_bundle(plain, manifest, sensor)

    stage_root = pathlib.Path(tempfile.mkdtemp(prefix="edr-p0-release-"))
    try:
        staged_enc = stage_root / enc.name
        run([sys.executable, str(encrypt_script), "--input", str(plain), "--output", str(staged_enc)], agent_root)
        published = publish_staged_files([(staged_enc, enc)])
        return version, sha256_file(plain), sha256_file(staged_enc), published
    finally:
        shutil.rmtree(stage_root, ignore_errors=True)


def main() -> int:
    script = pathlib.Path(__file__).resolve()
    agent_root = script.parents[1]
    backend_config = resolve_backend_config(agent_root)

    try:
        if backend_config is None:
            print(
                "[prepare-p0] edr-backend config not found; using checked-in "
                "edr-agent/config P0 artifacts for standalone agent build",
                flush=True,
            )
            version, plain_sha, enc_sha, published = prepare_standalone_bundle(agent_root)
            backend_enc = "<standalone-skip>"
            matrix = "<standalone-skip>"
        else:
            version, plain_sha, enc_sha, published = prepare_backend_bundle(agent_root, backend_config)
            backend_enc = str(backend_config / "p0_rule_bundle_ir_v1.json.enc")
            matrix = str(agent_root.parent / "edr-backend/platform/testdata/p0_validation_matrix_v1.json")
    except (RuntimeError, subprocess.CalledProcessError) as exc:
        print(f"P0 release bundle preparation failed: {exc}", file=sys.stderr)
        return 1

    plain = agent_root / "config" / "p0_rule_bundle_ir_v1.json"
    enc = agent_root / "config" / "p0_rule_bundle_ir_v1.json.enc"
    print(
        "P0 release bundle ready: "
        f"version={version} plain_size={plain.stat().st_size} plain_sha256={plain_sha} "
        f"enc_size={enc.stat().st_size} enc_sha256={enc_sha} "
        f"published_files={published} backend_enc={backend_enc} matrix={matrix}",
        flush=True,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
