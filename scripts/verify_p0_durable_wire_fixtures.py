#!/usr/bin/env python3
"""Verify or regenerate Go P0 durable-wire fixtures from the Agent.

The backend consumes BAT1 frames produced by the compiled Agent test emitter;
it must never grow a hand-written look-alike frame. This is the single writer
for the two versioned fixtures. ``--regenerate`` first proves the Agent emits
the same result twice, preserves the fixed semantic fixture identities, then
performs a staged-pair replacement with rollback on an ordinary replacement
failure. A filesystem cannot make two independent names crash-atomic; the
normal freshness gate detects any interrupted pair and refuses to pass it.
"""

from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
from typing import Any


AGENT_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = AGENT_ROOT.parent
DEFAULT_P0_IR = AGENT_ROOT / "config" / "p0_rule_bundle_ir_v1.json"
DEFAULT_SOURCE_FIXTURE = (
    REPO_ROOT / "edr-backend" / "platform" / "internal" / "handler" /
    "testdata" / "p0_source_only_durable_wire_golden.json"
)
DEFAULT_TERMINAL_FIXTURE = (
    REPO_ROOT / "edr-backend" / "platform" / "internal" / "handler" /
    "testdata" / "enforcement_terminal_authority_durable_wire_golden.json"
)

FIXTURE_GENERATOR_KEY = "fixture_generator"
FIXTURE_GENERATOR_COMMAND = (
    "python3 edr-agent/scripts/verify_p0_durable_wire_fixtures.py "
    "--emitter <compiled-test_p0_source_only_durable_contract> --regenerate"
)
SOURCE_FIXTURE_CASE_COUNT = 18
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

# This is an intentionally narrow, reviewed transition in the terminal
# source-only reason catalog.  It is not a general bypass for semantic fixture
# drift: source semantics and the terminal authority identity must remain
# byte-for-byte equivalent under their own manifests, and only this complete
# terminal manifest hash pair may be regenerated.
APPROVED_TERMINAL_SEMANTIC_TRANSITION = {
    "reason": "append source_fields_truncated",
    "source_semantic_manifest_sha256": "a9617757fba9229275eff0649609ebff92cde64705fc1f3fb602b7d8f8198ca1",
    "terminal_before_sha256": "209edf89d42ac7c5ec1c1f7ec8fde19f148b30948024e234a835491295c66c6c",
    "terminal_after_sha256": "64803237e7d13f29ea9c99d617f170a6f7fa71cbab9003ba19c869a39f5098dc",
    "terminal_authority_identity_sha256": "6313248207c7861b900a3071dad4850b5e63edc33fe0d5d3e4a20e7f2447f526",
}


class FixtureError(RuntimeError):
    pass


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise FixtureError(f"read fixture {path}: {exc}") from exc


def normalized_json(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256_file(path: Path, *, label: str) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as exc:
        raise FixtureError(f"read {label} {path}: {exc}") from exc


def require_string(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise FixtureError(f"{label} must be a non-empty string")
    return value


def require_object(value: Any, *, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise FixtureError(f"{label} must be an object")
    return value


def validate_base64(value: Any, *, label: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise FixtureError(f"{label} lacks a non-empty BAT1 base64 value")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as exc:
        raise FixtureError(f"{label} has invalid BAT1 base64") from exc
    if len(decoded) < 4 or decoded[:4] != b"BAT1":
        raise FixtureError(f"{label} is not a BAT1 payload")
    return decoded


def require_batch_id(value: Any, payload: bytes, *, prefix: str, label: str) -> None:
    expected = prefix + hashlib.sha256(payload).hexdigest()
    if value != expected:
        raise FixtureError(f"{label}.batch_id={value!r} want={expected!r}")


def validate_fixture_generator(value: dict[str, Any], *, label: str,
                               expected_rules_version: str | None = None,
                               expected_rules_sha256: str | None = None,
                               expected_source_semantic_sha256: str | None = None,
                               expected_terminal_semantic_sha256: str | None = None,
                               expected_terminal_authority_identity_sha256: str | None = None) -> None:
    generator = require_object(value.get(FIXTURE_GENERATOR_KEY), label=f"{label}.{FIXTURE_GENERATOR_KEY}")
    if generator.get("command") != FIXTURE_GENERATOR_COMMAND:
        raise FixtureError(f"{label}.{FIXTURE_GENERATOR_KEY}.command is not the sole regeneration command")
    if value.get("reproduce_with") != FIXTURE_GENERATOR_COMMAND:
        raise FixtureError(f"{label}.reproduce_with does not name the sole regeneration command")
    for key in (
        "generator_binary_sha256", "p0_ir_sha256", "rules_bundle_sha256",
        "source_semantic_manifest_sha256", "terminal_semantic_manifest_sha256",
        "terminal_authority_identity_sha256",
    ):
        digest = require_string(generator.get(key), label=f"{label}.{FIXTURE_GENERATOR_KEY}.{key}")
        if not SHA256_RE.fullmatch(digest):
            raise FixtureError(f"{label}.{FIXTURE_GENERATOR_KEY}.{key} is not a lowercase SHA-256")
    version = require_string(generator.get("rules_bundle_version"),
                             label=f"{label}.{FIXTURE_GENERATOR_KEY}.rules_bundle_version")
    if generator["p0_ir_sha256"] != generator["rules_bundle_sha256"]:
        raise FixtureError(f"{label}.{FIXTURE_GENERATOR_KEY} IR hash does not bind the rules artifact")
    if expected_rules_version is not None and version != expected_rules_version:
        raise FixtureError(f"{label}.{FIXTURE_GENERATOR_KEY} rules version does not match Agent emission")
    if expected_rules_sha256 is not None and generator["rules_bundle_sha256"] != expected_rules_sha256:
        raise FixtureError(f"{label}.{FIXTURE_GENERATOR_KEY} rules hash does not match Agent emission")
    if (expected_source_semantic_sha256 is not None and
            generator["source_semantic_manifest_sha256"] != expected_source_semantic_sha256):
        raise FixtureError(
            f"{label}.{FIXTURE_GENERATOR_KEY} source semantic manifest does not match the fixture"
        )
    if (expected_terminal_semantic_sha256 is not None and
            generator["terminal_semantic_manifest_sha256"] != expected_terminal_semantic_sha256):
        raise FixtureError(
            f"{label}.{FIXTURE_GENERATOR_KEY} terminal semantic manifest does not match the fixture"
        )
    if (expected_terminal_authority_identity_sha256 is not None and
            generator["terminal_authority_identity_sha256"] !=
            expected_terminal_authority_identity_sha256):
        raise FixtureError(
            f"{label}.{FIXTURE_GENERATOR_KEY} terminal authority identity does not match the fixture"
        )


def source_rule_binding(value: dict[str, Any], *, label: str) -> tuple[str, str]:
    bindings = {
        (
            require_string(item.get("rules_bundle_version"),
                           label=f"{label}.fixtures[{index}].rules_bundle_version"),
            require_string(item.get("rules_bundle_sha256"),
                           label=f"{label}.fixtures[{index}].rules_bundle_sha256"),
        )
        for index, item in enumerate(value["fixtures"])
        if item.get("stage") == "direct"
    }
    if len(bindings) != 1:
        raise FixtureError(f"{label} must contain exactly one direct rules binding, got {sorted(bindings)!r}")
    return next(iter(bindings))


def terminal_rule_binding(value: dict[str, Any], *, label: str) -> tuple[str, str]:
    authority = require_object(value.get("authority"), label=f"{label}.authority")
    return (
        require_string(authority.get("rules_bundle_version"), label=f"{label}.authority.rules_bundle_version"),
        require_string(authority.get("rules_bundle_sha256"), label=f"{label}.authority.rules_bundle_sha256"),
    )


def validate_source_fixture(value: Any, *, label: str, require_generator: bool) -> dict[str, Any]:
    fixture = require_object(value, label=label)
    if fixture.get("fixture_version") != 1:
        raise FixtureError(f"{label} is not fixture version 1")
    fixtures = fixture.get("fixtures")
    if not isinstance(fixtures, list) or len(fixtures) != SOURCE_FIXTURE_CASE_COUNT:
        raise FixtureError(f"{label} must contain exactly {SOURCE_FIXTURE_CASE_COUNT} emitted source-only frames")
    semantic_ids: set[tuple[str, str, str]] = set()
    for index, item_value in enumerate(fixtures):
        item = require_object(item_value, label=f"{label}.fixtures[{index}]")
        stage = require_string(item.get("stage"), label=f"{label}.fixtures[{index}].stage")
        event_type = require_string(item.get("event_type"), label=f"{label}.fixtures[{index}].event_type")
        event_id = require_string(item.get("event_id"), label=f"{label}.fixtures[{index}].event_id")
        require_string(item.get("reason"), label=f"{label}.fixtures[{index}].reason")
        semantic_id = (stage, event_type, event_id)
        if semantic_id in semantic_ids:
            raise FixtureError(f"{label} has duplicate semantic fixture ID {semantic_id!r}")
        semantic_ids.add(semantic_id)
        payload = validate_base64(item.get("bat1_base64"), label=f"{label}.fixtures[{index}]")
        require_batch_id(item.get("batch_id"), payload, prefix="p0-source-", label=f"{label}.fixtures[{index}]")
    rules_version, rules_sha256 = source_rule_binding(fixture, label=label)
    if require_generator:
        validate_fixture_generator(
            fixture,
            label=label,
            expected_rules_version=rules_version,
            expected_rules_sha256=rules_sha256,
            expected_source_semantic_sha256=source_semantic_manifest_sha256(fixture),
        )
    return fixture


def validate_terminal_fixture(value: Any, *, label: str, require_generator: bool) -> dict[str, Any]:
    fixture = require_object(value, label=label)
    if fixture.get("fixture_version") != 1:
        raise FixtureError(f"{label} is not fixture version 1")
    outer = require_object(fixture.get("outer"), label=f"{label}.outer")
    for key in ("tenant_id", "endpoint_id", "event_id", "raw_exe_path", "canonical_image_path"):
        require_string(outer.get(key), label=f"{label}.outer.{key}")
    if not isinstance(outer.get("pid"), int) or outer["pid"] < 0:
        raise FixtureError(f"{label}.outer.pid must be a non-negative integer")
    authority = require_object(fixture.get("authority"), label=f"{label}.authority")
    for key in ("terminal_key", "rule_id", "source_event_key", "source_event_id", "planned_action"):
        require_string(authority.get(key), label=f"{label}.authority.{key}")
    if authority.get("process_pid") != outer["pid"]:
        raise FixtureError(f"{label}.authority.process_pid does not bind outer.pid")
    for key, prefix in (
        ("intent", "p0-enforcement-intent-"),
        ("result", "p0-enforcement-source-"),
        ("combined", "p0-enforcement-combined-"),
    ):
        payload = validate_base64(fixture.get(f"{key}_bat1_base64"), label=f"{label}.{key}_bat1_base64")
        require_batch_id(fixture.get(f"{key}_batch_id"), payload, prefix=prefix, label=f"{label}.{key}")
    rules_version, rules_sha256 = terminal_rule_binding(fixture, label=label)
    if require_generator:
        validate_fixture_generator(
            fixture,
            label=label,
            expected_rules_version=rules_version,
            expected_rules_sha256=rules_sha256,
            expected_terminal_semantic_sha256=terminal_semantic_manifest_sha256(fixture),
            expected_terminal_authority_identity_sha256=terminal_authority_identity_sha256(fixture),
        )
    return fixture


def validate_fixture_pair_provenance(source_fixture: dict[str, Any],
                                     terminal_fixture: dict[str, Any]) -> None:
    source_generator = require_object(
        source_fixture.get(FIXTURE_GENERATOR_KEY), label=f"source fixture.{FIXTURE_GENERATOR_KEY}"
    )
    terminal_generator = require_object(
        terminal_fixture.get(FIXTURE_GENERATOR_KEY), label=f"terminal fixture.{FIXTURE_GENERATOR_KEY}"
    )
    for key in (
        "source_semantic_manifest_sha256",
        "terminal_semantic_manifest_sha256",
        "terminal_authority_identity_sha256",
    ):
        if source_generator.get(key) != terminal_generator.get(key):
            raise FixtureError(f"fixture generator provenance disagrees on {key}")
    if source_generator["source_semantic_manifest_sha256"] != source_semantic_manifest_sha256(source_fixture):
        raise FixtureError("fixture generator source semantic manifest does not bind the source fixture")
    if terminal_generator["terminal_semantic_manifest_sha256"] != terminal_semantic_manifest_sha256(terminal_fixture):
        raise FixtureError("fixture generator terminal semantic manifest does not bind the terminal fixture")
    if (terminal_generator["terminal_authority_identity_sha256"] !=
            terminal_authority_identity_sha256(terminal_fixture)):
        raise FixtureError("fixture generator terminal authority identity does not bind the terminal fixture")


def source_semantic_ids(value: dict[str, Any]) -> tuple[tuple[Any, ...], ...]:
    return tuple(
        (
            item.get("stage"), item.get("event_type"), item.get("event_id"), item.get("reason"),
            item.get("rule_id", ""), item.get("gate_id", ""), item.get("loss_detected"),
        )
        for item in value["fixtures"]
    )


def terminal_semantic_ids(value: dict[str, Any]) -> tuple[Any, ...]:
    outer = value["outer"]
    authority = value["authority"]
    process = require_object(authority.get("process"), label="terminal fixture authority.process")
    expectations = require_object(value.get("combined_expectations"),
                                  label="terminal fixture combined_expectations")
    return (
        outer["tenant_id"], outer["endpoint_id"], outer["event_id"], outer["pid"],
        outer["raw_exe_path"], outer["canonical_image_path"],
        authority["terminal_key"], authority["rule_id"], authority["source_event_key"],
        authority["source_event_id"], authority["process_pid"], authority["planned_action"],
        process.get("generation_key"), process.get("creation_filetime_100ns"),
        process.get("canonical_image_path"), process.get("file_identity"),
        process.get("file_identity_available"),
        expectations.get("outer_exe_path"), expectations.get("alert_process_path"),
        expectations.get("subject_process_path"),
        tuple(value.get("not_evaluable_reasons", [])),
    )


def semantic_manifest_sha256(value: object) -> str:
    return hashlib.sha256(normalized_json(value)).hexdigest()


def source_semantic_manifest_sha256(value: dict[str, Any]) -> str:
    return semantic_manifest_sha256(source_semantic_ids(value))


def terminal_semantic_manifest_sha256(value: dict[str, Any]) -> str:
    return semantic_manifest_sha256(terminal_semantic_ids(value))


def terminal_authority_identity_sha256(value: dict[str, Any]) -> str:
    # `not_evaluable_reasons` is the only separately approved catalog field;
    # all authority, key, process, path, generation, and file-ID identity must
    # remain stable for the approved transition to apply.
    return semantic_manifest_sha256(terminal_semantic_ids(value)[:-1])


def require_same_semantic_ids(emitted_source: dict[str, Any], source_fixture: dict[str, Any],
                              emitted_terminal: dict[str, Any], terminal_fixture: dict[str, Any], *,
                              allow_approved_transition: bool = False) -> str | None:
    source_before = source_semantic_manifest_sha256(source_fixture)
    source_after = source_semantic_manifest_sha256(emitted_source)
    terminal_before = terminal_semantic_manifest_sha256(terminal_fixture)
    terminal_after = terminal_semantic_manifest_sha256(emitted_terminal)
    if source_before == source_after and terminal_before == terminal_after:
        return None
    approval = APPROVED_TERMINAL_SEMANTIC_TRANSITION
    if (allow_approved_transition and
            source_before == approval["source_semantic_manifest_sha256"] and
            source_after == approval["source_semantic_manifest_sha256"] and
            terminal_before == approval["terminal_before_sha256"] and
            terminal_after == approval["terminal_after_sha256"] and
            terminal_authority_identity_sha256(terminal_fixture) ==
            approval["terminal_authority_identity_sha256"] and
            terminal_authority_identity_sha256(emitted_terminal) ==
            approval["terminal_authority_identity_sha256"]):
        return approval["reason"]
    if source_before != source_after:
        raise FixtureError(
            "Agent source fixture semantic IDs changed; update the C contract intentionally before regeneration"
        )
    raise FixtureError(
        "Agent terminal fixture semantic IDs changed; update the C contract intentionally before regeneration"
    )


def load_ir_binding(p0_ir: Path) -> tuple[str, str]:
    try:
        raw = p0_ir.read_bytes()
        parsed = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FixtureError(f"read published P0 IR {p0_ir}: {exc}") from exc
    record = require_object(parsed, label="published P0 IR")
    return require_string(record.get("rules_bundle_version"), label="published P0 IR.rules_bundle_version"), hashlib.sha256(raw).hexdigest()


def fixture_generator_provenance(emitter: Path, p0_ir: Path,
                                 source_fixture: dict[str, Any],
                                 terminal_fixture: dict[str, Any]) -> dict[str, str]:
    rules_version, rules_sha256 = load_ir_binding(p0_ir)
    source_binding = source_rule_binding(source_fixture, label="emitted source fixture")
    terminal_binding = terminal_rule_binding(terminal_fixture, label="emitted terminal fixture")
    if source_binding != (rules_version, rules_sha256):
        raise FixtureError("emitted source fixture rules binding does not match the published P0 IR")
    if terminal_binding != (rules_version, rules_sha256):
        raise FixtureError("emitted terminal fixture rules binding does not match the published P0 IR")
    return {
        "command": FIXTURE_GENERATOR_COMMAND,
        "generator_binary_sha256": sha256_file(emitter, label="Agent fixture emitter"),
        "p0_ir_sha256": rules_sha256,
        "rules_bundle_version": rules_version,
        "rules_bundle_sha256": rules_sha256,
        "source_semantic_manifest_sha256": source_semantic_manifest_sha256(source_fixture),
        "terminal_semantic_manifest_sha256": terminal_semantic_manifest_sha256(terminal_fixture),
        "terminal_authority_identity_sha256": terminal_authority_identity_sha256(terminal_fixture),
    }


def with_generator_provenance(value: dict[str, Any], provenance: dict[str, str]) -> dict[str, Any]:
    result = copy.deepcopy(value)
    # The compiled emitter is evidence producer, while this script is the
    # only writer for versioned backend fixtures.  Do not leave a second
    # hand-executable write command in the committed artifact.
    result["reproduce_with"] = FIXTURE_GENERATOR_COMMAND
    result[FIXTURE_GENERATOR_KEY] = provenance
    return result


def normalized_for_freshness(value: dict[str, Any]) -> bytes:
    """Compare functional bytes and portable source provenance.

    The committed binary digest records the exact generator used for a fixture.
    It is intentionally not a cross-toolchain requirement: the same C emitter
    is exercised on Linux and Windows with different object code. The wire
    payloads plus the P0 IR binding are the cross-platform freshness contract.
    """
    comparable = copy.deepcopy(value)
    generator = comparable.get(FIXTURE_GENERATOR_KEY)
    if isinstance(generator, dict):
        generator.pop("generator_binary_sha256", None)
    return normalized_json(comparable)


def require_fresh(emitted: dict[str, Any], fixture: dict[str, Any], *, label: str) -> None:
    emitted_bytes = normalized_for_freshness(emitted)
    fixture_bytes = normalized_for_freshness(fixture)
    if emitted_bytes != fixture_bytes:
        emitted_hash = hashlib.sha256(emitted_bytes).hexdigest()
        fixture_hash = hashlib.sha256(fixture_bytes).hexdigest()
        raise FixtureError(
            f"{label} is stale: Agent emitter sha256={emitted_hash} fixture sha256={fixture_hash}; "
            "run the sole regeneration command with --regenerate and review the wire change"
        )


def emit(emitter: Path, argument: str, p0_ir: Path) -> dict[str, Any]:
    if not emitter.is_file():
        raise FixtureError(f"Agent durable-fixture emitter is missing: {emitter}")
    if not p0_ir.is_file():
        raise FixtureError(f"published P0 IR is missing: {p0_ir}")
    environment = dict(os.environ)
    environment["EDR_P0_IR_PATH"] = str(p0_ir)
    environment["LC_ALL"] = "C"
    environment["TZ"] = "UTC"
    completed = subprocess.run(
        [str(emitter), argument],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
    )
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        raise FixtureError(f"Agent emitter {argument} failed: {detail or completed.returncode}")
    try:
        return require_object(json.loads(completed.stdout.decode("utf-8")), label=f"Agent emitter {argument}")
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FixtureError(f"Agent emitter {argument} did not emit valid JSON") from exc


def emit_pair(emitter: Path, p0_ir: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    return (
        emit(emitter, "--emit-p0-source-only-durable-fixture", p0_ir),
        emit(emitter, "--emit-terminal-authority-durable-fixture", p0_ir),
    )


def require_deterministic_emission(first: tuple[dict[str, Any], dict[str, Any]],
                                   second: tuple[dict[str, Any], dict[str, Any]]) -> None:
    for label, first_value, second_value in (
        ("source", first[0], second[0]),
        ("terminal", first[1], second[1]),
    ):
        if normalized_json(first_value) != normalized_json(second_value):
            raise FixtureError(f"Agent {label} fixture emission is not deterministic")


def render_json(value: dict[str, Any]) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=False) + "\n").encode("utf-8")


def stage_fixture(path: Path, payload: bytes) -> Path:
    if not path.parent.is_dir():
        raise FixtureError(f"fixture directory does not exist: {path.parent}")
    try:
        # ``NamedTemporaryFile`` defaults to owner-only permissions.  Keep an
        # existing fixture's mode, or use the repository-safe 0644 mode for a
        # new fixture instead of inheriting an arbitrary process umask.
        try:
            original_mode = stat.S_IMODE(path.stat().st_mode)
        except FileNotFoundError:
            original_mode = 0o644
        with tempfile.NamedTemporaryFile(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent,
                                         delete=False) as staged:
            staged.write(payload)
            staged.flush()
            os.fsync(staged.fileno())
            os.chmod(staged.name, original_mode)
            # Persist the permission metadata as well as the fixture bytes
            # before this staged pathname becomes observable at ``path``.
            os.fsync(staged.fileno())
            return Path(staged.name)
    except OSError as exc:
        raise FixtureError(f"stage fixture {path}: {exc}") from exc


def replace_staged_pair(source_path: Path, source_value: dict[str, Any],
                        terminal_path: Path, terminal_value: dict[str, Any]) -> None:
    """Replace a pair only after both writes are durable, with ordinary-error rollback.

    ``os.replace`` is atomic for one pathname, not for two. Retaining the old
    bytes lets an ordinary second replace error restore the first path. A host
    crash between replacements cannot be made transactional without adding a
    persistent journal; the normal fail-closed freshness gate is the recovery
    detector for that case.
    """
    staged_paths: list[Path] = []
    originals: list[tuple[Path, bytes]] = []
    replaced: list[tuple[Path, bytes]] = []
    try:
        originals = [(source_path, source_path.read_bytes()), (terminal_path, terminal_path.read_bytes())]
        staged_paths.append(stage_fixture(source_path, render_json(source_value)))
        staged_paths.append(stage_fixture(terminal_path, render_json(terminal_value)))
        os.replace(staged_paths[0], source_path)
        replaced.append(originals[0])
        os.replace(staged_paths[1], terminal_path)
        replaced.append(originals[1])
    except OSError as exc:
        rollback_errors: list[str] = []
        for path, original in reversed(replaced):
            try:
                rollback_staged = stage_fixture(path, original)
                try:
                    os.replace(rollback_staged, path)
                finally:
                    rollback_staged.unlink(missing_ok=True)
            except OSError as rollback_exc:
                rollback_errors.append(f"{path}: {rollback_exc}")
        detail = f"staged pair replacement failed: {exc}"
        if rollback_errors:
            detail += "; rollback failed: " + "; ".join(rollback_errors)
        else:
            detail += "; replaced paths restored"
        raise FixtureError(detail) from exc
    finally:
        for staged in staged_paths:
            try:
                staged.unlink(missing_ok=True)
            except OSError:
                pass


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--emitter", type=Path, required=True,
                        help="compiled test_p0_source_only_durable_contract executable")
    parser.add_argument("--p0-ir", type=Path, default=DEFAULT_P0_IR)
    parser.add_argument("--source-fixture", type=Path, default=DEFAULT_SOURCE_FIXTURE)
    parser.add_argument("--terminal-fixture", type=Path, default=DEFAULT_TERMINAL_FIXTURE)
    parser.add_argument("--regenerate", action="store_true",
                        help="the sole writer: stage and replace both fixtures from the compiled Agent emitter")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        emitter = args.emitter.resolve()
        p0_ir = args.p0_ir.resolve()
        source_path = args.source_fixture.resolve()
        terminal_path = args.terminal_fixture.resolve()
        source_fixture = validate_source_fixture(load_json(source_path), label="source fixture",
                                                  require_generator=not args.regenerate)
        terminal_fixture = validate_terminal_fixture(load_json(terminal_path), label="terminal fixture",
                                                      require_generator=not args.regenerate)
        if not args.regenerate:
            validate_fixture_pair_provenance(source_fixture, terminal_fixture)
        emitted_pair = emit_pair(emitter, p0_ir)
        repeated_pair = emit_pair(emitter, p0_ir)
        require_deterministic_emission(emitted_pair, repeated_pair)
        emitted_source = validate_source_fixture(emitted_pair[0], label="emitted source fixture",
                                                 require_generator=False)
        emitted_terminal = validate_terminal_fixture(emitted_pair[1], label="emitted terminal fixture",
                                                     require_generator=False)
        approved_transition = require_same_semantic_ids(
            emitted_source,
            source_fixture,
            emitted_terminal,
            terminal_fixture,
            allow_approved_transition=args.regenerate,
        )
        provenance = fixture_generator_provenance(emitter, p0_ir, emitted_source, emitted_terminal)
        generated_source = with_generator_provenance(emitted_source, provenance)
        generated_terminal = with_generator_provenance(emitted_terminal, provenance)
        validate_source_fixture(generated_source, label="generated source fixture", require_generator=True)
        validate_terminal_fixture(generated_terminal, label="generated terminal fixture", require_generator=True)
        validate_fixture_pair_provenance(generated_source, generated_terminal)
        if args.regenerate:
            replace_staged_pair(source_path, generated_source, terminal_path, generated_terminal)
            transition_note = (
                f"; approved semantic transition={approved_transition}"
                if approved_transition else ""
            )
            print(
                "P0 durable wire fixtures regenerated by staged-pair replacement from the compiled Agent "
                f"(generator sha256={provenance['generator_binary_sha256']}, "
                f"P0 IR={provenance['rules_bundle_version']}:{provenance['p0_ir_sha256']}"
                f"{transition_note})"
            )
            return 0
        require_fresh(generated_source, source_fixture, label=source_path.name)
        require_fresh(generated_terminal, terminal_fixture, label=terminal_path.name)
        fixture_binary_sha = source_fixture[FIXTURE_GENERATOR_KEY]["generator_binary_sha256"]
        current_binary_sha = provenance["generator_binary_sha256"]
        binary_note = "matches" if fixture_binary_sha == current_binary_sha else "differs (recorded provenance retained)"
        print(
            "P0 durable wire fixtures match bytes emitted by the compiled Agent "
            f"(generator sha256 {binary_note}; P0 IR={provenance['rules_bundle_version']}:{provenance['p0_ir_sha256']})"
        )
        return 0
    except FixtureError as exc:
        print(f"P0 durable wire fixture gate: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
