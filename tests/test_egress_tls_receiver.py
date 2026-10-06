#!/usr/bin/env python3
"""Repeatable loopback mTLS receiver; no production URL, credentials or queue.

Run with --client PATH. OpenSSL generates temporary CA/server/client keys;
normal certificate chain and DNS verification remain enabled. SQLite FULL
commits precede receipts. Only synthetic counters/hashes appear in the report.
"""
import argparse
from contextlib import closing
import base64
import hashlib
import http.server
import json
import os
from pathlib import Path
import shutil
import sqlite3
import ssl
import struct
import subprocess
import tempfile
import threading
import time


def openssl_certificates(root: Path):
    executable = shutil.which("openssl")
    if not executable:
        raise RuntimeError("OpenSSL executable is required for isolated TLS fixtures")

    def run(*args):
        subprocess.run([executable, *args], cwd=root, check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    for name in ("ca", "other-ca"):
        run("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
            "-subj", f"/CN=Synthetic-{name}", "-keyout", f"{name}.key", "-out", f"{name}.pem")
    for name, usage, san in (("server", "serverAuth", "DNS:localhost,IP:127.0.0.1"),
                             ("wrong-host", "serverAuth", "DNS:wrong.invalid"),
                             ("client", "clientAuth", "DNS:synthetic-endpoint")):
        run("req", "-newkey", "rsa:2048", "-nodes", "-subj", f"/CN=Synthetic-{name}",
            "-keyout", f"{name}.key", "-out", f"{name}.csr")
        (root / f"{name}.ext").write_text(f"subjectAltName={san}\nextendedKeyUsage={usage}\n", encoding="ascii")
        run("x509", "-req", "-in", f"{name}.csr", "-CA", "ca.pem", "-CAkey", "ca.key",
            "-CAcreateserial", "-days", "1", "-extfile", f"{name}.ext", "-out", f"{name}.pem")


def protobuf(data: bytes):
    fields = {}
    position = 0

    def varint():
        nonlocal position
        value = 0
        for shift in range(0, 70, 7):
            if position >= len(data):
                raise ValueError("truncated protobuf")
            byte = data[position]
            position += 1
            value |= (byte & 127) << shift
            if not byte & 128:
                return value
        raise ValueError("protobuf varint overflow")

    while position < len(data):
        key = varint()
        tag, wire = key >> 3, key & 7
        if wire == 0:
            value = varint()
        elif wire == 2:
            size = varint()
            value = data[position:position + size]
            if len(value) != size:
                raise ValueError("truncated protobuf field")
            position += size
        elif wire in (1, 5):
            size = 8 if wire == 1 else 4
            value = data[position:position + size]
            position += size
        else:
            raise ValueError("unsupported protobuf wire type")
        fields.setdefault(tag, []).append(value)
    return fields


def decode_frames(raw: bytes):
    if len(raw) < 12:
        raise ValueError("short batch")
    magic, count, length = struct.unpack("<III", raw[:12])
    if magic != 0x31544142 or length != len(raw) - 12:
        raise ValueError("receiver fixture expects canonical BAT1")
    frames, offset = [], 12
    for _ in range(count):
        size = struct.unpack_from("<I", raw, offset)[0]
        offset += 4
        frames.append(protobuf(raw[offset:offset + size]))
        offset += size
    if offset != len(raw):
        raise ValueError("unaccounted batch bytes")
    return frames


def is_proven_alert(frame):
    try:
        alert = protobuf(frame[40][0])
        subject = json.loads(alert[11][0])
        if frame[9][0] != b"synthetic.exe --required-alert-context" or alert[7][0] != frame[6][0]:
            return False
        if subject["subject_type"] == "edr_dynamic_rule":
            # The initial fixed-proof fixture remains independently checkable
            # for the exact-before-source comparison; current fixtures use the
            # actual AVE callback path below.
            return subject["rule_id"] == "synthetic-rule" and \
                subject["context"]["source_event_id"] == "synthetic-source" and \
                subject["context"]["pid"] == alert[7][0]
        if subject["subject_type"] != "detection_context" or frame[4][0] != 70:
            return False
        basis = subject["evaluation_basis"]
        context = subject["detection_context"]
        score = struct.unpack("<f", alert[1][0])[0]
        threshold = basis["threshold"]
        return basis["schema"] == "agent_detection_basis_v1" and \
            basis["owner"] == "ave_behavior_pipeline" and \
            basis["predicate_matched"] is True and basis["threshold_met"] is True and \
            basis["pid"] == context["process"]["pid"] == frame[6][0] and \
            int(basis["timestamp_ns"]) == frame[5][0] == alert[6][0] and \
            basis["event_count"] == 1 and basis["last_event_type"] == 9 and \
            basis["behavior_flags"] == 4294967295 and 0 < threshold <= score <= 1 and \
            context["engine"] == "ave" and context["rule_id"] == "behavior_anomaly"
    except (KeyError, IndexError, ValueError, TypeError, struct.error):
        return False


def is_bound_pmfe(frame, db):
    """Independent synthetic receiver oracle: durable original ownership must
    precede a nonpositive follow-up; tags alone cannot establish association."""
    try:
        if frame[2][0] != b"synthetic-endpoint" or frame[3][0] != b"synthetic-tenant" or 40 in frame:
            return False
        context = json.loads(frame[30][0])
        engine = context["engine_evidence"]
        generation = (str(frame[51][0]), str(frame[52][0]))
        if frame[6][0] != 4242 or generation != (str(0xfedcba9876543210), str(133444000000000000)):
            return False
        if frame[4][0] == 63:
            valid = engine["schema"] == "shellcode_result_v1" and engine["alert_id"] == "sc-local-1" and \
                engine["owner"]["pid"] == frame[6][0] and engine["detection"]["score"] == 0.9 and \
                engine["detection"]["rule"] == "synthetic-payload-signature" and \
                engine["payload"]["sha256"] == "a" * 64
            if valid:
                db.execute("INSERT INTO followup_owner VALUES(?,?,?,?,?) ON CONFLICT(alert_id) DO NOTHING",
                           (engine["alert_id"], frame[6][0], *generation, frame[5][0]))
            return valid
        if frame[4][0] != 66 or engine["schema"] != "pmfe_result_v1" or \
            engine["detector"] != "pmfe" or engine["followup_only"] is not True or \
            engine["verdict"] != "inconclusive" or engine["status"] != "failed":
            return False
        owner = db.execute("SELECT pid,start_key,birth,time_ns FROM followup_owner WHERE alert_id=?",
                           (engine["source_alert_id"],)).fetchone()
        return owner is not None and owner[:3] == (frame[6][0], *generation) and \
            owner[3] <= frame[5][0] <= owner[3] + 3600 * 10**9 and \
            not frame.get(9) and b"pmfe_association_id=" not in frame[30][0]
    except (KeyError, IndexError, TypeError, ValueError):
        return False


def is_paired_p0(frame, db, digest):
    """Synthetic business consumer: a receipt for combined alone cannot create
    the action alert. A matching independently received intent is required."""
    try:
        context = json.loads(frame[30][0])
        terminal = context["enforcement_terminal"]
        process = terminal["process"]
        tenant, endpoint, event = (frame[tag][0].decode() for tag in (3, 2, 1))
        pid, start, birth = (frame[tag][0] for tag in (6, 51, 52))
        path, file_id = process["canonical_image_path"], process["file_identity"]
        if (tenant, endpoint) != ("synthetic-tenant", "synthetic-endpoint") or \
            terminal["source_event_key"] != event or terminal["source_event_id"] != event or \
            terminal["process_pid"] != pid or process["generation_key"] != f"startkey-{start:016x}" or \
            process["creation_filetime_100ns"] != birth or process["file_identity_available"] is not True or \
            terminal["planned_action"] != "terminate_process" or \
            context["evidence"]["file_identity"] != file_id or \
            context["evidence"]["artifact"]["source"] != "process_image_section" or \
            context["evidence"]["artifact"]["quality"] != "action_authoritative":
            return False
        commitment = hashlib.sha256()
        for value in ("edr-p0-enforcement-terminal-v1", tenant, endpoint, terminal["rule_id"],
                      event, str(pid), f"{start:016x}", f"{birth:016x}", path, file_id):
            encoded = value.encode()
            commitment.update(struct.pack("<I", len(encoded)) + encoded + b"\0")
        key = "p0-enforcement-" + commitment.hexdigest()
        if terminal["terminal_key"] != key:
            return False
        phase = terminal["phase"]
        if phase == "intent":
            if 40 in frame or terminal["requested"] is not True or any(name in terminal for name in ("attempted", "succeeded", "action", "error_code")):
                return False
        elif phase == "result" and 40 in frame:
            alert = protobuf(frame[40][0])
            subject = json.loads(alert[11][0])
            source = subject["context"]
            if subject["subject_type"] != "edr_dynamic_rule" or alert[7][0] != pid or \
                alert[9][0].decode() != path or source["process_path"] != path or \
                source["canonical_image_path"] != path or source["file_identity"] != file_id or \
                source["source_event_id"] != event or source["pid"] != pid or \
                source["process_start_key"] != str(start) or \
                source["process_creation_filetime_100ns"] != str(birth) or \
                subject["enforcement"]["requested"] is not True or \
                any(subject[name] != terminal[name] for name in ("rule_id", "rules_bundle_version", "rules_bundle_sha256")) or \
                any(subject["enforcement"][name] != terminal[name]
                    for name in ("attempted", "succeeded", "action", "error_code")):
                return False
            phase = "combined"
        else:
            return False  # A source-only result is not another alert receipt.
        lineage = json.dumps({name: terminal[name] for name in
                              ("rule_id", "rules_bundle_version", "rules_bundle_sha256")}, sort_keys=True)
        previous = db.execute("SELECT lineage,intent_sha,combined_sha FROM p0_association WHERE terminal_key=?", (key,)).fetchone()
        slot = 1 if phase == "intent" else 2
        if previous and (previous[0] != lineage or (previous[slot] and previous[slot] != digest)):
            return False
        db.execute("INSERT INTO p0_association(terminal_key,lineage) VALUES(?,?) ON CONFLICT(terminal_key) DO NOTHING", (key, lineage))
        column = "intent_sha" if phase == "intent" else "combined_sha"
        db.execute(f"UPDATE p0_association SET {column}=? WHERE terminal_key=?", (digest, key))
        db.execute("UPDATE p0_association SET alert_created=1 WHERE terminal_key=? AND intent_sha IS NOT NULL AND combined_sha IS NOT NULL", (key,))
        return True
    except (KeyError, IndexError, TypeError, ValueError, struct.error):
        return False


class Receiver(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, certificate_root: Path, certificate: str, database: Path):
        super().__init__(("127.0.0.1", 0), Handler)
        self.database = database
        self.observations = []
        self.errors = []
        self.config_receipts = []
        self.lock = threading.Lock()
        with closing(sqlite3.connect(database)) as db, db:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("PRAGMA synchronous=FULL")
            db.execute("CREATE TABLE receipt(batch_id TEXT PRIMARY KEY,sha TEXT NOT NULL,observations INTEGER NOT NULL)")
            db.execute("CREATE TABLE health(id INTEGER PRIMARY KEY,revision INTEGER NOT NULL,payload TEXT NOT NULL)")
            db.execute("CREATE TABLE followup_owner(alert_id TEXT PRIMARY KEY,pid INTEGER,start_key TEXT,birth TEXT,time_ns INTEGER)")
            db.execute("CREATE TABLE p0_association(terminal_key TEXT PRIMARY KEY,lineage TEXT NOT NULL,intent_sha TEXT,combined_sha TEXT,alert_created INTEGER NOT NULL DEFAULT 0)")
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certificate_root / f"{certificate}.pem", certificate_root / f"{certificate}.key")
        context.load_verify_locations(certificate_root / "ca.pem")
        context.verify_mode = ssl.CERT_REQUIRED
        self.socket = context.wrap_socket(self.socket, server_side=True)
        self.thread = threading.Thread(target=self.serve_forever, daemon=True)
        self.thread.start()

    def finish(self):
        self.shutdown()
        self.server_close()
        self.thread.join(timeout=5)


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_):
        pass

    def reply(self, data, status=200):
        body = json.dumps(data, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
            pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        if not 0 < length <= 8 * 1024 * 1024:
            self.reply({"code": "INVALID_SIZE"}, 400)
            return
        wire = self.rfile.read(length)
        with self.server.lock:
            self.server.observations.append({"path": self.path, "bytes": len(wire), "sha256": hashlib.sha256(wire).hexdigest()})
        try:
            if self.headers.get("Content-Type") == "application/x-protobuf":
                envelope = protobuf(wire)
                if envelope[1][0] != b"edr.transport.envelope.v1" or envelope[8][0] != b"identity":
                    raise ValueError("dictionary profile must retain inspectable identity codec")
                body = {"endpoint_id": envelope[2][0].decode(), "batch_id": envelope[3][0].decode()}
                envelope_raw = envelope[9][0]
            else:
                body = json.loads(wire)
                envelope_raw = None
            if self.path == "/api/v1/ingest/report-events":
                raw = envelope_raw if envelope_raw is not None else base64.b64decode(body["payload"], validate=True)
                frames = decode_frames(raw)
                if not frames:
                    raise ValueError("empty raw event batch reached synthetic receiver")
                digest = hashlib.sha256(raw).hexdigest()
                batch = body["batch_id"]
                with closing(sqlite3.connect(self.server.database)) as db, db:
                    db.execute("PRAGMA synchronous=FULL")
                    if not all(is_proven_alert(frame) or is_bound_pmfe(frame, db) or is_paired_p0(frame, db, digest) for frame in frames):
                        raise ValueError("unproven alert or follow-up reached synthetic receiver")
                    previous = db.execute("SELECT sha,observations FROM receipt WHERE batch_id=?", (batch,)).fetchone()
                    if previous and previous[0] != digest:
                        raise ValueError("batch ID reused with changed payload")
                    count = previous[1] + 1 if previous else 1
                    db.execute("INSERT INTO receipt VALUES(?,?,?) ON CONFLICT(batch_id) DO UPDATE SET observations=excluded.observations",
                               (batch, digest, count))
                    db.commit()
                if (batch in ("tls-ack-lost", "tls-p0-intent") or frames[0][4][0] == 66) and count == 1:
                    self.reply({"code": "OK", "data": {"accepted": True}})
                    return
                ack = {"version": 1, "state": "durable", "endpoint_id": body["endpoint_id"],
                       "batch_id": batch, "payload_sha256": digest}
                if batch == "tls-ack-mismatch":
                    ack["payload_sha256"] = "0" * 64
                self.reply({"code": "OK", "data": {"accepted": True, "invalid_frames": 0, "ack": ack}})
            elif self.path == "/api/v1/ingest/heartbeat":
                if set(body) != {"endpoint_id", "agent_version", "policy_version"}:
                    raise ValueError("heartbeat raw field reached receiver")
                self.reply({"code": "OK"})
            elif self.path == "/api/v1/ingest/config-status":
                fields = {"tenant_id", "endpoint_id", "agent_version", "policy_version",
                          "config_hash", "config_sequence", "config_nonce", "config_signature",
                          "signing_key_id", "verified", "reject_reason", "desired_version",
                          "desired_hash", "apply_status", "restart_required", "payload"}
                contract = self.headers.get("X-EDR-Suppression-Contract")
                if set(body) != fields or body["tenant_id"] != "synthetic-tenant" or \
                        body["endpoint_id"] != "synthetic-endpoint" or contract != "2" or \
                        body["payload"] != {"source": "agent-runtime-policy", "verified": body["verified"]} or \
                        b"synthetic-secret" in wire:
                    raise ValueError("invalid config receipt reached receiver")
                with self.server.lock:
                    self.server.config_receipts.append({"status": body["apply_status"],
                                                       "verified": body["verified"],
                                                       "reason": body["reject_reason"],
                                                       "contract": contract})
                self.reply({"code": "OK"})
            elif self.path in ("/api/v1/ingest/engine-health", "/api/v1/ingest/engine-health/delta"):
                if b"synthetic-secret" in wire or b"raw_event" in wire:
                    raise ValueError("private diagnostic evidence reached health receiver")
                with closing(sqlite3.connect(self.server.database)) as db, db:
                    db.execute("PRAGMA synchronous=FULL")
                    previous = db.execute("SELECT revision,payload FROM health WHERE id=1").fetchone()
                    update = body.get("engine_health_update")
                    if update:
                        if not previous or update["base"] != f"r{previous[0]}":
                            self.reply({"code": "ENGINE_HEALTH_BASE_MISMATCH"}, 409)
                            return
                        merged = json.loads(previous[1])
                        for key in update["removed"]:
                            merged.pop(key, None)
                        merged.update(body["engine_health"])
                    else:
                        merged = body["engine_health"]
                    revision = previous[0] + 1 if previous else 1
                    db.execute("INSERT INTO health VALUES(1,?,?) ON CONFLICT(id) DO UPDATE SET revision=excluded.revision,payload=excluded.payload",
                               (revision, json.dumps(merged, sort_keys=True)))
                    db.commit()
                self.reply({"code": "OK", "data": {"accepted": True, "health_delta_version": 1, "health_revision": f"r{revision}"}})
            else:
                raise ValueError("unsupported data channel reached receiver")
        except (ValueError, KeyError, IndexError, sqlite3.Error) as error:
            with self.server.lock:
                self.server.errors.append(type(error).__name__)
            self.reply({"code": "SYNTHETIC_BUSINESS_REJECTED"}, 400)


def synthetic_child_diagnostics(stderr):
    """Report fixed assertion names and a hash, never child log contents."""
    known = {
        "detect_synthetic_input(r, &capture)": "detector_input",
        "ordinary_len && alert_len": "fixture_encoding",
        "edr_storage_queue_open(argv[5]) == EDR_OK": "queue_open",
        "queue_result == EDR_OK": "queue_enqueue",
        'row_count(argv[5], "tls-ordinary", "policy_held") == 1': "ordinary_policy_held",
        'row_count(argv[5], "tls-alert", NULL) == 0': "alert_receipt",
        "edr_ingest_http_post_heartbeat() == 0": "heartbeat_receipt",
        'row_count(argv[5], "tls-ack-lost", "pending") == 1': "lost_ack_pending",
    }
    names, unknown = set(), 0
    prefix = "synthetic TLS check failed: "
    for line in stderr.decode("utf-8", errors="replace").splitlines():
        if line.startswith(prefix):
            expression = line[len(prefix):]
            if expression in known:
                names.add(known[expression])
            else:
                unknown += 1
    return {"stderr_bytes": len(stderr), "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
            "failed_assertions": sorted(names), "unknown_assertions": unknown}


def crash_restart_scenario(client, root):
    """Kill only the child created here, after an independently durable receipt
    whose ACK is missing. Verify the pending original bytes before reopening."""
    server = Receiver(root, "server", root / "receiver-crash.db")
    database = root / "agent-crash.db"
    environment = os.environ.copy()
    for name in ("EDR_ZSTD_DICT_PATH", "EDR_CONTROL_DICT_PATH"):
        environment.pop(name, None)
    environment["EDR_TEST_CRASH_AFTER_LOST_ACK"] = "1"
    # This receiver binds IPv4 only. The crash deadline measures durable owner
    # recovery; DNS/TLS hostname paths remain exercised by the other scenarios.
    arguments = [client, f"https://127.0.0.1:{server.server_port}/api/v1", str(root / "ca.pem"),
                 str(root / "client.pem"), str(root / "client.key"), str(database)]
    checkpoint = root / "crash-checkpoint.json"
    stderr_path = root / "crash-child.stderr"
    child = None
    stage = "checkpoint"
    started = time.monotonic()
    failure = None
    try:
        with checkpoint.open("w", encoding="utf-8") as output, stderr_path.open("wb") as errors:
            child = subprocess.Popen(arguments + ["positive"], stdout=output,
                                     stderr=errors, env=environment, cwd=root)
            deadline = time.monotonic() + 10
            metrics = None
            while time.monotonic() < deadline and child.poll() is None:
                for line in checkpoint.read_text(encoding="utf-8").splitlines():
                    if line.startswith('{"crash_checkpoint"'):
                        metrics = json.loads(line)
                if metrics:
                    break
                time.sleep(0.05)
            if not metrics:
                raise RuntimeError("synthetic crash checkpoint not established")
            stage = "checkpoint_counters"
            assert metrics["detector_inputs"] == metrics["detected"] == 1 and metrics["enqueued"] == 3
            stage = "pending_original"
            with closing(sqlite3.connect(database)) as db, db:
                before = db.execute("SELECT payload,status FROM event_queue WHERE batch_id='tls-ack-lost'").fetchone()
                assert before and before[1] == "pending"
                original_hash = hashlib.sha256(before[0]).hexdigest()
            child.kill()
            killed = child.wait(timeout=5)
        stage = "killed_original"
        with closing(sqlite3.connect(database)) as db, db:
            after = db.execute("SELECT payload,status FROM event_queue WHERE batch_id='tls-ack-lost'").fetchone()
            assert after == before
        environment.pop("EDR_TEST_CRASH_AFTER_LOST_ACK", None)
        stage = "resume_receipt"
        result = subprocess.run(arguments + ["resume-after-crash"], capture_output=True,
                                text=True, timeout=15, env=environment, cwd=root)
        assert result.returncode == 0, "crashed owner did not recover its genuine receipt"
        stage = "durable_receipt"
        with closing(sqlite3.connect(server.database)) as db, db:
            receipt = db.execute("SELECT sha,observations FROM receipt WHERE batch_id='tls-ack-lost'").fetchone()
            assert receipt == (original_hash, 2)
            durable = db.execute("SELECT COUNT(*) FROM receipt").fetchone()[0]
        return {"mode": "positive-crash-restart", "client_exit": result.returncode,
                "client_metrics": [metrics] + [json.loads(line) for line in result.stdout.splitlines() if line.startswith("{")],
                "killed_child_exit": killed, "original_pending_hash_preserved": True,
                "received_requests": len(server.observations),
                "received_body_bytes": sum(item["bytes"] for item in server.observations),
                "receiver_business_failures": len(server.errors), "durable_batches": durable,
                "duplicate_observations": 1, "distinct_queue_acks": 2}
    except (AssertionError, RuntimeError, OSError, sqlite3.Error, ValueError, KeyError,
            subprocess.SubprocessError) as error:
        failure = {"mode": "positive-crash-restart", "client_exit": 1,
                   "receiver_business_failures": len(server.errors),
                   "received_requests": len(server.observations),
                   "received_body_bytes": sum(item["bytes"] for item in server.observations),
                   "classes": {path: sum(item["path"] == path for item in server.observations)
                               for path in sorted({item["path"] for item in server.observations})},
                   "diagnostic": {"stage": stage, "error_type": type(error).__name__,
                                  "elapsed_ms": round((time.monotonic() - started) * 1000),
                                  "child_running_at_failure": bool(child and child.poll() is None),
                                  "child_exit_at_failure": child.poll() if child else None}}
    finally:
        if child and child.poll() is None:
            child.kill()
            child.wait(timeout=5)
        server.finish()
    # Failure stays failure, including checkpoint/read errors. The parent still
    # reports completed scenarios before this one instead of losing their data.
    failure["diagnostic"].update(synthetic_child_diagnostics(stderr_path.read_bytes()))
    failure["diagnostic"]["child_exit_after_cleanup"] = child.poll() if child else None
    return failure


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--client", required=True)
    parser.add_argument("--baseline", action="store_true", help="run historical implementation; regression is expected to fail")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="edr-egress-mtls-") as temporary:
        root = Path(temporary)
        openssl_certificates(root)
        # An existing dictionary is an optional optimization. The production
        # policy must preserve alert delivery using the existing identity codec.
        (root / "synthetic.dict").write_bytes(b"synthetic-dictionary-content-" * 40)
        reports = []
        modes = ("positive", "positive-ip", "positive-v2", "wrong-ca", "wrong-host")
        if not args.baseline:
            modes += ("positive-pmfe", "positive-journal", "positive-p0-journal")
        for mode in modes:
            server = Receiver(root, "wrong-host" if mode == "wrong-host" else "server", root / f"receiver-{mode}.db")
            try:
                environment = os.environ.copy()
                environment.pop("EDR_ZSTD_DICT_PATH", None)
                environment.pop("EDR_CONTROL_DICT_PATH", None)
                if mode == "positive-v2":
                    environment["EDR_ZSTD_DICT_PATH"] = str(root / "synthetic.dict")
                host = "127.0.0.1" if mode == "positive-ip" else "localhost"
                result = subprocess.run([args.client, f"https://{host}:{server.server_port}/api/v1",
                                         str(root / ("other-ca.pem" if mode == "wrong-ca" else "ca.pem")),
                                         str(root / "client.pem"), str(root / "client.key"),
                                         str(root / f"agent-{mode}.db"), mode],
                                        capture_output=True, text=True, timeout=45, env=environment, cwd=root)
            finally:
                server.finish()
            reports.append({"mode": mode, "client_exit": result.returncode,
                            "client_metrics": [json.loads(line) for line in result.stdout.splitlines() if line.startswith("{")],
                            "received_requests": len(server.observations),
                            "received_body_bytes": sum(item["bytes"] for item in server.observations),
                            "receiver_business_failures": len(server.errors),
                            "classes": {path: sum(item["path"] == path for item in server.observations)
                                        for path in sorted({item["path"] for item in server.observations})}})
            if mode.startswith("positive"):
                with closing(sqlite3.connect(server.database)) as db, db:
                    reports[-1]["durable_batches"] = db.execute("SELECT COUNT(*) FROM receipt").fetchone()[0]
                    reports[-1]["duplicate_observations"] = db.execute("SELECT COALESCE(SUM(observations-1),0) FROM receipt").fetchone()[0]
                    if mode == "positive-p0-journal":
                        reports[-1]["business_alerts"] = db.execute("SELECT COALESCE(SUM(alert_created),0) FROM p0_association").fetchone()[0]
                        if reports[-1]["business_alerts"] != 1:
                            reports[-1]["receiver_business_failures"] += 1
                if mode in ("positive", "positive-ip", "positive-v2"):
                    reports[-1]["config_receipts"] = server.config_receipts
                    expected = [{"status": "applied", "verified": True, "reason": "", "contract": "2"},
                                {"status": "failed", "verified": False,
                                 "reason": "config_validation_failed", "contract": "2"}]
                    if server.config_receipts != expected:
                        reports[-1]["receiver_business_failures"] += 1
            if result.returncode and not args.baseline:
                # Safe synthetic assertion names only; no body or credentials.
                print(result.stderr[-4000:])
        if not args.baseline:
            try:
                reports.append(crash_restart_scenario(args.client, root))
            except (AssertionError, RuntimeError, OSError, sqlite3.Error, ValueError, KeyError,
                    subprocess.SubprocessError) as error:
                reports.append({"mode": "positive-crash-restart", "client_exit": 1,
                                "received_requests": None, "receiver_business_failures": 0,
                                "diagnostic": {"stage": "crash_owner_cleanup",
                                               "error_type": type(error).__name__}})
        failed = any(report["client_exit"] or report["receiver_business_failures"] for report in reports)
        failed |= any(report["received_requests"] for report in reports if not report["mode"].startswith("positive"))
        print(json.dumps({"synthetic_only": True, "production_connections": 0,
                          "baseline_expected_failure": args.baseline, "passed": not failed,
                          "scenarios": reports}, indent=2, sort_keys=True))
        return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
