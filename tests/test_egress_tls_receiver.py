#!/usr/bin/env python3
"""Repeatable loopback mTLS receiver; no production URL, credentials or queue.

Run with --client PATH. OpenSSL generates temporary CA/server/client keys;
normal certificate chain and DNS verification remain enabled. SQLite FULL
commits precede receipts. Only synthetic counters/hashes appear in the report.
"""
import argparse
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
            context["engine"] == "ave" and context["rule_id"] == "behavior_anomaly" and \
            context["process"]["cmdline"] == "synthetic.exe --required-alert-context"
    except (KeyError, IndexError, ValueError, TypeError, struct.error):
        return False


class Receiver(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, certificate_root: Path, certificate: str, database: Path):
        super().__init__(("127.0.0.1", 0), Handler)
        self.database = database
        self.observations = []
        self.errors = []
        self.lock = threading.Lock()
        with sqlite3.connect(database) as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("PRAGMA synchronous=FULL")
            db.execute("CREATE TABLE receipt(batch_id TEXT PRIMARY KEY,sha TEXT NOT NULL,observations INTEGER NOT NULL)")
            db.execute("CREATE TABLE health(id INTEGER PRIMARY KEY,revision INTEGER NOT NULL,payload TEXT NOT NULL)")
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
                if not frames or not all(is_proven_alert(frame) for frame in frames):
                    raise ValueError("non-alert raw event reached synthetic receiver")
                digest = hashlib.sha256(raw).hexdigest()
                batch = body["batch_id"]
                with sqlite3.connect(self.server.database) as db:
                    db.execute("PRAGMA synchronous=FULL")
                    previous = db.execute("SELECT sha,observations FROM receipt WHERE batch_id=?", (batch,)).fetchone()
                    if previous and previous[0] != digest:
                        raise ValueError("batch ID reused with changed payload")
                    count = previous[1] + 1 if previous else 1
                    db.execute("INSERT INTO receipt VALUES(?,?,?) ON CONFLICT(batch_id) DO UPDATE SET observations=excluded.observations",
                               (batch, digest, count))
                    db.commit()
                if batch == "tls-ack-lost" and count == 1:
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
            elif self.path in ("/api/v1/ingest/engine-health", "/api/v1/ingest/engine-health/delta"):
                if b"synthetic-secret" in wire or b"raw_event" in wire:
                    raise ValueError("private diagnostic evidence reached health receiver")
                with sqlite3.connect(self.server.database) as db:
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
        for mode in ("positive", "positive-ip", "positive-v2", "wrong-ca", "wrong-host"):
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
                with sqlite3.connect(server.database) as db:
                    reports[-1]["durable_batches"] = db.execute("SELECT COUNT(*) FROM receipt").fetchone()[0]
                    reports[-1]["duplicate_observations"] = db.execute("SELECT COALESCE(SUM(observations-1),0) FROM receipt").fetchone()[0]
            if result.returncode and not args.baseline:
                # Safe synthetic assertion names only; no body or credentials.
                print(result.stderr[-4000:])
        failed = any(report["client_exit"] or report["receiver_business_failures"] for report in reports)
        failed |= any(report["received_requests"] for report in reports if not report["mode"].startswith("positive"))
        print(json.dumps({"synthetic_only": True, "production_connections": 0,
                          "baseline_expected_failure": args.baseline, "passed": not failed,
                          "scenarios": reports}, indent=2, sort_keys=True))
        return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
