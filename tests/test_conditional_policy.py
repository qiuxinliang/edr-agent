"""Synthetic loopback mTLS exercises the production GET/cache/signature path."""
import argparse
import base64
import hashlib
import hmac
import http.server
import os
from pathlib import Path
import ssl
import subprocess
import tempfile
import threading
from test_egress_tls_receiver import openssl_certificates

SECRET = "synthetic-policy-secret"
def b64(data):
    return base64.urlsafe_b64encode(data).decode().rstrip("=")

class Receiver(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    calls = 0
    health_profiles = []
    def log_message(self, *_):
        pass
    def do_POST(self):
        import json
        if self.path == "/api/v1/ingest/config-status":
            self.rfile.read(int(self.headers["Content-Length"]))
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"{}")
            self.wfile.flush()
            return
        assert self.path == "/api/v1/ingest/engine-health"
        assert self.connection.getpeercert()
        data = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        monitor = data["engine_health"]["monitor"]
        assert monitor["interval_s"] == 120
        type(self).health_profiles.append(monitor["profile"])
        self.send_response(200)
        reply = b'{"data":{"accepted":true}}'
        self.send_header("Content-Length", str(len(reply)))
        self.end_headers()
        self.wfile.write(reply)
        self.wfile.flush()
    def do_GET(self):
        import json
        step = type(self).calls
        type(self).calls += 1
        assert self.path == "/api/v1/agent/runtime-policy.toml"
        assert self.connection.getpeercert()
        assert (self.headers.get("If-None-Match") is None) == (step in (0, 11, 13))
        body = b"[synthetic]\nvalue = 1\n" if step < 2 else b"[synthetic]\nvalue = 2\n"
        if step >= 7:
            body = b"[synthetic]\nvalue = 3\n"
        digest = hashlib.sha256(body).hexdigest()
        if step == 3:
            digest = "0" * 64
        fields = dict(schema="agent-config-signature-v1", version="synthetic-v1", sequence=1 if step == 9 else 2,
                      configHash=digest, previousHash="", nonce=f"synthetic-{step}",
                      expiresAt="2000-01-01T00:00:00Z" if step in (5, 12) else "2099-01-01T00:00:00Z",
                      signingKeyId="synthetic-key")
        payload = json.dumps(fields, separators=(",", ":")).encode()
        self.send_response(200 if step in (0, 2, 7, 11, 13) else 304)
        if step not in (4, 10):
            for header, value in {
                "X-Rules-Version": fields["version"], "X-Agent-Config-Hash": digest,
                "X-Agent-Config-Sequence": str(fields["sequence"]), "X-Agent-Config-Previous-Hash": "",
                "X-Agent-Config-Nonce": fields["nonce"], "X-Agent-Config-Expires-At": fields["expiresAt"],
                "X-Agent-Config-Signing-Key": "synthetic-key",
                "X-Agent-Config-Signed-Payload": b64(payload),
                "X-Agent-Config-Signature": b64(hmac.digest(("invalid-fixture-key" if step == 8 else SECRET).encode(), payload, "sha256")),
            }.items():
                self.send_header(header, value)
        # The 304 selected-representation length must never be consumed as a body.
        self.send_header("Content-Length", str(len(body)) if step in (0, 2, 6, 7, 11, 13) else "0")
        self.end_headers()
        if step in (0, 2, 7, 11, 13):
            self.wfile.write(body)
        self.wfile.flush()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--client", required=True)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="edr-conditional-policy-") as temp:
        root = Path(temp)
        openssl_certificates(root)
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Receiver)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(root / "server.pem", root / "server.key")
        context.load_verify_locations(root / "ca.pem")
        context.verify_mode = ssl.CERT_REQUIRED
        server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            env = dict(os.environ, EDR_AGENT_CONFIG_SIGNING_SECRET=SECRET, EDR_ENGINE_HEALTH_INTERVAL_S="120", EDR_REMOTE_CONFIG_AUTO_PULL="1", EDR_REMOTE_CONFIG_POLL_S="60", EDR_REMOTE_CONFIG_URL=f"https://127.0.0.1:{server.server_port}/api/v1/agent/runtime-policy.toml")
            subprocess.run([args.client, f"https://127.0.0.1:{server.server_port}/api/v1",
                            str(root / "ca.pem"), str(root / "client.pem"), str(root / "client.key"),
                            str(root / "queue.db"), str(root / "response.toml")], env=env, check=True, timeout=45)
            assert Receiver.calls == 14
            assert Receiver.health_profiles == ["basic", "diagnostic"]
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

if __name__ == "__main__":
    main()
