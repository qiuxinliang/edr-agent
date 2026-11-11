"""Exercise the production signed sender against one mutually authenticated loopback receiver."""
import hashlib
import hmac
import json
import os
import ssl
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from test_egress_tls_receiver import openssl_certificates


class ReceiptHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass  # The test records routes, lengths and identities without logging evidence.

    def do_POST(self):
        self.server.paths.append(self.path)
        wire = self.rfile.read(int(self.headers["Content-Length"]))
        digest = hashlib.sha256(wire).hexdigest()
        assert self.connection.getpeercert()
        assert self.path == "/api/v1/ingest/alert-window-result"
        assert self.headers["Authorization"] == "Bearer synthetic-token"
        assert self.headers["X-EDR-Key-ID"] == "synthetic-key"
        assert self.headers["X-EDR-Content-SHA256"] == digest
        canonical = "\n".join(("REQSIG-V1", "POST", self.path, self.headers["X-EDR-Timestamp-Ms"],
                               self.headers["X-EDR-Nonce"], digest, "ep")).encode()
        assert hmac.compare_digest(self.headers["X-EDR-Signature"], hmac.new(b"synthetic", canonical, "sha256").hexdigest())
        record = json.loads(wire)["result"]
        assert record["command_type"] == "alert_window_query_v2" and record["endpoint_id"] == "ep"
        assert record["soar_correlation_id"] == record["command_id"]
        assert json.loads(record["detail_utf8"])["rows"][0]["remote_port"] == 51742
        self.server.digests.append(digest)
        exact = hashlib.sha256(record["detail_utf8"].encode()).hexdigest()
        count = len(self.server.digests)
        body = {"data": {"accepted": True, "complete": True, "command_id": record["command_id"],
                         "endpoint_id": "ep", "result_sha256": exact if count == 3 else "0" * 64}}
        if count == 1:
            body = {"message": "synthetic-proxy-reflection-must-not-be-logged"}
        response = json.dumps(body).encode()
        self.send_response(404 if count == 1 else 200)
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)


def main():
    with tempfile.TemporaryDirectory(prefix="edr-window-mtls-") as tmp:
        root = Path(tmp)
        openssl_certificates(root)
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(root / "server.pem", root / "server.key")
        tls.load_verify_locations(root / "ca.pem")
        tls.verify_mode = ssl.CERT_REQUIRED
        with ThreadingHTTPServer(("127.0.0.1", 0), ReceiptHandler) as server:
            server.socket = tls.wrap_socket(server.socket, server_side=True)
            server.paths, server.digests = [], []
            thread = threading.Thread(target=server.serve_forever)
            thread.start()
            try:
                base = f"https://127.0.0.1:{server.server_port}/api/v1"
                result = subprocess.run([sys.argv[1], "--private-transport", base], cwd=tmp, capture_output=True,
                                        timeout=25, env={**os.environ, "EDR_CONTROL_HTTP2_ENABLED": "0",
                                                        "EDR_CONTROL_HTTP2_REQUIRE": "0", "EDR_CONTROL_HTTP1_FALLBACK": "1"})
                assert b"synthetic-proxy-reflection-must-not-be-logged" not in result.stderr
                if result.returncode:
                    raise RuntimeError(result.stderr.decode(errors="replace")[-2400:])
                assert server.paths == ["/api/v1/ingest/alert-window-result"] * 3
                assert len(set(server.digests)) == 1 and len(server.digests) == 3
            finally:
                server.shutdown()
                thread.join()


if __name__ == "__main__":
    main()
