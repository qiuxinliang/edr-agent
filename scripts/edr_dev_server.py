#!/usr/bin/env python3
"""
EDR Agent 开发/调试用 HTTP 服务器。
为 Agent 提供稳定的 /api/v1/agent/rules.toml 和 /api/v1/agent/p0-bundle.enc 端点。

用法:
    python3 scripts/edr_dev_server.py                  # 默认 0.0.0.0:8080
    python3 scripts/edr_dev_server.py --port 9090       # 指定端口
    python3 scripts/edr_dev_server.py --config-dir ./config  # 指定规则目录
"""

import http.server
import os
import sys
import json
import argparse
import time
import base64
import threading
from io import BytesIO
from collections import defaultdict


class EdrDevHandler(http.server.BaseHTTPRequestHandler):
    # --- 配置 (由 server 启动前注入) ---
    rules_toml_path = None
    p0_bundle_path = None
    rules_version = None

    # --- 内存指令队列 (endpoint_id -> list of command dicts) ---
    _cmd_queue = defaultdict(list)
    _cmd_lock = threading.Lock()

    def log_message(self, format, *args):
        print(f"[edr-server] {self.client_address[0]} {format % args}")

    def _send_json(self, code, body):
        data = json.dumps(body, ensure_ascii=False, separators=(',', ':')).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _send_file(self, path, content_type, extra_headers=None):
        if not os.path.isfile(path):
            self._send_json(500, {"code": "INTERNAL_ERROR", "message": f"file not found: {os.path.basename(path)}"})
            return
        try:
            with open(path, "rb") as f:
                data = f.read()
        except OSError as e:
            self._send_json(500, {"code": "INTERNAL_ERROR", "message": f"failed to read file: {e}"})
            return

        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Rules-Version", self.rules_version)
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def _handle_agent_rules_toml(self):
        """GET / HEAD /api/v1/agent/rules.toml"""
        if self.command == "HEAD":
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("X-Rules-Version", self.rules_version)
            self.end_headers()
            return
        self._send_file(self.rules_toml_path, "application/octet-stream")

    def _handle_agent_p0_bundle(self):
        """GET / HEAD /api/v1/agent/p0-bundle.enc"""
        if self.command == "HEAD":
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.end_headers()
            return
        self._send_file(self.p0_bundle_path, "application/octet-stream",
                        extra_headers={"X-P0-Bundle-Version": "v1"})

    def _handle_ingest_heartbeat(self):
        """POST /api/v1/ingest/heartbeat"""
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length > 0 else b""
        self._send_json(200, {"code": "OK", "message": "heartbeat received"})

    def _handle_ingest_report_events(self):
        """POST /api/v1/ingest/report-events"""
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length > 0 else b""
        self._send_json(200, {"code": "OK", "message": f"events received ({len(body)} bytes)"})

    def _handle_ingest_report_command_result(self):
        """POST /api/v1/ingest/report-command-result"""
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length > 0 else b""
        print(f"[edr-server] report-command-result: {body.decode('utf-8', errors='replace')[:500]}")
        self._send_json(200, {"code": "OK", "message": "command result received"})

    def _handle_ingest_poll_commands(self):
        """GET /api/v1/ingest/poll-commands"""
        from urllib.parse import urlparse, parse_qs
        query = parse_qs(urlparse(self.path).query)
        endpoint_ids = query.get("endpoint_id", [])
        limit_str = query.get("limit", ["8"])
        limit = int(limit_str[0]) if limit_str else 8

        commands = []
        with self._cmd_lock:
            for eid in endpoint_ids:
                q = self._cmd_queue.get(eid, [])
                if q:
                    take = min(limit - len(commands), len(q))
                    commands.extend(q[:take])
                    self._cmd_queue[eid] = q[take:]
                    if len(commands) >= limit:
                        break

        self._send_json(200, {"commands": commands})
        if commands:
            print(f"[edr-server] poll response endpoint={endpoint_ids} returning {len(commands)} commands")

    def _handle_ingest_upload_file(self):
        """POST /api/v1/ingest/upload-file"""
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length > 0 else b""
        self._send_json(200, {"code": "OK", "upload_id": "fake-upload-001"})

    def _handle_dev_commands(self):
        """POST /dev/commands — 向指定端点下发指令"""
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length > 0 else b"{}"
        try:
            req = json.loads(body)
        except json.JSONDecodeError as e:
            self._send_json(400, {"code": "INVALID_ARGUMENT", "message": str(e)})
            return

        endpoint_id = req.get("endpoint_id", "").strip()
        command_type = req.get("command_type", "").strip()
        payload = req.get("payload", {})
        session_id = req.get("session_id", "")
        input_cmd = req.get("input", "")

        if not endpoint_id or not command_type:
            self._send_json(400, {"code": "INVALID_ARGUMENT",
                                  "message": "endpoint_id and command_type are required"})
            return

        if command_type in ("shell_open", "forensic_deep"):
            if isinstance(payload, dict):
                payload_bytes = json.dumps(payload).encode("utf-8")
            else:
                payload_bytes = str(payload).encode("utf-8")
        elif command_type == "shell_input":
            payload_bytes = json.dumps({"session_id": session_id or "0", "input": input_cmd}).encode("utf-8")
        elif command_type == "shell_close":
            payload_bytes = json.dumps({"session_id": session_id or "0"}).encode("utf-8")
        else:
            payload_bytes = json.dumps(payload).encode("utf-8") if isinstance(payload, dict) else str(payload).encode("utf-8")

        task_id = f"cmd_{command_type}_{int(time.time() * 1000000)}"
        cmd_obj = {
            "command_id": task_id,
            "command_type": command_type,
            "payload_b64": base64.b64encode(payload_bytes).decode("ascii"),
            "idempotency_key": task_id,
            "issued_at_unix_ms": str(int(time.time() * 1000)),
        }

        with self._cmd_lock:
            self._cmd_queue[endpoint_id].append(cmd_obj)

        print(f"[edr-server] enqueued {command_type} → endpoint={endpoint_id} task_id={task_id}")
        self._send_json(200, {"code": "OK", "task_id": task_id, "status": "queued"})

    # --- 路由表 ---
    ROUTES = {
        ("GET", "/api/v1/agent/rules.toml"): "_handle_agent_rules_toml",
        ("HEAD", "/api/v1/agent/rules.toml"): "_handle_agent_rules_toml",
        ("GET", "/api/v1/agent/p0-bundle.enc"): "_handle_agent_p0_bundle",
        ("HEAD", "/api/v1/agent/p0-bundle.enc"): "_handle_agent_p0_bundle",
        ("POST", "/api/v1/ingest/heartbeat"): "_handle_ingest_heartbeat",
        ("POST", "/api/v1/ingest/report-events"): "_handle_ingest_report_events",
        ("POST", "/api/v1/ingest/report-command-result"): "_handle_ingest_report_command_result",
        ("GET", "/api/v1/ingest/poll-commands"): "_handle_ingest_poll_commands",
        ("POST", "/api/v1/ingest/upload-file"): "_handle_ingest_upload_file",
        ("POST", "/dev/commands"): "_handle_dev_commands",
    }

    def do_GET(self):
        self._dispatch("GET")

    def do_HEAD(self):
        self._dispatch("HEAD")

    def do_POST(self):
        self._dispatch("POST")

    def _dispatch(self, method):
        # 标准化路径 (去掉 query string)
        path = self.path.split("?")[0]
        handler_name = self.ROUTES.get((method, path))
        if handler_name:
            handler = getattr(self, handler_name, None)
            if handler:
                handler()
                return
        # 根路径
        if path == "/" or path == "/api/v1" or path == "/api/v1/":
            self._send_json(200, {"code": "OK", "message": "EDR dev server running"})
            return
        self._send_json(404, {"code": "NOT_FOUND", "message": "route not found", "path": path})


def configure_handler(config_dir):
    rules_toml = os.path.join(config_dir, "agent_preprocess_rules_v1.toml")
    p0_bundle = os.path.join(config_dir, "p0_rule_bundle_ir_v1.json.enc")
    version = "edr-dynamic-rules-v1-r218-9ae52519"
    if os.path.isfile(rules_toml):
        try:
            with open(rules_toml, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("rules_version") and "=" in line:
                        version = line.split("=", 1)[1].strip().strip('"')
                        break
        except OSError:
            pass

    EdrDevHandler.rules_toml_path = rules_toml
    EdrDevHandler.p0_bundle_path = p0_bundle
    EdrDevHandler.rules_version = version
    return EdrDevHandler


def main():
    parser = argparse.ArgumentParser(description="EDR Agent 开发 HTTP 服务器")
    parser.add_argument("--port", type=int, default=8080, help="监听端口 (默认 8080)")
    parser.add_argument("--bind", type=str, default="0.0.0.0", help="绑定地址 (默认 0.0.0.0)")
    parser.add_argument("--config-dir", type=str, default=None,
                        help="规则文件目录 (默认自动检测)")
    args = parser.parse_args()

    # 自动检测 config 目录
    if args.config_dir:
        config_dir = os.path.abspath(args.config_dir)
    else:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        repo_root = os.path.dirname(script_dir)
        config_dir = os.path.join(repo_root, "config")

    rules_toml = os.path.join(config_dir, "agent_preprocess_rules_v1.toml")

    print("=" * 60)
    print("EDR Agent 开发 HTTP 服务器")
    print("=" * 60)
    print(f"  监听地址: http://{args.bind}:{args.port}")
    print(f"  规则目录: {config_dir}")
    print(f"  rules.toml: {rules_toml}")
    if not os.path.isfile(rules_toml):
        print(f"  ⚠️  警告: rules.toml 不存在!")
    print()
    print("端点:")
    print(f"  GET  /api/v1/agent/rules.toml")
    print(f"  GET  /api/v1/agent/p0-bundle.enc")
    print(f"  POST /api/v1/ingest/heartbeat")
    print(f"  POST /api/v1/ingest/report-events")
    print(f"  POST /api/v1/ingest/report-command-result")
    print(f"  GET  /api/v1/ingest/poll-commands")
    print(f"  POST /api/v1/ingest/upload-file")
    print(f"  POST /dev/commands   ← 手动下发指令")
    print("=" * 60)

    handler = configure_handler(config_dir)
    server = http.server.HTTPServer((args.bind, args.port), handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[edr-server] 关闭中...")
        server.shutdown()


if __name__ == "__main__":
    main()
