#!/usr/bin/env python3
"""
将平台 GET /api/v1/internal/tip/ioc/delta 的 JSON 应用到本地 AVE ioc.db（SQLite）。

依赖：Python 3.9+（stdlib only）。

示例：
  export EDR_TIP_BASE=https://platform.example.com
  export EDR_INTERNAL_TIP_KEY=...
  export EDR_TENANT_ID=tenant-1
  export EDR_IOC_DB_PATH=/var/lib/edr/ioc.db
  curl -fsS -H "X-EDR-Internal-Key: $EDR_INTERNAL_TIP_KEY" \
    "$EDR_TIP_BASE/api/v1/internal/tip/ioc/delta?tenant_id=$EDR_TENANT_ID&since_version=0&full=1" \
    | ./tip_ioc_delta_apply.py

首次同步用 full=1；之后用 since_version=<上次的 bundle_version>。
"""
from __future__ import annotations

import json
import os
import sqlite3
import sys


def sev_to_int(sev: str) -> int:
    s = (sev or "").lower().strip()
    if s in ("critical", "high"):
        return 3
    if s in ("medium",):
        return 2
    return 1


def ensure_schema(con: sqlite3.Connection) -> None:
    con.executescript(
        """
        CREATE TABLE IF NOT EXISTS ioc_file_hash (
          sha256 TEXT PRIMARY KEY,
          is_active INTEGER NOT NULL DEFAULT 1,
          severity INTEGER DEFAULT 3
        );
        CREATE TABLE IF NOT EXISTS ioc_ip (
          ip TEXT PRIMARY KEY,
          is_active INTEGER NOT NULL DEFAULT 1
        );
        CREATE TABLE IF NOT EXISTS ioc_domain (
          domain TEXT PRIMARY KEY,
          is_active INTEGER NOT NULL DEFAULT 1
        );
        """
    )


def apply_payload(con: sqlite3.Connection, data: dict) -> None:
    items = data.get("items") or []
    removed = data.get("removed") or []
    cur = con.cursor()
    for it in items:
        if it.get("deleted"):
            continue
        typ = (it.get("ioc_type") or "").lower().strip()
        val = (it.get("ioc_value") or "").strip()
        if not typ or not val:
            continue
        sev = sev_to_int(str(it.get("severity") or "medium"))
        if typ == "sha256":
            cur.execute(
                "INSERT OR REPLACE INTO ioc_file_hash (sha256, is_active, severity) VALUES (?, 1, ?)",
                (val.lower(), sev),
            )
        elif typ == "ip":
            cur.execute(
                "INSERT OR REPLACE INTO ioc_ip (ip, is_active) VALUES (?, 1)",
                (val.lower(),),
            )
        elif typ == "domain":
            cur.execute(
                "INSERT OR REPLACE INTO ioc_domain (domain, is_active) VALUES (?, 1)",
                (val.lower(),),
            )
    for it in removed:
        if not it.get("deleted"):
            continue
        typ = (it.get("ioc_type") or "").lower().strip()
        val = (it.get("ioc_value") or "").strip()
        if typ == "sha256":
            cur.execute("DELETE FROM ioc_file_hash WHERE sha256 = ?", (val.lower(),))
        elif typ == "ip":
            cur.execute("DELETE FROM ioc_ip WHERE ip = ?", (val.lower(),))
        elif typ == "domain":
            cur.execute("DELETE FROM ioc_domain WHERE domain = ?", (val.lower(),))
    con.commit()


def main() -> int:
    raw = sys.stdin.read()
    if not raw.strip():
        print("empty stdin", file=sys.stderr)
        return 2
    data = json.loads(raw)
    path = os.environ.get("EDR_IOC_DB_PATH", "").strip()
    if not path:
        print("set EDR_IOC_DB_PATH to ioc.db", file=sys.stderr)
        return 2
    con = sqlite3.connect(path)
    try:
        ensure_schema(con)
        apply_payload(con, data)
    finally:
        con.close()
    ver = data.get("bundle_version")
    print(f"ok bundle_version={ver}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
