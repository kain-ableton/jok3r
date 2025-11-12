#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations
import sqlite3, json
from typing import Any, Dict

class DB:
    def __init__(self, path: str):
        self.path = path
        self.conn = sqlite3.connect(self.path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self):
        cur = self.conn.cursor()
        cur.execute("CREATE TABLE IF NOT EXISTS runs (id INTEGER PRIMARY KEY AUTOINCREMENT, mission_id TEXT, started TEXT, finished TEXT)")
        cur.execute("CREATE TABLE IF NOT EXISTS assets (id INTEGER PRIMARY KEY AUTOINCREMENT, run_id INTEGER, uri TEXT, kind TEXT, UNIQUE(run_id, uri))")
        cur.execute("CREATE TABLE IF NOT EXISTS findings (id INTEGER PRIMARY KEY AUTOINCREMENT, run_id INTEGER, asset_id INTEGER, tool TEXT, severity TEXT, title TEXT, description TEXT, reference TEXT, raw JSON)")
        self.conn.commit()

    def start_run(self, mission_id: str) -> int:
        cur = self.conn.cursor()
        cur.execute("INSERT INTO runs (mission_id, started) VALUES (?, datetime('now'))", (mission_id,))
        self.conn.commit()
        return cur.lastrowid

    def finish_run(self, run_id: int):
        cur = self.conn.cursor()
        cur.execute("UPDATE runs SET finished=datetime('now') WHERE id=?", (run_id,))
        self.conn.commit()

    def upsert_asset(self, run_id: int, uri: str, kind: str = "http") -> int:
        cur = self.conn.cursor()
        cur.execute("INSERT OR IGNORE INTO assets (run_id, uri, kind) VALUES (?,?,?)", (run_id, uri, kind))
        self.conn.commit()
        cur.execute("SELECT id FROM assets WHERE run_id=? AND uri=?", (run_id, uri))
        row = cur.fetchone()
        return row["id"] if row else None

    def add_finding(self, run_id: int, asset_id: int, tool: str, severity: str, title: str, description: str, reference: str, raw: Dict[str, Any]):
        cur = self.conn.cursor()
        cur.execute("INSERT INTO findings (run_id, asset_id, tool, severity, title, description, reference, raw) VALUES (?,?,?,?,?,?,?,?)",
                    (run_id, asset_id, tool, severity, title, description, reference, json.dumps(raw)))
        self.conn.commit()

    def ingest_tool_result(self, run_id: int, tr):
        tool = getattr(tr, "name", "unknown")
        meta = getattr(tr, "meta", {}) or {}
        target = meta.get("target") or meta.get("uri") or meta.get("host") or "unknown"

        if "nuclei" in (tool or "").lower():
            for line in tr.stdout.splitlines():
                try:
                    obj = json.loads(line)
                except Exception:
                    continue
                uri = obj.get("matched-at") or obj.get("host") or target
                aid = self.upsert_asset(run_id, uri, kind="http")
                info = obj.get("info", {}) or {}
                tpl = obj.get("template-id") or obj.get("template") or ""
                sev = str(obj.get("severity") or info.get("severity") or "info")
                title = info.get("name") or tpl
                desc = info.get("description") or ""
                self.add_finding(run_id, aid, "nuclei", sev, title, desc, tpl, obj)
            return

        if "httpx" in (tool or "").lower():
            for line in tr.stdout.splitlines():
                try:
                    obj = json.loads(line)
                except Exception:
                    continue
                uri = obj.get("url") or target
                aid = self.upsert_asset(run_id, uri, kind="http")
                status = obj.get("status-code")
                title = obj.get("title") or ""
                tech = obj.get("tech") or []
                if status:
                    self.add_finding(run_id, aid, "httpx", "info", f"HTTP {status}", title, ",".join(tech) if tech else "", obj)
            return

        aid = self.upsert_asset(run_id, target, kind="misc")
        self.add_finding(run_id, aid, tool, "info", f"{tool} output", tr.stdout[:2000], "", {"stdout": tr.stdout, "stderr": tr.stderr, "meta": meta})
