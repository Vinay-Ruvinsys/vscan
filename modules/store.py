"""Tiny SQLite store for scan history (needed for the dashboard and regression reports)."""
from __future__ import annotations

import json
import os
import sqlite3
import threading
from datetime import datetime, timezone

DB_PATH = os.environ.get("SCAN_DB", "scans.db")
_lock = threading.Lock()
JSON_COLS = ("modules", "summary", "report")


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _conn():
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    return c


def init():
    with _lock, _conn() as c:
        c.execute("""CREATE TABLE IF NOT EXISTS scans (
            id TEXT PRIMARY KEY, target TEXT, modules TEXT, status TEXT, progress TEXT,
            created_at TEXT, finished_at TEXT, score INTEGER, summary TEXT, report TEXT,
            error TEXT, requested_by TEXT)""")
        c.execute("UPDATE scans SET status='failed', error='Server restarted during scan' WHERE status IN ('queued','running')")


def _row(r, with_report=True):
    d = dict(r)
    for k in JSON_COLS:
        if k in d and d[k]:
            if k == "report" and not with_report:
                d.pop("report")
                continue
            d[k] = json.loads(d[k])
    return d


def create(scan_id, target, modules, requested_by=""):
    with _lock, _conn() as c:
        c.execute("INSERT INTO scans (id,target,modules,status,progress,created_at,requested_by) VALUES (?,?,?,?,?,?,?)",
                  (scan_id, target, json.dumps(sorted(modules)), "queued", "Waiting for a free worker", now(), requested_by))


def update(scan_id, **fields):
    for k in JSON_COLS:
        if k in fields and fields[k] is not None:
            fields[k] = json.dumps(fields[k])
    cols = ", ".join(f"{k}=?" for k in fields)
    with _lock, _conn() as c:
        c.execute(f"UPDATE scans SET {cols} WHERE id=?", (*fields.values(), scan_id))


def get(scan_id):
    with _lock, _conn() as c:
        r = c.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
    return _row(r) if r else None


def list_scans(limit=100):
    with _lock, _conn() as c:
        rows = c.execute("SELECT * FROM scans ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
    return [_row(r, with_report=False) for r in rows]


def previous_completed(target, modules, exclude_id):
    """Latest finished scan of the same target with the same module set (a fair baseline)."""
    with _lock, _conn() as c:
        r = c.execute("SELECT * FROM scans WHERE target=? AND modules=? AND status='done' AND id!=? "
                      "ORDER BY created_at DESC LIMIT 1",
                      (target, json.dumps(sorted(modules)), exclude_id)).fetchone()
    return _row(r) if r else None


def score_history():
    with _lock, _conn() as c:
        rows = c.execute("SELECT id,target,created_at,score,summary FROM scans "
                         "WHERE status='done' AND score IS NOT NULL ORDER BY created_at").fetchall()
    return [_row(r) for r in rows]
