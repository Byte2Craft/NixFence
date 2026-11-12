"""Small local SQLite store; passwords and private keys are never stored in it."""
from __future__ import annotations

import json
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

SCHEMA = """
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS hosts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    address TEXT NOT NULL,
    ssh_port INTEGER NOT NULL,
    ssh_user TEXT NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    csrf_token TEXT NOT NULL,
    expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS login_failures (
    address TEXT PRIMARY KEY,
    attempts INTEGER NOT NULL,
    locked_until INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS operations (
    id TEXT PRIMARY KEY,
    host_id INTEGER NOT NULL REFERENCES hosts(id),
    kind TEXT NOT NULL CHECK (kind IN ('firewall_port', 'selinux_boolean')),
    target TEXT NOT NULL,
    desired TEXT NOT NULL,
    before_runtime INTEGER NOT NULL,
    before_permanent INTEGER,
    status TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    detail TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at INTEGER NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    host_id INTEGER,
    detail TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS operations_host_status ON operations(host_id, status);
"""


class Database:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            db.executescript(SCHEMA)
            db.execute("PRAGMA journal_mode=WAL")

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("PRAGMA busy_timeout=10000")
        try:
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def rows(self, sql: str, params: tuple = ()) -> list[dict[str, Any]]:
        with self.connect() as db:
            return [dict(row) for row in db.execute(sql, params).fetchall()]

    def one(self, sql: str, params: tuple = ()) -> dict[str, Any] | None:
        rows = self.rows(sql, params)
        return rows[0] if rows else None

    def execute(self, sql: str, params: tuple = ()) -> int:
        with self.connect() as db:
            return db.execute(sql, params).lastrowid

    def audit(self, action: str, *, host_id: int | None = None, detail: dict | None = None) -> None:
        self.execute("INSERT INTO audit (created_at, actor, action, host_id, detail) VALUES (?,?,?,?,?)",
                     (int(time.time()), "admin", action, host_id, json.dumps(detail or {}, sort_keys=True)))

    def lock_host(self, host_id: int, record: dict) -> None:
        """Atomically prevent concurrent operations on one host."""
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            active = db.execute(
                "SELECT id FROM operations WHERE host_id=? AND status IN ('staging','pending','confirming','reverting','needs_review')",
                (host_id,),
            ).fetchone()
            if active:
                raise ValueError(f"Host has an unresolved operation: {active['id']}")
            db.execute(
                """INSERT INTO operations (id,host_id,kind,target,desired,before_runtime,before_permanent,
                   status,expires_at,created_at,detail) VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (record["id"], host_id, record["kind"], record["target"], record["desired"],
                 int(record["before_runtime"]), record.get("before_permanent"), "staging",
                 record["expires_at"], int(time.time()), ""),
            )
