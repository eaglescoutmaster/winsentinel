"""SQLite cache that makes the files module resumable and incremental.

A file whose (path, size, mtime, rules_version) is already recorded is not
re-read; its cached findings are replayed. An interrupted scan therefore
fast-forwards through everything it already covered.
"""
from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path


class State:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(str(path), check_same_thread=False)
        self._lock = threading.Lock()
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=NORMAL")
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS files("
            "path TEXT PRIMARY KEY, size INTEGER, mtime_ns INTEGER, rules TEXT, result TEXT)"
        )
        self._pending = 0

    def get(self, path: str, size: int, mtime_ns: int, rules: str):
        with self._lock:
            row = self._db.execute(
                "SELECT result FROM files WHERE path=? AND size=? AND mtime_ns=? AND rules=?",
                (path, size, mtime_ns, rules),
            ).fetchone()
        return json.loads(row[0]) if row else None

    def put(self, path: str, size: int, mtime_ns: int, rules: str, result) -> None:
        with self._lock:
            self._db.execute(
                "INSERT OR REPLACE INTO files VALUES(?,?,?,?,?)",
                (path, size, mtime_ns, rules, json.dumps(result)),
            )
            self._pending += 1
            if self._pending >= 500:
                self._db.commit()
                self._pending = 0

    def close(self) -> None:
        with self._lock:
            self._db.commit()
            self._db.close()
