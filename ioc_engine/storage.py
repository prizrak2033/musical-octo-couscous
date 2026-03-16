"""SQLite-backed storage for IOCs."""

from __future__ import annotations

import json
import logging
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Generator, List, Optional

from .models import IOC, IOCType, Severity

logger = logging.getLogger(__name__)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS iocs (
    id          TEXT PRIMARY KEY,
    ioc_type    TEXT NOT NULL,
    value       TEXT NOT NULL,
    source      TEXT NOT NULL,
    confidence  INTEGER NOT NULL DEFAULT 50,
    severity    TEXT NOT NULL DEFAULT 'medium',
    tags        TEXT NOT NULL DEFAULT '[]',
    description TEXT NOT NULL DEFAULT '',
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    metadata    TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_iocs_value    ON iocs(value);
CREATE INDEX IF NOT EXISTS idx_iocs_type     ON iocs(ioc_type);
CREATE INDEX IF NOT EXISTS idx_iocs_source   ON iocs(source);
"""


class IOCStorage:
    """Thread-safe SQLite storage for IOCs."""

    def __init__(self, db_path: str = ":memory:") -> None:
        self.db_path = db_path
        self._conn: Optional[sqlite3.Connection] = None
        self._init_db()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _connect(self) -> sqlite3.Connection:
        if self.db_path == ":memory:":
            if self._conn is None:
                self._conn = sqlite3.connect(":memory:", check_same_thread=False)
                self._conn.row_factory = sqlite3.Row
            return self._conn
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    @contextmanager
    def _cursor(self) -> Generator[sqlite3.Cursor, None, None]:
        conn = self._connect()
        cur = conn.cursor()
        try:
            yield cur
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            if self.db_path != ":memory:":
                conn.close()

    def _init_db(self) -> None:
        with self._cursor() as cur:
            cur.executescript(_SCHEMA)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def upsert(self, ioc: IOC) -> None:
        """Insert or update an IOC (merges tags, updates last_seen)."""
        uid = ioc.unique_id
        with self._cursor() as cur:
            cur.execute("SELECT tags, first_seen FROM iocs WHERE id = ?", (uid,))
            existing = cur.fetchone()
            if existing:
                merged_tags = list(
                    set(json.loads(existing["tags"])) | set(ioc.tags)
                )
                cur.execute(
                    """UPDATE iocs
                       SET value=?, source=?, confidence=?, severity=?, tags=?,
                           description=?, last_seen=?, metadata=?
                     WHERE id=?""",
                    (
                        ioc.value,
                        ioc.source,
                        ioc.confidence,
                        ioc.severity.value,
                        json.dumps(merged_tags),
                        ioc.description,
                        ioc.last_seen.isoformat(),
                        json.dumps(ioc.metadata),
                        uid,
                    ),
                )
            else:
                cur.execute(
                    """INSERT INTO iocs
                       (id, ioc_type, value, source, confidence, severity,
                        tags, description, first_seen, last_seen, metadata)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        uid,
                        ioc.ioc_type.value,
                        ioc.value,
                        ioc.source,
                        ioc.confidence,
                        ioc.severity.value,
                        json.dumps(ioc.tags),
                        ioc.description,
                        ioc.first_seen.isoformat(),
                        ioc.last_seen.isoformat(),
                        json.dumps(ioc.metadata),
                    ),
                )

    def bulk_upsert(self, iocs: List[IOC]) -> int:
        """Upsert multiple IOCs; returns number processed."""
        for ioc in iocs:
            self.upsert(ioc)
        return len(iocs)

    def lookup(self, value: str) -> Optional[IOC]:
        """Return the first IOC matching *value* (case-insensitive)."""
        value = value.strip().lower()
        with self._cursor() as cur:
            cur.execute("SELECT * FROM iocs WHERE value = ?", (value,))
            row = cur.fetchone()
        if row is None:
            return None
        return self._row_to_ioc(row)

    def lookup_many(self, values: List[str]) -> List[IOC]:
        """Return all IOCs whose value appears in *values*."""
        normalised = [v.strip().lower() for v in values]
        # Build placeholder string from parameterised markers — no user data in SQL text
        placeholders = ",".join("?" * len(normalised))
        query = "SELECT * FROM iocs WHERE value IN (" + placeholders + ")"
        with self._cursor() as cur:
            cur.execute(query, normalised)
            rows = cur.fetchall()
        return [self._row_to_ioc(r) for r in rows]

    def list_all(
        self,
        ioc_type: Optional[IOCType] = None,
        source: Optional[str] = None,
        min_confidence: int = 0,
    ) -> List[IOC]:
        """List IOCs with optional filters."""
        query = "SELECT * FROM iocs WHERE confidence >= ?"
        params: list = [min_confidence]
        if ioc_type:
            query += " AND ioc_type = ?"
            params.append(ioc_type.value)
        if source:
            query += " AND source = ?"
            params.append(source)
        with self._cursor() as cur:
            cur.execute(query, params)
            rows = cur.fetchall()
        return [self._row_to_ioc(r) for r in rows]

    def count(self) -> int:
        with self._cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM iocs")
            return cur.fetchone()[0]

    def delete(self, value: str) -> bool:
        """Delete IOC by value; returns True if a row was removed."""
        value = value.strip().lower()
        with self._cursor() as cur:
            cur.execute("DELETE FROM iocs WHERE value = ?", (value,))
            return cur.rowcount > 0

    def clear(self) -> None:
        with self._cursor() as cur:
            cur.execute("DELETE FROM iocs")

    # ------------------------------------------------------------------
    # Row → model
    # ------------------------------------------------------------------

    @staticmethod
    def _row_to_ioc(row: sqlite3.Row) -> IOC:
        return IOC(
            ioc_type=IOCType(row["ioc_type"]),
            value=row["value"],
            source=row["source"],
            confidence=row["confidence"],
            severity=Severity(row["severity"]),
            tags=json.loads(row["tags"]),
            description=row["description"],
            first_seen=datetime.fromisoformat(row["first_seen"]),
            last_seen=datetime.fromisoformat(row["last_seen"]),
            metadata=json.loads(row["metadata"]),
        )
