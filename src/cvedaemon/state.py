"""SQLite state store. WAL mode, schema-versioned migrations, aiosqlite async.

State lives in a single SQLite file (path from ``Config.state_db``). The DB is
opened in WAL mode so concurrent readers (e.g. health/metrics) don't block the
poll loop's writers. A 30s lock timeout absorbs the brief windows where two
coroutines both need a write transaction.

Schema is migration-driven: the ``schema_version`` table tracks the highest
applied migration, and ``_MIGRATIONS`` is an ordered list of (version, sql)
tuples. Adding a new migration is append-only — never edit an existing one.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import aiosqlite

from cvedaemon.log import get_logger
from cvedaemon.models import Advisory
from cvedaemon.redact import redact

log = get_logger("state")


# Migration list. Each entry is (version, sql_block). Versions must be strictly
# increasing. The runner applies any migration whose version exceeds the value
# in schema_version, in order, inside a single transaction per migration.
_MIGRATIONS: list[tuple[int, str]] = [
    (
        1,
        """
        CREATE TABLE IF NOT EXISTS advisories (
            id TEXT PRIMARY KEY,
            source TEXT NOT NULL,
            advisory_class TEXT NOT NULL,
            cvss REAL,
            summary TEXT,
            published TEXT,
            modified TEXT,
            payload TEXT NOT NULL,
            processed INTEGER NOT NULL DEFAULT 0,
            seen_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS processed_packages (
            advisory_id TEXT NOT NULL,
            ecosystem TEXT NOT NULL,
            package TEXT NOT NULL,
            score REAL NOT NULL,
            breakdown TEXT,
            fired INTEGER NOT NULL DEFAULT 0,
            recorded_at TEXT NOT NULL,
            PRIMARY KEY (advisory_id, ecosystem, package)
        );

        CREATE TABLE IF NOT EXISTS action_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            advisory_id TEXT NOT NULL,
            ecosystem TEXT,
            package TEXT,
            action_name TEXT NOT NULL,
            action_type TEXT NOT NULL,
            status TEXT NOT NULL,
            detail TEXT,
            ran_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_action_log_ran_at ON action_log(ran_at);

        CREATE TABLE IF NOT EXISTS poll_state (
            source TEXT PRIMARY KEY,
            last_success TEXT,
            last_attempt TEXT,
            last_error TEXT
        );
        """,
    ),
    (
        2,
        """
        CREATE INDEX IF NOT EXISTS idx_processed_packages_recorded_at
            ON processed_packages(recorded_at);
        """,
    ),
]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class StateStore:
    """Async wrapper around aiosqlite with migration runner."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._conn: aiosqlite.Connection | None = None

    async def open(self) -> None:
        parent = self.path.parent
        parent.mkdir(parents=True, exist_ok=True)
        if not os.access(parent, os.W_OK):
            raise PermissionError(f"state_db parent directory not writable: {parent}")
        # 30s lock timeout: WAL still serializes writers, and burst dispatch +
        # housekeeping can briefly contend. Default 5s tripped under load.
        self._conn = await aiosqlite.connect(self.path, timeout=30.0)
        await self._conn.execute("PRAGMA journal_mode=WAL")
        await self._conn.execute("PRAGMA synchronous=NORMAL")
        await self._conn.execute("PRAGMA foreign_keys=ON")
        await self._conn.execute(
            "CREATE TABLE IF NOT EXISTS schema_version "
            "(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)"
        )
        await self._conn.commit()
        await self._run_migrations()

    async def close(self) -> None:
        if self._conn is not None:
            await self._conn.close()
            self._conn = None

    def _require_conn(self) -> aiosqlite.Connection:
        if self._conn is None:
            raise RuntimeError("StateStore not opened; call open() first")
        return self._conn

    async def _run_migrations(self) -> None:
        conn = self._require_conn()
        async with conn.execute("SELECT COALESCE(MAX(version), 0) FROM schema_version") as cur:
            row = await cur.fetchone()
        current = int(row[0]) if row else 0
        for version, sql in _MIGRATIONS:
            if version <= current:
                continue
            log.info("state.migration_apply", version=version)
            await conn.executescript(sql)
            await conn.execute(
                "INSERT INTO schema_version (version, applied_at) VALUES (?, ?)",
                (version, _now()),
            )
            await conn.commit()

    # ---------- advisories ----------

    async def advisory_seen(self, advisory_id: str) -> bool:
        conn = self._require_conn()
        async with conn.execute(
            "SELECT processed FROM advisories WHERE id = ?", (advisory_id,)
        ) as cur:
            row = await cur.fetchone()
        return bool(row and row[0])

    async def upsert_advisory(self, adv: Advisory) -> None:
        # default=str renders datetime fields inside adv.raw deterministically.
        payload = json.dumps(_advisory_to_dict(adv), default=str)
        conn = self._require_conn()
        await conn.execute(
            """
            INSERT INTO advisories (id, source, advisory_class, cvss, summary,
                                    published, modified, payload, processed, seen_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?)
            ON CONFLICT(id) DO UPDATE SET
                cvss=excluded.cvss,
                summary=excluded.summary,
                modified=excluded.modified,
                payload=excluded.payload
            """,
            (
                adv.id,
                adv.source.value,
                adv.advisory_class.value,
                adv.cvss,
                adv.summary,
                adv.published.isoformat() if adv.published else None,
                adv.modified.isoformat() if adv.modified else None,
                payload,
                _now(),
            ),
        )
        await conn.commit()

    async def mark_processed(self, advisory_id: str) -> None:
        conn = self._require_conn()
        await conn.execute(
            "UPDATE advisories SET processed = 1 WHERE id = ?", (advisory_id,)
        )
        await conn.commit()

    # ---------- processed packages ----------

    async def package_fired(
        self, advisory_id: str, ecosystem: str, package: str
    ) -> bool:
        """True iff a prior cycle already fired actions for this (adv, pkg) tuple.

        Used by the daemon to skip re-dispatch when a partial-batch retry rolls
        around — without it, an exception mid-loop would re-fire actions for
        every successfully-processed package on the next cycle.
        """
        conn = self._require_conn()
        async with conn.execute(
            "SELECT fired FROM processed_packages "
            "WHERE advisory_id = ? AND ecosystem = ? AND package = ?",
            (advisory_id, ecosystem, package),
        ) as cur:
            row = await cur.fetchone()
        return bool(row and row[0])

    async def record_package_score(
        self,
        advisory_id: str,
        ecosystem: str,
        package: str,
        score: float,
        breakdown: dict[str, Any] | None,
        fired: bool,
    ) -> None:
        conn = self._require_conn()
        await conn.execute(
            """
            INSERT INTO processed_packages (advisory_id, ecosystem, package, score,
                                            breakdown, fired, recorded_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(advisory_id, ecosystem, package) DO UPDATE SET
                score=excluded.score,
                breakdown=excluded.breakdown,
                fired=excluded.fired,
                recorded_at=excluded.recorded_at
            """,
            (
                advisory_id,
                ecosystem,
                package,
                score,
                json.dumps(breakdown) if breakdown else None,
                1 if fired else 0,
                _now(),
            ),
        )
        await conn.commit()

    async def prune_processed_packages(self, retention_days: int) -> int:
        """Delete processed_packages rows older than retention_days.

        Without this the table grows without bound over months of operation;
        each advisory contributes one row per affected package, easily 5–50.
        """
        conn = self._require_conn()
        cutoff = (datetime.now(timezone.utc) - timedelta(days=retention_days)).isoformat()
        cur = await conn.execute(
            "DELETE FROM processed_packages WHERE recorded_at < ?", (cutoff,)
        )
        await conn.commit()
        return max(cur.rowcount or 0, 0)

    # ---------- action log ----------

    async def log_action(
        self,
        advisory_id: str,
        action_name: str,
        action_type: str,
        status: str,
        detail: str,
        ecosystem: str | None = None,
        package: str | None = None,
    ) -> None:
        conn = self._require_conn()
        await conn.execute(
            """
            INSERT INTO action_log (advisory_id, ecosystem, package, action_name,
                                   action_type, status, detail, ran_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                advisory_id,
                ecosystem,
                package,
                action_name,
                action_type,
                status,
                redact(detail),
                _now(),
            ),
        )
        await conn.commit()

    async def prune_action_log(self, retention_days: int) -> int:
        conn = self._require_conn()
        cutoff = (datetime.now(timezone.utc) - timedelta(days=retention_days)).isoformat()
        cur = await conn.execute(
            "DELETE FROM action_log WHERE ran_at < ?", (cutoff,)
        )
        await conn.commit()
        return max(cur.rowcount or 0, 0)

    async def recent_action_failures(
        self, action_name: str, since: datetime
    ) -> int:
        """Count error-status actions for ``action_name`` since the given UTC time.

        Used by the circuit breaker to decide whether to skip an action that's
        been failing consistently.
        """
        conn = self._require_conn()
        async with conn.execute(
            "SELECT COUNT(*) FROM action_log "
            "WHERE action_name = ? AND status != 'ok' AND ran_at >= ?",
            (action_name, since.isoformat()),
        ) as cur:
            row = await cur.fetchone()
        return int(row[0]) if row else 0

    # ---------- poll state ----------

    async def set_poll_success(self, source: str) -> None:
        conn = self._require_conn()
        ts = _now()
        await conn.execute(
            """
            INSERT INTO poll_state (source, last_success, last_attempt, last_error)
            VALUES (?, ?, ?, NULL)
            ON CONFLICT(source) DO UPDATE SET last_success=excluded.last_success,
                                              last_attempt=excluded.last_attempt,
                                              last_error=NULL
            """,
            (source, ts, ts),
        )
        await conn.commit()

    async def set_poll_failure(self, source: str, error: str) -> None:
        conn = self._require_conn()
        ts = _now()
        await conn.execute(
            """
            INSERT INTO poll_state (source, last_success, last_attempt, last_error)
            VALUES (?, NULL, ?, ?)
            ON CONFLICT(source) DO UPDATE SET last_attempt=excluded.last_attempt,
                                              last_error=excluded.last_error
            """,
            (source, ts, redact(error)[:1000]),
        )
        await conn.commit()

    async def get_last_success(self, source: str) -> datetime | None:
        conn = self._require_conn()
        async with conn.execute(
            "SELECT last_success FROM poll_state WHERE source = ?", (source,)
        ) as cur:
            row = await cur.fetchone()
        if row and row[0]:
            # _parse_dt mirrors the write side's isoformat() output.
            return _parse_stored_dt(row[0])
        return None


def _parse_stored_dt(value: str) -> datetime:
    """Parse an ISO-8601 timestamp written by ``_now()``.

    fromisoformat handles offset suffixes but not the trailing ``Z``; we never
    write ``Z`` ourselves, but tolerate it for forward-compatibility.
    """
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    return datetime.fromisoformat(value)


def _advisory_to_dict(adv: Advisory) -> dict[str, Any]:
    return {
        "id": adv.id,
        "source": adv.source.value,
        "advisory_class": adv.advisory_class.value,
        "cvss": adv.cvss,
        "summary": adv.summary,
        "published": adv.published.isoformat() if adv.published else None,
        "modified": adv.modified.isoformat() if adv.modified else None,
        "affected": [{"ecosystem": p.ecosystem, "name": p.name} for p in adv.affected],
        "aliases": adv.aliases,
        "references": adv.references,
    }


__all__ = ["StateStore"]
