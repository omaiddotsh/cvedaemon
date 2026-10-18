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

from sev1daemon.log import get_logger
from sev1daemon.models import Advisory, AdvisoryClass, AffectedPackage, SourceKind
from sev1daemon.redact import redact

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
    (
        3,
        """
        -- Retry bookkeeping: advisories whose actions failed or were skipped
        -- stay processed=0 and are re-queued every cycle until they complete
        -- or hit advisory_max_attempts.
        ALTER TABLE advisories ADD COLUMN attempts INTEGER NOT NULL DEFAULT 0;
        ALTER TABLE advisories ADD COLUMN last_error TEXT;

        -- Cross-source dedupe: every id + alias of an advisory whose alert went
        -- out for (ecosystem, package). PYSEC-/GO-/GHSA-/CVE- records for the
        -- same vulnerability share an alias, so the second one is skipped.
        CREATE TABLE IF NOT EXISTS fired_keys (
            key TEXT NOT NULL,
            ecosystem TEXT NOT NULL,
            package TEXT NOT NULL,
            advisory_id TEXT NOT NULL,
            fired_at TEXT NOT NULL,
            PRIMARY KEY (key, ecosystem, package)
        );
        CREATE INDEX IF NOT EXISTS idx_fired_keys_fired_at ON fired_keys(fired_at);

        -- Per-action idempotency lookups on retry.
        CREATE INDEX IF NOT EXISTS idx_action_log_lookup
            ON action_log(advisory_id, ecosystem, package, action_name, status);
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
        try:
            await self._conn.execute("PRAGMA journal_mode=WAL")
            await self._conn.execute("PRAGMA synchronous=NORMAL")
            await self._conn.execute("PRAGMA foreign_keys=ON")
            await self._conn.execute(
                "CREATE TABLE IF NOT EXISTS schema_version "
                "(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)"
            )
            await self._conn.commit()
            await self._run_migrations()
        except BaseException:
            # aiosqlite runs a non-daemon thread per connection; leaving it
            # open after a failed migration keeps the process from exiting,
            # so the daemon would hang instead of failing (and restarting).
            await self.close()
            raise

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
            # One transaction per migration, version row included: SQLite DDL
            # is transactional, so a crash half-way leaves nothing behind. Two
            # commits here would let a crash between them strand an
            # ALTER TABLE without its version row, and every later start would
            # fail on "duplicate column".
            await conn.executescript(
                "BEGIN;\n"
                + sql
                + "\nINSERT INTO schema_version (version, applied_at) "
                + f"VALUES ({int(version)}, '{_now()}');\nCOMMIT;"
            )

    # ---------- advisories ----------

    async def advisory_seen(self, advisory_id: str) -> bool:
        conn = self._require_conn()
        async with conn.execute(
            "SELECT processed FROM advisories WHERE id = ?", (advisory_id,)
        ) as cur:
            row = await cur.fetchone()
        return bool(row and row[0])

    async def upsert_advisory(self, adv: Advisory) -> None:
        await self.upsert_advisories([adv])

    async def upsert_advisories(self, advisories: list[Advisory]) -> None:
        """Store advisories as pending (``processed=0``) in one transaction.

        An existing row keeps its ``processed`` flag and attempt count; only
        the record itself is refreshed.
        """
        if not advisories:
            return
        conn = self._require_conn()
        now = _now()
        await conn.executemany(
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
            [
                (
                    adv.id,
                    adv.source.value,
                    adv.advisory_class.value,
                    adv.cvss,
                    adv.summary,
                    adv.published.isoformat() if adv.published else None,
                    adv.modified.isoformat() if adv.modified else None,
                    # default=str renders datetime fields inside adv.raw deterministically.
                    json.dumps(_advisory_to_dict(adv), default=str),
                    now,
                )
                for adv in advisories
            ],
        )
        await conn.commit()

    async def stored_modified(self, advisory_id: str) -> datetime | None:
        """The ``modified`` stamp of the stored record, or None if unknown."""
        conn = self._require_conn()
        async with conn.execute(
            "SELECT modified FROM advisories WHERE id = ?", (advisory_id,)
        ) as cur:
            row = await cur.fetchone()
        return _parse_stored_dt(row[0]) if row and row[0] else None

    async def unscored_packages(
        self, advisory_id: str, packages: list[tuple[str, str]]
    ) -> list[tuple[str, str]]:
        """The given (ecosystem, name) pairs this advisory has no score row for."""
        if not packages:
            return []
        conn = self._require_conn()
        async with conn.execute(
            "SELECT ecosystem, package FROM processed_packages WHERE advisory_id = ?",
            (advisory_id,),
        ) as cur:
            rows = await cur.fetchall()
        scored = {(str(eco), str(name)) for eco, name in rows}
        return [pkg for pkg in packages if pkg not in scored]

    async def reopen(self, advisory_id: str) -> None:
        """Queue a processed advisory again (upstream added packages to it).

        Scores, fired flags and the action log are kept, so packages that
        already alerted are not sent again; only the new ones are scored.
        """
        conn = self._require_conn()
        await conn.execute(
            "UPDATE advisories SET processed = 0, attempts = 0, last_error = NULL WHERE id = ?",
            (advisory_id,),
        )
        await conn.commit()

    async def mark_processed(self, advisory_id: str) -> None:
        conn = self._require_conn()
        await conn.execute(
            "UPDATE advisories SET processed = 1, last_error = NULL WHERE id = ?",
            (advisory_id,),
        )
        await conn.commit()

    async def record_attempt(self, advisory_id: str, error: str) -> int:
        """Count one unfinished processing attempt; returns the new total."""
        conn = self._require_conn()
        await conn.execute(
            "UPDATE advisories SET attempts = attempts + 1, last_error = ? WHERE id = ?",
            (redact(error)[:1000], advisory_id),
        )
        await conn.commit()
        async with conn.execute(
            "SELECT attempts FROM advisories WHERE id = ?", (advisory_id,)
        ) as cur:
            row = await cur.fetchone()
        return int(row[0]) if row else 0

    async def give_up(self, advisory_id: str, error: str) -> None:
        """Stop retrying: mark processed but keep the reason for operators."""
        conn = self._require_conn()
        await conn.execute(
            "UPDATE advisories SET processed = 1, last_error = ? WHERE id = ?",
            (("gave up: " + redact(error))[:1000], advisory_id),
        )
        await conn.commit()

    async def get_advisory(self, advisory_id: str) -> Advisory | None:
        conn = self._require_conn()
        async with conn.execute(
            "SELECT payload FROM advisories WHERE id = ?", (advisory_id,)
        ) as cur:
            row = await cur.fetchone()
        return advisory_from_payload(json.loads(row[0])) if row else None

    async def reset_for_replay(self, advisory_id: str) -> None:
        """Forget processing state so the advisory is scored and dispatched again.

        action_log is kept: actions that already succeeded stay skipped.
        """
        conn = self._require_conn()
        await conn.execute(
            "UPDATE advisories SET processed = 0, attempts = 0, last_error = NULL WHERE id = ?",
            (advisory_id,),
        )
        await conn.execute("DELETE FROM processed_packages WHERE advisory_id = ?", (advisory_id,))
        await conn.execute("DELETE FROM fired_keys WHERE advisory_id = ?", (advisory_id,))
        await conn.commit()

    async def pending_advisories(
        self, max_attempts: int, exclude: set[str] | None = None, limit: int = 500
    ) -> list[Advisory]:
        """Advisories stored but never finished (processed=0), oldest first.

        These were fetched in an earlier cycle and then interrupted (timeout,
        restart, exception) or left with failed/skipped actions. Sources only
        re-query from their last checkpoint, so without this they'd never be
        picked up again.
        """
        conn = self._require_conn()
        exclude = exclude or set()
        out: list[Advisory] = []
        async with conn.execute(
            "SELECT id, payload FROM advisories WHERE processed = 0 AND attempts < ? "
            "ORDER BY seen_at LIMIT ?",
            (max_attempts, limit),
        ) as cur:
            rows = await cur.fetchall()
        for advisory_id, payload in rows:
            if advisory_id in exclude:
                continue
            try:
                out.append(advisory_from_payload(json.loads(payload)))
            except (KeyError, TypeError, ValueError) as exc:
                log.warning("state.pending_unreadable", advisory=advisory_id, error=str(exc))
        return out

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

    async def prune_advisories(self, retention_days: int) -> int:
        """Delete finished advisories neither seen nor modified within the window.

        Pending (processed=0) rows are kept regardless: they're still owed a
        delivery attempt.
        """
        if retention_days <= 0:
            return 0
        conn = self._require_conn()
        cutoff = (datetime.now(timezone.utc) - timedelta(days=retention_days)).isoformat()
        cur = await conn.execute(
            "DELETE FROM advisories WHERE processed = 1 AND seen_at < ? "
            "AND (modified IS NULL OR modified < ?)",
            (cutoff, cutoff),
        )
        await conn.commit()
        return max(cur.rowcount or 0, 0)

    async def any_key_fired(self, keys: list[str], ecosystem: str, package: str) -> str | None:
        """Advisory id that already alerted for this package under any shared id/alias."""
        if not keys:
            return None
        conn = self._require_conn()
        placeholders = ",".join("?" for _ in keys)
        async with conn.execute(
            f"SELECT advisory_id FROM fired_keys WHERE ecosystem = ? AND package = ? "
            f"AND key IN ({placeholders}) LIMIT 1",
            (ecosystem, package, *keys),
        ) as cur:
            row = await cur.fetchone()
        return str(row[0]) if row else None

    async def record_fired_keys(
        self, keys: list[str], ecosystem: str, package: str, advisory_id: str
    ) -> None:
        conn = self._require_conn()
        ts = _now()
        await conn.executemany(
            "INSERT OR IGNORE INTO fired_keys (key, ecosystem, package, advisory_id, fired_at) "
            "VALUES (?, ?, ?, ?, ?)",
            [(k, ecosystem, package, advisory_id, ts) for k in dict.fromkeys(keys)],
        )
        await conn.commit()

    async def action_succeeded(
        self, advisory_id: str, ecosystem: str, package: str, action_name: str
    ) -> bool:
        """True if this action already ran OK for (advisory, package) — skip on retry."""
        conn = self._require_conn()
        async with conn.execute(
            "SELECT 1 FROM action_log WHERE advisory_id = ? AND ecosystem = ? AND package = ? "
            "AND action_name = ? AND status = 'ok' LIMIT 1",
            (advisory_id, ecosystem, package, action_name),
        ) as cur:
            row = await cur.fetchone()
        return row is not None

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
        await conn.execute("DELETE FROM fired_keys WHERE fired_at < ?", (cutoff,))
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
        been failing consistently. Skipped dispatches (circuit open, rate
        limited, SSRF block) are logged with status ``skipped`` and don't
        count, or an open circuit would keep itself open.
        """
        conn = self._require_conn()
        async with conn.execute(
            "SELECT COUNT(*) FROM action_log "
            "WHERE action_name = ? AND status = 'error' AND ran_at >= ?",
            (action_name, since.isoformat()),
        ) as cur:
            row = await cur.fetchone()
        return int(row[0]) if row else 0

    # ---------- poll state ----------

    async def set_poll_success(self, source: str, at: datetime | None = None) -> None:
        """Advance the source checkpoint.

        ``at`` should be when the fetch *started*: records modified while a
        long fetch was running are then still inside the next query window.
        """
        conn = self._require_conn()
        ts = (at or datetime.now(timezone.utc)).astimezone(timezone.utc).isoformat()
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


def advisory_from_payload(payload: dict[str, Any]) -> Advisory:
    """Inverse of ``_advisory_to_dict`` (the ``advisories.payload`` column)."""

    def _dt(value: str | None) -> datetime | None:
        return _parse_stored_dt(value) if value else None

    return Advisory(
        id=payload["id"],
        source=SourceKind(payload["source"]),
        advisory_class=AdvisoryClass(payload["advisory_class"]),
        cvss=payload.get("cvss"),
        summary=payload.get("summary") or "",
        published=_dt(payload.get("published")),
        modified=_dt(payload.get("modified")),
        affected=[
            AffectedPackage(ecosystem=p["ecosystem"], name=p["name"])
            for p in payload.get("affected", [])
        ],
        aliases=list(payload.get("aliases", [])),
        references=list(payload.get("references", [])),
    )


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


__all__ = ["StateStore", "advisory_from_payload"]
