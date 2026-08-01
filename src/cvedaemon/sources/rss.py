"""RSS/Atom feed ingestor for supply chain attack early warning.

These advisories bypass scorer entirely. Score forced to 100, always fires.
"""

from __future__ import annotations

import asyncio
import hashlib
import re
from datetime import datetime, timezone
from typing import Any

import feedparser

from cvedaemon.http import HttpClient
from cvedaemon.log import get_logger
from cvedaemon.models import (
    Advisory,
    AdvisoryClass,
    AffectedPackage,
    SourceKind,
)
from cvedaemon.sources.base import Source

log = get_logger("rss")


# Match CVE-2024-1234, GHSA-xxxx-xxxx-xxxx anywhere in text.
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
_GHSA_RE = re.compile(r"\bGHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}\b", re.IGNORECASE)


# Lowercased keyword → canonical ecosystem name.
_ECOSYSTEM_HINTS: dict[str, str] = {
    "npm": "npm",
    "node.js": "npm",
    "node ": "npm",
    "javascript": "npm",
    "pypi": "PyPI",
    "python": "PyPI",
    "pip ": "PyPI",
    "rubygems": "RubyGems",
    "ruby gem": "RubyGems",
    "crate": "crates.io",
    "cargo": "crates.io",
    "rust ": "crates.io",
    "nuget": "NuGet",
    ".net": "NuGet",
    "maven": "Maven",
    "java ": "Maven",
    "golang": "Go",
    "go modules": "Go",
    "composer": "Packagist",
    "php ": "Packagist",
    "packagist": "Packagist",
    "dart": "Pub",
    "flutter": "Pub",
    "elixir": "Hex",
    "swift ": "SwiftURL",
    "github action": "GitHub Actions",
}


class RssSource(Source):
    name = "rss"

    def __init__(
        self,
        http: HttpClient,
        feeds: list[dict[str, str]],
        keywords: list[str],
    ):
        self._http = http
        self._feeds = feeds
        self._keywords = [k.lower() for k in keywords]

    async def fetch(self, since: datetime) -> list[Advisory]:
        if not self._feeds or not self._keywords:
            return []
        out: list[Advisory] = []
        for feed in self._feeds:
            try:
                advisories = await self._fetch_feed(feed, since)
            except Exception as exc:
                log.warning("rss.feed_failed", name=feed.get("name"), error=str(exc))
                continue
            out.extend(advisories)
        return out

    async def _fetch_feed(self, feed: dict[str, str], since: datetime) -> list[Advisory]:
        name = feed.get("name", "rss")
        url = feed.get("url", "")
        if not url:
            return []
        resp = await self._http.request("GET", url, timeout=30.0)
        if resp.status_code != 200:
            log.warning("rss.bad_status", feed=name, status=resp.status_code)
            return []
        text = resp.text
        # feedparser is sync; offload to thread.
        parsed = await asyncio.to_thread(feedparser.parse, text)
        results: list[Advisory] = []
        for entry in parsed.entries or []:
            adv = self._entry_to_advisory(name, entry, since)
            if adv is not None:
                results.append(adv)
        return results

    def _entry_to_advisory(
        self, feed_name: str, entry: Any, since: datetime
    ) -> Advisory | None:
        title = (entry.get("title") or "") if isinstance(entry, dict) else getattr(entry, "title", "")
        summary = (entry.get("summary") or "") if isinstance(entry, dict) else getattr(entry, "summary", "")
        link = (entry.get("link") or "") if isinstance(entry, dict) else getattr(entry, "link", "")
        haystack = f"{title}\n{summary}".lower()
        if not any(kw in haystack for kw in self._keywords):
            return None

        published_dt = _entry_published(entry)
        # Drop entries with no parseable timestamp — feed must commit to a date
        # to participate in modified-since dedupe. Re-fire-on-restart would be
        # the alternative and is worse.
        if published_dt is None:
            return None
        if published_dt < since:
            return None

        # ID stability: GHSA > CVE > sha256(feed_name + link_or_title). The
        # sha256 fallback is deterministic across process restarts (Python's
        # built-in hash() is salted, do not use it for persisted IDs).
        # Aliases stored uppercase to match GHSA/NVD canonical form so
        # cross-source dedupe via Advisory.merge() works.
        cve_ids = [m.upper() for m in _CVE_RE.findall(haystack)]
        ghsa_ids = [m.upper() for m in _GHSA_RE.findall(haystack)]
        aliases = sorted({*cve_ids, *ghsa_ids})
        if ghsa_ids:
            adv_id = ghsa_ids[0]
        elif cve_ids:
            adv_id = cve_ids[0]
        else:
            digest = hashlib.sha256(
                f"{feed_name}\0{link or title}".encode()
            ).hexdigest()[:16]
            adv_id = f"{feed_name}:{digest}"

        affected = _guess_ecosystems(haystack)

        return Advisory(
            id=adv_id,
            source=SourceKind.RSS,
            advisory_class=AdvisoryClass.SUPPLY_CHAIN,
            cvss=None,
            summary=title[:1000],
            published=published_dt,
            modified=published_dt,
            affected=affected,
            aliases=aliases,
            references=[link] if link else [],
            raw={"feed": feed_name, "title": title, "link": link},
        )


def _entry_published(entry: Any) -> datetime | None:
    for attr in ("published_parsed", "updated_parsed"):
        val = getattr(entry, attr, None) if not isinstance(entry, dict) else entry.get(attr)
        if val:
            try:
                # feedparser yields time.struct_time-like tuples
                # (year, mon, day, hour, min, sec, ...).
                y, mo, d, h, mi, s = val[:6]
                return datetime(y, mo, d, h, mi, s, tzinfo=timezone.utc)
            except (TypeError, ValueError):
                continue
    return None


def _guess_ecosystems(haystack: str) -> list[AffectedPackage]:
    """Detect mentioned ecosystems by keyword. Returns dummy package marker."""
    found: dict[str, AffectedPackage] = {}
    for hint, eco in _ECOSYSTEM_HINTS.items():
        if hint in haystack and eco not in found:
            # Empty name = "ecosystem-wide" notification, downstream actions
            # can still fire because supply chain bypasses score.
            found[eco] = AffectedPackage(ecosystem=eco, name="(unspecified)")
    return list(found.values())
