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
import httpx

from sev1daemon.http import HttpClient
from sev1daemon.log import get_logger
from sev1daemon.models import (
    Advisory,
    AdvisoryClass,
    AffectedPackage,
    SourceKind,
)
from sev1daemon.sources.base import Source, SourceFetchIncomplete

log = get_logger("rss")


# Match CVE-2024-1234, GHSA-xxxx-xxxx-xxxx anywhere in text.
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
_GHSA_RE = re.compile(r"\bGHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}\b", re.IGNORECASE)


# Ecosystem cues, matched against the lowercased title + summary. Word
# boundaries plus specific phrasing keep ordinary words and domains from
# matching ("trust " is not Rust, "example.net" is not NuGet, a "swift
# response" is not SwiftPM).
_ECOSYSTEM_HINTS: tuple[tuple[re.Pattern[str], str], ...] = tuple(
    (re.compile(pattern), ecosystem)
    for pattern, ecosystem in (
        (r"\bnpm\b", "npm"),
        (r"\bnode\.?js\b", "npm"),
        (r"\bjavascript (?:packages?|modules?|librar(?:y|ies))\b", "npm"),
        (r"\bpypi\b", "PyPI"),
        (r"\bpip install\b", "PyPI"),
        (r"\bpython (?:packages?|modules?|librar(?:y|ies))\b", "PyPI"),
        (r"\brubygems\b", "RubyGems"),
        (r"\bruby gems?\b", "RubyGems"),
        (r"\bcrates\.io\b", "crates.io"),
        (r"\bcargo (?:crates?|packages?|registry)\b", "crates.io"),
        (r"\brust (?:crates?|packages?|librar(?:y|ies))\b", "crates.io"),
        (r"\bnuget\b", "NuGet"),
        (r"\bmaven\b", "Maven"),
        (r"\bjava (?:packages?|librar(?:y|ies))\b", "Maven"),
        (r"\bgolang\b", "Go"),
        (r"\bgo modules?\b", "Go"),
        (r"\bpackagist\b", "Packagist"),
        (r"\b(?:composer|php) (?:packages?|librar(?:y|ies))\b", "Packagist"),
        (r"\bpub\.dev\b", "Pub"),
        (r"\b(?:dart|flutter) packages?\b", "Pub"),
        (r"\bhex\.pm\b", "Hex"),
        (r"\belixir packages?\b", "Hex"),
        (r"\bswift packages?\b", "SwiftURL"),
        (r"\bswiftpm\b", "SwiftURL"),
        (r"\bcocoapods\b", "SwiftURL"),
        (r"\bgithub actions?\b", "GitHub Actions"),
    )
)


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
        """Fetch every feed; a failing feed makes the result incomplete.

        Items from the healthy feeds are returned inside
        ``SourceFetchIncomplete``; if every feed fails, a plain
        ``RuntimeError`` is raised.
        """
        if not self._feeds or not self._keywords:
            return []
        out: list[Advisory] = []
        failed: list[str] = []
        for feed in self._feeds:
            name = feed.get("name") or "rss"
            try:
                advisories = await self._fetch_feed(feed, since)
            except (httpx.HTTPError, OSError, RuntimeError, ValueError) as exc:
                failed.append(name)
                log.warning(
                    "rss.feed_failed",
                    name=name,
                    error_type=type(exc).__name__,
                    error=str(exc),
                )
                continue
            out.extend(advisories)
        if not failed:
            return out
        if len(failed) == len(self._feeds):
            raise RuntimeError(f"rss: all {len(failed)} feeds failed")
        raise SourceFetchIncomplete(
            f"rss: {len(failed)}/{len(self._feeds)} feeds failed ({', '.join(failed)})",
            out,
        )

    async def _fetch_feed(self, feed: dict[str, str], since: datetime) -> list[Advisory]:
        name = feed.get("name", "rss")
        url = feed.get("url", "")
        if not url:
            raise ValueError(f"rss feed {name!r} has no url")
        # Feeds move (http→https, feedburner hops). A redirect is not a failure
        # here — a credential-free GET, unlike the action POSTs that must not
        # follow redirects.
        resp = await self._http.request("GET", url, timeout=30.0, follow_redirects=True)
        if resp.status_code != 200:
            log.warning("rss.bad_status", feed=name, status=resp.status_code)
            raise RuntimeError(f"rss feed {name!r}: HTTP {resp.status_code}")
        text = resp.text
        # feedparser is sync; offload to thread.
        parsed = await asyncio.to_thread(feedparser.parse, text)
        entries = parsed.entries or []
        if parsed.get("bozo") and not entries:
            # Not a feed at all (HTML error page, truncated body): nothing
            # usable came back, so don't let it pass as an empty feed.
            raise ValueError(
                f"rss feed {name!r}: unparseable ({parsed.get('bozo_exception')!r})"
            )
        results: list[Advisory] = []
        for entry in entries:
            adv = self._entry_to_advisory(name, entry, since)
            if adv is not None:
                results.append(adv)
        return results

    def _entry_to_advisory(
        self, feed_name: str, entry: Any, since: datetime
    ) -> Advisory | None:
        title = _entry_text(entry, "title")
        summary = _entry_text(entry, "summary")
        link = _entry_text(entry, "link")
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

        # RSS items live in their own id namespace. Taking a CVE/GHSA id found
        # in the article text as the item's id would collide with (and merge
        # into) the real CVE record during dedupe, so those ids go into aliases
        # only (uppercase, the GHSA/NVD canonical form). The sha256 is
        # deterministic across restarts (Python's built-in hash() is salted).
        cve_ids = [m.upper() for m in _CVE_RE.findall(haystack)]
        ghsa_ids = [m.upper() for m in _GHSA_RE.findall(haystack)]
        aliases = sorted({*cve_ids, *ghsa_ids})
        adv_id = _rss_advisory_id(feed_name, _entry_text(entry, "id") or link or title)

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


def _rss_advisory_id(feed_name: str, entry_key: str) -> str:
    """Stable id for an RSS item: ``rss:`` + 16 hex chars of sha256(feed + guid/link)."""
    digest = hashlib.sha256(f"{feed_name}\n{entry_key}".encode()).hexdigest()[:16]
    return f"rss:{digest}"


def _entry_text(entry: Any, key: str) -> str:
    """String field from a feedparser entry (or a plain dict); "" when absent."""
    value = entry.get(key) if isinstance(entry, dict) else getattr(entry, key, None)
    return value if isinstance(value, str) else ""


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
    for pattern, eco in _ECOSYSTEM_HINTS:
        if eco not in found and pattern.search(haystack):
            # Empty name = "ecosystem-wide" notification, downstream actions
            # can still fire because supply chain bypasses score.
            found[eco] = AffectedPackage(ecosystem=eco, name="(unspecified)")
    return list(found.values())
