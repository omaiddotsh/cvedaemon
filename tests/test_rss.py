from datetime import datetime, timezone

from cvedaemon.models import AdvisoryClass, SourceKind
from cvedaemon.sources.rss import RssSource


def make_entry(title: str, summary: str = "", link: str = "https://example.test/x"):
    class E:
        pass

    e = E()
    e.title = title
    e.summary = summary
    e.link = link
    e.published_parsed = (2099, 1, 1, 0, 0, 0)
    return e


def test_keyword_match_fires():
    rss = RssSource(
        http=None,  # not used by _entry_to_advisory
        feeds=[],
        keywords=["supply chain", "malicious package"],
    )
    entry = make_entry(
        "New supply chain attack on npm registry",
        "Researchers discovered a typosquat targeting javascript projects.",
    )
    adv = rss._entry_to_advisory(
        "thehackernews", entry, datetime(1970, 1, 1, tzinfo=timezone.utc)
    )
    assert adv is not None
    assert adv.advisory_class is AdvisoryClass.SUPPLY_CHAIN
    assert adv.source is SourceKind.RSS
    # ecosystem detected from "npm" / "javascript"
    assert any(p.ecosystem == "npm" for p in adv.affected)


def test_keyword_miss_returns_none():
    rss = RssSource(http=None, feeds=[], keywords=["supply chain"])
    entry = make_entry("Random tech newsletter", "nothing of interest")
    assert (
        rss._entry_to_advisory("x", entry, datetime(1970, 1, 1, tzinfo=timezone.utc))
        is None
    )


def test_cve_id_extracted_as_alias():
    rss = RssSource(http=None, feeds=[], keywords=["supply chain"])
    entry = make_entry(
        "Supply chain attack tracked as CVE-2024-12345",
        "GHSA-aaaa-bbbb-cccc was issued.",
    )
    adv = rss._entry_to_advisory(
        "x", entry, datetime(1970, 1, 1, tzinfo=timezone.utc)
    )
    assert adv is not None
    aliases_upper = [a.upper() for a in adv.aliases]
    assert "CVE-2024-12345" in aliases_upper
    assert any(a.upper().startswith("GHSA-") for a in adv.aliases)
