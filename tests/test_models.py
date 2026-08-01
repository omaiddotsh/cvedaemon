from datetime import datetime, timezone

from cvedaemon.models import (
    Advisory,
    AdvisoryClass,
    AffectedPackage,
    SourceKind,
)


def test_merge_unions_affected_packages():
    a = Advisory(
        id="GHSA-x",
        source=SourceKind.GITHUB,
        advisory_class=AdvisoryClass.CVE,
        cvss=9.8,
        summary="a",
        published=datetime.now(timezone.utc),
        modified=datetime.now(timezone.utc),
        affected=[AffectedPackage("npm", "left")],
    )
    b = Advisory(
        id="GHSA-x",
        source=SourceKind.OSV,
        advisory_class=AdvisoryClass.CVE,
        cvss=9.1,
        summary="b",
        published=datetime.now(timezone.utc),
        modified=datetime.now(timezone.utc),
        affected=[AffectedPackage("PyPI", "right"), AffectedPackage("npm", "left")],
    )
    merged = a.merge(b)
    keys = {p.key() for p in merged.affected}
    assert keys == {"npm::left", "PyPI::right"}
    assert merged.cvss == 9.8  # max of two
