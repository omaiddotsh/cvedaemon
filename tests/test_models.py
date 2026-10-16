from datetime import datetime, timezone

from sev1daemon.models import (
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


def _classed(advisory_class: AdvisoryClass, source: SourceKind = SourceKind.OSV) -> Advisory:
    return Advisory(
        id="MAL-2099-1",
        source=source,
        advisory_class=advisory_class,
        cvss=None,
        summary="s",
        published=None,
        modified=None,
        affected=[AffectedPackage("npm", "evil")],
    )


def test_malicious_package_class_is_scored_not_supply_chain():
    assert AdvisoryClass("malicious_package") is AdvisoryClass.MALICIOUS_PACKAGE
    assert not _classed(AdvisoryClass.MALICIOUS_PACKAGE).is_supply_chain


def test_merge_class_precedence_is_order_independent():
    mal = _classed(AdvisoryClass.MALICIOUS_PACKAGE)
    cve = _classed(AdvisoryClass.CVE, SourceKind.GITHUB)
    sc = _classed(AdvisoryClass.SUPPLY_CHAIN, SourceKind.RSS)
    assert mal.merge(cve).advisory_class is AdvisoryClass.MALICIOUS_PACKAGE
    assert cve.merge(mal).advisory_class is AdvisoryClass.MALICIOUS_PACKAGE
    assert mal.merge(sc).advisory_class is AdvisoryClass.SUPPLY_CHAIN
    assert sc.merge(mal).advisory_class is AdvisoryClass.SUPPLY_CHAIN
    assert cve.merge(cve).advisory_class is AdvisoryClass.CVE


def test_malicious_package_class_round_trips_through_state_payload():
    from sev1daemon.models import Alert
    from sev1daemon.state import _advisory_to_dict, advisory_from_payload

    adv = _classed(AdvisoryClass.MALICIOUS_PACKAGE)
    payload = _advisory_to_dict(adv)
    assert payload["advisory_class"] == "malicious_package"
    restored = advisory_from_payload(payload)
    assert restored.advisory_class is AdvisoryClass.MALICIOUS_PACKAGE
    assert restored.affected == adv.affected
    alert = Alert(advisory=restored, package=restored.affected[0], score=42.0, breakdown=None)
    assert alert.as_payload()["advisory_class"] == "malicious_package"
