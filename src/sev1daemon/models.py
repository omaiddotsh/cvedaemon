"""Domain models for advisories, packages, scoring, alerts."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class SourceKind(str, Enum):
    OSV = "osv"
    NVD = "nvd"
    GITHUB = "github"
    RSS = "rss"


class AdvisoryClass(str, Enum):
    CVE = "cve"
    SUPPLY_CHAIN = "supply_chain"
    # OpenSSF malicious-packages reports (OSV ``MAL-`` ids). Scored like CVEs
    # (enrichment + threshold), so only popular packages alert; deliberately
    # not supply chain, which always fires at score 100.
    MALICIOUS_PACKAGE = "malicious_package"


# Merged records keep the most specific class, whichever side it came from.
_CLASS_PRECEDENCE = {
    AdvisoryClass.CVE: 0,
    AdvisoryClass.MALICIOUS_PACKAGE: 1,
    AdvisoryClass.SUPPLY_CHAIN: 2,
}


@dataclass(frozen=True)
class AffectedPackage:
    ecosystem: str
    name: str

    def key(self) -> str:
        return f"{self.ecosystem}::{self.name}"


@dataclass
class Advisory:
    """Normalized advisory record from any source."""

    id: str
    source: SourceKind
    advisory_class: AdvisoryClass
    cvss: float | None
    summary: str
    published: datetime | None
    modified: datetime | None
    affected: list[AffectedPackage] = field(default_factory=list)
    aliases: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def is_supply_chain(self) -> bool:
        return self.advisory_class is AdvisoryClass.SUPPLY_CHAIN

    def merge(self, other: Advisory) -> Advisory:
        """Merge two records for same id (richer affected list wins).

        Classification is order-independent: supply_chain beats
        malicious_package beats cve. Supply chain must be sticky, otherwise
        the threshold bypass would silently disappear when an OSV CVE happens
        to share an id with an RSS supply-chain entry.
        """
        if other.id != self.id:
            raise ValueError(f"cannot merge {self.id} with {other.id}")
        affected = list({p.key(): p for p in (self.affected + other.affected)}.values())
        aliases = sorted(set(self.aliases) | set(other.aliases))
        references = sorted(set(self.references) | set(other.references))
        cvss = max(filter(None, [self.cvss, other.cvss]), default=None)
        advisory_class = max(
            self.advisory_class, other.advisory_class, key=_CLASS_PRECEDENCE.__getitem__
        )
        return Advisory(
            id=self.id,
            source=self.source,
            advisory_class=advisory_class,
            cvss=cvss,
            summary=self.summary or other.summary,
            published=self.published or other.published,
            modified=max(filter(None, [self.modified, other.modified]), default=None),
            affected=affected,
            aliases=aliases,
            references=references,
            raw={**other.raw, **self.raw},
        )


@dataclass
class ScoreBreakdown:
    """Points per signal (already renormalized; they sum to ``total``).

    ``scale`` is the factor applied to the raw points and ``supported_signals``
    the signals the ecosystem has a data source for (see scoring.py).
    """

    stars_points: float
    downloads_points: float
    depsdev_points: float
    stars_raw: int | None
    downloads_raw: int | None
    depsdev_raw: int | None
    scale: float = 1.0
    supported_signals: tuple[str, ...] = ("stars", "downloads", "depsdev")

    @property
    def total(self) -> float:
        return round(self.stars_points + self.downloads_points + self.depsdev_points, 2)

    def as_dict(self) -> dict[str, Any]:
        return {
            "stars_points": self.stars_points,
            "downloads_points": self.downloads_points,
            "depsdev_points": self.depsdev_points,
            "stars_raw": self.stars_raw,
            "downloads_raw": self.downloads_raw,
            "depsdev_raw": self.depsdev_raw,
            "scale": self.scale,
            "supported_signals": list(self.supported_signals),
            "total": self.total,
        }


@dataclass
class Alert:
    """Final fireable record after scoring."""

    advisory: Advisory
    package: AffectedPackage
    score: float
    breakdown: ScoreBreakdown | None
    fired_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def as_payload(self) -> dict[str, Any]:
        return {
            "advisory_id": self.advisory.id,
            "source": self.advisory.source.value,
            "advisory_class": self.advisory.advisory_class.value,
            "cvss": self.advisory.cvss,
            "summary": self.advisory.summary,
            "ecosystem": self.package.ecosystem,
            "package": self.package.name,
            "score": self.score,
            "score_breakdown": self.breakdown.as_dict() if self.breakdown else None,
            "aliases": self.advisory.aliases,
            "references": self.advisory.references,
            "published": self.advisory.published.isoformat() if self.advisory.published else None,
            "modified": self.advisory.modified.isoformat() if self.advisory.modified else None,
            "fired_at": self.fired_at.isoformat(),
        }
