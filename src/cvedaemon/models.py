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

        Supply-chain classification is sticky: if either side classifies as
        supply_chain, the merged record inherits it. Otherwise the threshold
        bypass would silently disappear when an OSV CVE happens to share an
        id with an RSS supply-chain entry.
        """
        if other.id != self.id:
            raise ValueError(f"cannot merge {self.id} with {other.id}")
        affected = list({p.key(): p for p in (self.affected + other.affected)}.values())
        aliases = sorted(set(self.aliases) | set(other.aliases))
        references = sorted(set(self.references) | set(other.references))
        cvss = max(filter(None, [self.cvss, other.cvss]), default=None)
        advisory_class = (
            AdvisoryClass.SUPPLY_CHAIN
            if (self.is_supply_chain or other.is_supply_chain)
            else self.advisory_class
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
    stars_points: float
    downloads_points: float
    depsdev_points: float
    stars_raw: int | None
    downloads_raw: int | None
    depsdev_raw: int | None

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
