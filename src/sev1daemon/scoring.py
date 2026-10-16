"""Blast-radius scoring.

Raw points per signal, each 0..weight (default 40 + 40 + 20 = 100):

    stars     min(stars / saturate_at, 1) * weight
    downloads min(downloads / thresholds[ecosystem], 1) * weight
    depsdev   min(dependents / saturate_at, 1) * weight

Not every ecosystem has every signal: Maven, Go, SwiftURL and GitHub Actions
publish no download counts, and deps.dev only has dependents for npm, PyPI,
crates.io and Maven. Without correction those ecosystems top out at 60 or 40
points and could never reach the default threshold of 70. So the score is
renormalized over the signals the ecosystem *supports*:

    score = sum(points) / sum(weights of supported signals) * sum(all weights)

"Supported" is structural (a data source exists for the ecosystem), never
per package: a supported signal that came back None for this package still
scores 0 and stays in the denominator. Unknown signal → 0 points (don't
over-fire on partial data); an unsupported signal never scores.
"""

from __future__ import annotations

from sev1daemon.config import BlastRadiusConfig
from sev1daemon.enrich.depsdev import DepsDevClient
from sev1daemon.enrich.registry import RegistryClient
from sev1daemon.models import AffectedPackage, ScoreBreakdown

SIGNALS = ("stars", "downloads", "depsdev")


class Scorer:
    def __init__(self, cfg: BlastRadiusConfig):
        self._cfg = cfg

    def score(
        self,
        package: AffectedPackage,
        stars: int | None,
        downloads: int | None,
        depsdev: int | None,
    ) -> ScoreBreakdown:
        supported = self.supported_signals(package.ecosystem)
        if "downloads" in supported and not self._cfg.downloads.thresholds.get(package.ecosystem):
            # Downloads exist upstream but the config sets no threshold to
            # score them against: treat as unsupported instead of a silent 0
            # that would still count in the denominator.
            supported = tuple(s for s in supported if s != "downloads")
        raw = {
            "stars": self._stars_points(stars),
            "downloads": self._downloads_points(package.ecosystem, downloads),
            "depsdev": self._depsdev_points(depsdev),
        }
        weights = self._weights()
        supported_weight = sum(weights[s] for s in supported)
        all_weight = sum(weights.values())
        scale = all_weight / supported_weight if supported_weight > 0 else 1.0

        def points(signal: str) -> float:
            if signal not in supported:
                return 0.0
            return round(raw[signal] * scale, 2)

        return ScoreBreakdown(
            stars_points=points("stars"),
            downloads_points=points("downloads"),
            depsdev_points=points("depsdev"),
            stars_raw=stars,
            downloads_raw=downloads,
            depsdev_raw=depsdev,
            scale=round(scale, 4),
            supported_signals=supported,
        )

    def crosses_threshold(self, score: float) -> bool:
        return score >= self._cfg.score_threshold

    @staticmethod
    def supported_signals(ecosystem: str) -> tuple[str, ...]:
        """Signals with a data source for this ecosystem, in SIGNALS order.

        Stars are supported everywhere: every ecosystem has a repo URL route
        (deps.dev, registry metadata, or the package name itself).
        """
        has = {
            "stars": True,
            "downloads": RegistryClient.supports(ecosystem),
            "depsdev": DepsDevClient.supports(ecosystem),
        }
        return tuple(s for s in SIGNALS if has[s])

    # ---------- per-signal ----------

    def _weights(self) -> dict[str, float]:
        return {
            "stars": max(self._cfg.stars.weight, 0),
            "downloads": max(self._cfg.downloads.weight, 0),
            "depsdev": max(self._cfg.depsdev.weight, 0),
        }

    def _stars_points(self, stars: int | None) -> float:
        if stars is None or stars < 0:
            return 0.0
        cap = self._cfg.stars.saturate_at
        if cap <= 0:
            return 0.0
        return round(min(stars / cap, 1.0) * self._cfg.stars.weight, 2)

    def _downloads_points(self, ecosystem: str, downloads: int | None) -> float:
        if downloads is None or downloads < 0:
            return 0.0
        threshold = self._cfg.downloads.thresholds.get(ecosystem)
        if not threshold or threshold <= 0:
            return 0.0
        return round(min(downloads / threshold, 1.0) * self._cfg.downloads.weight, 2)

    def _depsdev_points(self, depsdev: int | None) -> float:
        if depsdev is None or depsdev < 0:
            return 0.0
        cap = self._cfg.depsdev.saturate_at
        if cap <= 0:
            return 0.0
        return round(min(depsdev / cap, 1.0) * self._cfg.depsdev.weight, 2)
