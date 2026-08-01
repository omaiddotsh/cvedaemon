"""Blast-radius scoring.

Score = stars_points + downloads_points + depsdev_points
      (0..weight per signal, default 40 + 40 + 20 = 100)

Each unknown signal contributes 0 (conservative: don't over-fire on partial data).
"""

from __future__ import annotations

from cvedaemon.config import BlastRadiusConfig
from cvedaemon.models import AffectedPackage, ScoreBreakdown


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
        stars_points = self._stars_points(stars)
        downloads_points = self._downloads_points(package.ecosystem, downloads)
        depsdev_points = self._depsdev_points(depsdev)
        return ScoreBreakdown(
            stars_points=stars_points,
            downloads_points=downloads_points,
            depsdev_points=depsdev_points,
            stars_raw=stars,
            downloads_raw=downloads,
            depsdev_raw=depsdev,
        )

    def crosses_threshold(self, score: float) -> bool:
        return score >= self._cfg.score_threshold

    # ---------- per-signal ----------

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
