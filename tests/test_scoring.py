from sev1daemon.config import BlastRadiusConfig
from sev1daemon.models import AffectedPackage
from sev1daemon.scoring import Scorer


def test_full_signal_saturates_to_max():
    cfg = BlastRadiusConfig()
    scorer = Scorer(cfg)
    pkg = AffectedPackage(ecosystem="npm", name="react")
    brk = scorer.score(pkg, stars=200_000, downloads=20_000_000, depsdev=50_000)
    assert brk.stars_points == 40.0
    assert brk.downloads_points == 40.0
    assert brk.depsdev_points == 20.0
    assert brk.total == 100.0
    assert scorer.crosses_threshold(brk.total) is True


def test_no_signal_yields_zero_and_does_not_fire():
    cfg = BlastRadiusConfig()
    scorer = Scorer(cfg)
    pkg = AffectedPackage(ecosystem="npm", name="who-cares")
    brk = scorer.score(pkg, stars=None, downloads=None, depsdev=None)
    assert brk.total == 0.0
    assert not scorer.crosses_threshold(brk.total)


def test_partial_signal_does_not_cross_default_70():
    cfg = BlastRadiusConfig()
    scorer = Scorer(cfg)
    # Only stars saturated → 40 pts. Default threshold 70.
    pkg = AffectedPackage(ecosystem="npm", name="trendy")
    brk = scorer.score(pkg, stars=999_999, downloads=None, depsdev=None)
    assert brk.stars_points == 40.0
    assert brk.total == 40.0
    assert not scorer.crosses_threshold(brk.total)


def test_unknown_ecosystem_downloads_score_zero():
    cfg = BlastRadiusConfig()
    scorer = Scorer(cfg)
    pkg = AffectedPackage(ecosystem="cpe:vendor", name="thing")
    brk = scorer.score(pkg, stars=None, downloads=999_999_999, depsdev=None)
    assert brk.downloads_points == 0.0


def test_two_signals_cross_threshold():
    cfg = BlastRadiusConfig()
    scorer = Scorer(cfg)
    pkg = AffectedPackage(ecosystem="npm", name="popular")
    brk = scorer.score(pkg, stars=5_000, downloads=100_000, depsdev=None)
    # stars 40 + downloads 40 = 80, crosses 70
    assert brk.total == 80.0
    assert scorer.crosses_threshold(brk.total)
