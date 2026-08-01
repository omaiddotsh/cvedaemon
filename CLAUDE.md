# cvedaemon — project context for Claude

## What this is

Python 3.10+ async daemon. Watches OSS CVE feeds + supply chain attack RSS,
scores affected packages by blast radius (stars + downloads + deps.dev
dependents), fires actions when score crosses threshold. Supply chain alerts
bypass the scorer entirely (always fire at score 100).

Full spec in `README.md`. Read it before making non-trivial changes.

## Layout

```
src/cvedaemon/
├── __init__.py          # version
├── __main__.py          # python -m cvedaemon entry
├── cli.py               # click subcommands: run, check, score, show-config, test-action
├── config.py            # pydantic schema + YAML loader + ${ENV} expansion
├── daemon.py            # poll loop, pipeline orchestration, signal handling
├── health.py            # /healthz /readyz /livez (stdlib threaded server)
├── http.py              # httpx async client + on-disk cache + retry
├── log.py               # structlog JSON setup + redact processor
├── models.py            # Advisory, AffectedPackage, ScoreBreakdown, Alert
├── redact.py            # webhook URL + bearer token redaction
├── scoring.py           # blast-radius scoring (Scorer)
├── state.py             # aiosqlite store (WAL); advisories, processed_packages,
│                        # action_log, poll_state tables
├── sources/             # advisory ingestors
│   ├── base.py          # Source ABC
│   ├── osv.py           # OSV.dev (per-ecosystem all.json)
│   ├── nvd.py           # NVD API 2.0 (rate-limit aware, 120-day window clamp)
│   ├── github.py        # GHSA (Link-header pagination)
│   └── rss.py           # supply chain RSS/Atom + keyword filter
├── enrich/              # popularity signal lookups
│   ├── github_stars.py  # repo stargazers
│   ├── registry.py      # 6 ecosystems hot path (npm, PyPI, RubyGems, crates, NuGet, Packagist)
│   └── depsdev.py       # deps.dev dependents + repo URL lookup
└── actions/             # alert dispatch
    ├── base.py          # Action ABC + ActionResult
    ├── dispatcher.py    # routing: min_score + ecosystem whitelist
    ├── webhook.py       # generic JSON POST
    ├── github_issue.py  # REST create-issue
    ├── shell.py         # templated argv, env vars, no shell-injection
    └── nebari.py        # shells out to external cve_response.py
```

## Pipeline flow

`daemon.py::Daemon._run_cycle()`:

1. `_collect()` — fetch from each enabled source in parallel-ish (sequential for
   now; intentional to be polite to upstream APIs).
2. `_dedupe_and_filter()` — merge by advisory id across sources, drop already-
   processed (per `advisories.processed` column).
3. For each advisory:
   - **Supply chain** (`adv.is_supply_chain`) → `_process_supply_chain()`:
     skip enrich/score, force score=100, fire matching actions.
   - **CVE** → `_process_cve()`: per-affected-package enrich (stars, downloads,
     depsdev), `Scorer.score()`, fire if ≥ threshold.
4. `prune_action_log()` housekeeping.

## Hot paths when editing

- **Adding a source** → new module in `sources/`, subclass `Source`, register in
  `Daemon._build_sources()`. Add config block in `config.py::SourcesConfig`.
- **Adding an action type** → new module in `actions/`, subclass `Action`. Wire
  into `dispatcher.py::build_runner()` and add a config class in
  `config.py` (subclass `ActionBase`, register in `_build_action()`).
- **Adding an ecosystem** → update `ECOSYSTEMS` in `config.py`,
  `_OSV_ECOSYSTEM_FROM_GHSA` in `sources/github.py`, `_SYSTEM` in
  `enrich/depsdev.py`, and optionally a `_<ecosystem>` handler in
  `enrich/registry.py`. Default threshold in
  `DownloadsConfig.thresholds`.

## Commands

```bash
# Setup
python3.12 -m venv .venv
.venv/bin/pip install -e ".[dev]"

# Run checks (CI runs these)
.venv/bin/ruff check src/ tests/
.venv/bin/mypy src/
.venv/bin/pytest -q

# Smoke run
cp config.example.yaml config.yaml
# edit config.yaml: GITHUB_TOKEN at minimum
.venv/bin/cvedaemon show-config -c config.yaml
.venv/bin/cvedaemon check -c config.yaml
.venv/bin/cvedaemon run -c config.yaml
```

## Conventions

- **Async everywhere.** All IO is `async`. Use `asyncio.to_thread` for blocking
  libs (e.g. feedparser).
- **No bare excepts.** Catch specific exceptions. Top-level loop in `daemon.py`
  catches `Exception` only to log + continue.
- **Redact on the way in.** Anything user-supplied that lands in logs or
  `action_log.detail` goes through `redact()`. structlog processor enforces this
  for all log messages.
- **Score is conservative.** Unknown signal → 0 points (never inflate).
- **Webhook URLs are sensitive.** Slack/Discord/Teams hosts are auto-redacted
  by `redact.py` — do not log them raw.
- **Config-driven, not flag-driven.** New behavior should be a config field
  with sane defaults, not a CLI flag.
- **No CVE timelock or staged rollout.** When in doubt, ship behind a config
  `enabled: false`.

## What NOT to do

- Don't add a global secrets-in-DB cleartext store. We avoid persisting
  webhook URLs and tokens; configs hold them, redact strips them from logs/DB.
- Don't add Sentry / Rollbar / FE error tracking — it's a daemon, structlog
  JSON to stdout is the contract.
- Don't pin to a single CVE feed. The 4-source design is intentional
  resilience.
- Don't break the `Source` ABC signature without updating `daemon.py`.

## Testing

- `tests/test_*.py` — pytest-asyncio (auto mode). Mock HTTP with `respx`.
- 32 tests at last run. Keep that bar.
- Add a mocked source test for new ingestors. Add a mocked action test for
  new action types.

## Deploy

- **systemd**: `systemd/cvedaemon.service` — hardened (NoNewPrivileges,
  ProtectSystem=strict, MemoryDenyWriteExecute, dropped capability set).
  README has full install steps.
- **Docker**: multi-stage `Dockerfile`, runs as uid 10001. Mount config at
  `/etc/cvedaemon/config.yaml`, state at `/var/lib/cvedaemon`. Exposes 8080.
- **k8s**: wire `/healthz` to `livenessProbe`, `/readyz` to `readinessProbe`.

## Open questions / future

- Replace OSV per-ecosystem `all.json` (heavy) with deps.dev modified-since
  feed when API stabilizes.
- Add Prometheus `/metrics` endpoint (currently only health probes).
- Parallel source fetch with bounded `asyncio.Semaphore` — currently serial.
