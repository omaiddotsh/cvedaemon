# Contributing to sev1daemon

Thanks for helping. This guide covers the dev setup, how the code is laid out,
and the few rules that keep the daemon trustworthy. Read the
[README](README.md) first for what the daemon does.

## Dev setup

Python 3.10 or newer.

```bash
git clone https://github.com/omaiddotsh/cvedaemon sev1daemon
cd sev1daemon
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
```

Before sending a change, all three must pass:

```bash
.venv/bin/pytest -q
.venv/bin/ruff check src/ tests/
.venv/bin/mypy src/
```

Tests never touch the network: HTTP is mocked with `respx`.

To try a change against the real feeds without sending anything:

```bash
cp config.example.yaml config.yaml          # all actions start disabled
export GITHUB_TOKEN=...                      # read-only, public repos
.venv/bin/sev1daemon show-config -c config.yaml
.venv/bin/sev1daemon check --dry-run -c config.yaml
.venv/bin/sev1daemon score --ecosystem npm --name react -c config.yaml
```

## Layout

```
src/sev1daemon/
├── cli.py               # click commands: run, check, replay, score, show-config, test-action
├── config.py            # pydantic schema, YAML loader, ${ENV} expansion
├── daemon.py            # lifecycle, poll loop, source collection, housekeeping, signals
├── pipeline.py          # AlertPipeline: dedupe, re-queue, score, dispatch, retry bookkeeping
├── scoring.py           # blast-radius score, renormalized per ecosystem
├── state.py             # SQLite store (WAL, schema migrations)
├── health.py            # /healthz /readyz /livez /metrics (stdlib HTTP server)
├── http.py              # httpx client: on-disk cache, retries, Retry-After, line streaming
├── log.py, redact.py    # structlog JSON + secret redaction
├── metrics.py           # Prometheus metrics
├── models.py            # Advisory, AffectedPackage, ScoreBreakdown, Alert
├── sources/             # advisory ingestors
│   ├── base.py          # Source ABC + SourceFetchIncomplete
│   ├── osv.py           # OSV change index (modified_id.csv) + per-record JSON
│   ├── github.py        # GitHub global advisories (GHSA)
│   ├── nvd.py           # NVD API 2.0 (off by default)
│   └── rss.py           # supply-chain RSS/Atom + keyword filter
├── enrich/              # popularity signals
│   ├── registry.py      # download counts per registry
│   ├── depsdev.py       # deps.dev dependents + repo lookup
│   ├── github_stars.py  # stargazers (rate-limit aware)
│   └── repo.py          # GitHub repo URL parsing / repo from package name
└── actions/             # alert dispatch
    ├── dispatcher.py    # matching, circuit breaker, SSRF guard, rate limit, idempotency
    ├── webhook.py       # JSON POST
    ├── github_issue.py  # create an issue
    └── shell.py         # templated argv (no shell), allowlisted env
```

## How a poll cycle works

`Daemon._run_cycle()`:

1. `_collect()` fetches from each enabled source (two at a time). A complete
   fetch advances that source's checkpoint to the time the fetch *started*; a
   partial fetch raises `SourceFetchIncomplete` with what it got, and the
   checkpoint stays put so the missed part is queried again.
2. `AlertPipeline.new_advisories()` merges records sharing an id and drops
   already-processed ones; `AlertPipeline.requeued()` adds advisories an
   earlier cycle stored but didn't finish.
3. `AlertPipeline.process()` runs every affected package through one loop:
   supply-chain advisories skip enrichment and score 100; everything else
   (CVEs, `malicious_package` records) is enriched, scored and dispatched only
   at or above the threshold.
4. `_housekeeping()` prunes old rows and evicts the HTTP cache.

## Delivery guarantees (don't regress these)

- A source's checkpoint only advances after a complete fetch, and only after
  every advisory that fetch returned is stored (`processed=0`). Nothing a
  cycle collected is lost if the cycle is cancelled or the process dies.
- A processed advisory that comes back modified with packages the daemon
  never scored is queued again; packages that already alerted are not re-sent.
- An advisory is marked processed only when every matching action succeeded
  for every package over the threshold. Otherwise it is re-queued next cycle,
  up to `advisory_max_attempts`.
- Actions that already succeeded for an (advisory, package) are never re-run
  (`action_log`); records for the same vulnerability under different ids
  alert once per package (`fired_keys`, ids + aliases).
- SIGTERM cancels the in-flight cycle; dry runs write to a DB snapshot.

`tests/test_pipeline_reliability.py` pins these. Don't weaken those tests to
make a change pass.

## Conventions

- **Async everywhere.** All I/O is `async`; use `asyncio.to_thread` for
  blocking libraries (feedparser, zip/JSON parsing of large bodies).
- **Catch specific exceptions.** The poll loop catches `Exception` only to log
  and continue.
- **Never log secrets.** Anything that can carry a URL or token goes through
  `redact()`; the structlog processor and a stdlib logging filter enforce it.
  Webhook URLs are credentials.
- **Score conservatively.** An unknown signal is 0 points, never a guess.
- **Config, not flags.** New behaviour is a config field with a safe default;
  unknown config keys are rejected.
- **Sources must not truncate silently.** Raise `SourceFetchIncomplete` (with
  partial results) or an exception; never return a short list as if complete.

## Common changes

- **New source:** subclass `Source` in `sources/`, register it in
  `Daemon._build_sources()`, add its config block to `SourcesConfig`, and add
  a mocked test that covers full, partial and failed fetches.
- **New action:** subclass `Action` in `actions/`, wire it into
  `dispatcher.build_runner()`, add a config class (subclass `ActionBase`,
  register it in `_build_action()`), and add a mocked test.
- **New ecosystem:** add it to `ECOSYSTEMS` in `config.py` and
  `_OSV_ECOSYSTEM_FROM_GHSA` in `sources/github.py`; add `_SYSTEM` in
  `enrich/depsdev.py` if deps.dev indexes it, a download handler in
  `enrich/registry.py` (plus a default in `DownloadsConfig.thresholds`) if the
  registry publishes counts, and a repo route in `enrich/repo.py`. The scorer
  renormalizes over whatever signals exist, so nothing else changes.

## Pull requests

Keep them focused, describe the behaviour change and how you verified it, and
include tests. For anything touching delivery (checkpoints, retries, dedupe),
explain why the guarantees above still hold.
