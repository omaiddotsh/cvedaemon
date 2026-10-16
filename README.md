# sev1daemon

**Alerts on critical open-source vulnerabilities and supply-chain attacks
that hit packages people actually use.**

Advisory feeds publish thousands of critical vulnerabilities a year, and most
affect packages nobody depends on. sev1daemon watches the feeds, looks up how
widely each affected package is used (GitHub stars, registry downloads,
deps.dev dependents) and only alerts when the blast radius is real. Reports of
actively compromised packages skip the popularity check and alert
immediately.

- **Sources:** [OSV](https://osv.dev) (fetching only what changed since the
  last poll), GitHub's global advisory database, supply-chain news feeds, and
  optionally NVD.
- **12 ecosystems:** npm, PyPI, RubyGems, crates.io, NuGet, Maven, Go,
  Packagist (Composer), Pub, Hex, Swift, GitHub Actions.
- **Actions:** webhook (Slack, Discord, Teams, anything that takes JSON),
  GitHub issue, or a shell command.
- **Built to be left running:** alerts are retried until they're delivered,
  duplicates across feeds are suppressed, health and Prometheus endpoints are
  included, and it ships as a hardened systemd unit or a small Docker image.

## Quick start

Requires Python 3.10+. A GitHub token (read-only, public repos) is strongly
recommended: without one, GitHub allows 60 requests an hour.

```bash
git clone https://github.com/omaiddotsh/cvedaemon sev1daemon
cd sev1daemon
python3 -m venv .venv && .venv/bin/pip install .

cp config.example.yaml config.yaml
export GITHUB_TOKEN=...            # read by config.yaml via ${GITHUB_TOKEN}

.venv/bin/sev1daemon check --dry-run   # one poll over the last 24h, nothing sent
```

Then enable an action in `config.yaml` (for example set `enabled: true` on
`notify-slack` and export `SLACK_WEBHOOK_URL`) and run it for real:

```bash
.venv/bin/sev1daemon run
```

Or with Docker:

```bash
cp config.example.yaml config.yaml
GITHUB_TOKEN=... docker compose up --build -d
curl -fsS http://127.0.0.1:8080/healthz
```

Check how a package would score:

```bash
.venv/bin/sev1daemon score --ecosystem npm --name handlebars
```

## What an alert looks like

A webhook action POSTs one JSON document per affected package. Shell actions
get the main fields as `SEV1DAEMON_ADVISORY_ID`, `SEV1DAEMON_PACKAGE`,
`SEV1DAEMON_SCORE` and friends, plus the whole document in
`SEV1DAEMON_PAYLOAD`.

```json
{
  "advisory_id": "GHSA-p8wg-vrv2-v86f",
  "source": "github",
  "advisory_class": "cve",
  "cvss": 9.2,
  "summary": "Handlebars: JavaScript Injection via Own Property Check Bypass",
  "ecosystem": "npm",
  "package": "handlebars",
  "score": 100.0,
  "score_breakdown": {
    "stars_points": 40.0, "downloads_points": 40.0, "depsdev_points": 20.0,
    "stars_raw": 18683, "downloads_raw": 43384329, "depsdev_raw": 56395,
    "scale": 1.0, "supported_signals": ["stars", "downloads", "depsdev"],
    "total": 100.0
  },
  "aliases": ["CVE-2026-106445", "GHSA-p8wg-vrv2-v86f"],
  "references": ["https://github.com/advisories/GHSA-p8wg-vrv2-v86f"],
  "published": "2026-10-08T17:52:26+00:00",
  "modified": "2026-10-12T14:33:17+00:00",
  "fired_at": "2026-10-13T05:59:44+00:00"
}
```

`advisory_class` is `cve`, `malicious_package` (an OpenSSF malicious-package
report, scored like a CVE) or `supply_chain` (from a news feed; always score
100, `score_breakdown` null).

## How it decides what's worth an alert

**Vulnerabilities** (CVSS ≥ 9.0 by default) are scored 0–100 by how widely the
affected package is used, and alert at 70 or above. See [Scoring](#scoring).

**Malicious packages.** OpenSSF publishes dozens of malicious-package reports a
day, mostly typosquats nobody installs. They arrive through OSV and are scored
like vulnerabilities, so a hijacked popular package alerts and the typosquats
don't.

**Supply-chain attacks** (backdoors, dependency confusion, account takeovers)
often show up in security news before any advisory exists. Feed items matching
your keywords alert immediately at score 100: popularity is irrelevant when a
package is actively compromised.

## Architecture

```
   SCORED PIPELINE (CVEs + malicious packages)        SUPPLY CHAIN PIPELINE
┌──────────────────┐ ┌────────────┐ ┌──────────────┐  ┌───────────────────────┐
│ OSV change index │ │ GitHub GHSA│ │ NVD (opt-in) │  │  RSS/Atom feeds       │
└────────┬─────────┘ └─────┬──────┘ └──────┬───────┘  │  (TheHackerNews)      │
         └─────────────────┼───────────────┘          └───────────┬───────────┘
                           ▼                                      │
               ┌───────────────────────┐                          │
               │ merge + dedupe + queue│ ←────────────────────────┘
               └───────────┬───────────┘
                   ┌───────┴────────┐
                   ▼                ▼
          ┌────────────────┐  ┌─────────────┐
          │ enrich + score │  │  BYPASS     │
          │ (0..100, fire  │  │  score=100  │
          │  if ≥ 70)      │  │  always fire│
          └───────┬────────┘  └──────┬──────┘
                  └────────┬─────────┘
                           ▼
                 ┌──────────────────┐
                 │  actions         │
                 └──────────────────┘
```

Each poll cycle:

1. **Fetch** advisories from each enabled source in parallel, since the
   source's last *complete* fetch (overlapping the previous window by
   max(10 min, 2× poll interval); dedupe makes the overlap free). A source
   that only partly succeeds still hands over what it got, but its checkpoint
   doesn't move, so the missed part is queried again next cycle.
2. **Merge** advisories by ID across sources (richer affected list wins).
3. **Skip** advisories already fully processed (stored in SQLite), and
   **re-queue** advisories an earlier cycle stored but didn't finish.
4. **Route** by source type:
   - **Scored path** (CVEs and `malicious_package` records): enrich each
     affected package (stars, downloads, dependents), score 0..100, fire
     actions only if score ≥ threshold.
   - **Supply chain path:** Skip enrichment and scoring entirely. Score fixed
     at 100, always fires — popularity is irrelevant for active compromises.
5. **Fire** matching actions; record each invocation in `action_log` table.
6. **Finish** the advisory only when every matching action succeeded for
   every package that crossed the threshold. Otherwise it stays pending and
   is retried next cycle (actions that already succeeded aren't re-run), up
   to `advisory_max_attempts` cycles.

**Delivery guarantees.** Alerts are at-least-once: a cycle cut short by
SIGTERM or `cycle_timeout_seconds` can re-send an alert on the next run, but
nothing fetched is dropped. Records for the same vulnerability from different
sources (GHSA-…, PYSEC-…, GO-…, CVE-…) share aliases and alert once per
package. NVD records only carry CPEs, not package names, so NVD contributes
CVSS/metadata to merged records but never alerts on its own.

## Scoring

```
Score = stars_points     (0..40 default)
      + downloads_points (0..40 default)
      + depsdev_points   (0..20 default)
```

| Signal | Why |
|---|---|
| GitHub stars | Cross-ecosystem popularity proxy |
| Registry downloads | Catches build tools / infrastructure libs (modest stars, heavy use) |
| deps.dev dependents | Catches foundational libraries (low downloads, critical to long tail) |

A signal we can't fetch for a package contributes 0 — conservative in the
trigger direction.

**Renormalization.** Not every ecosystem has every signal, so the score is
scaled over the signals that exist for that ecosystem:

```
score = sum(points) / sum(weights of supported signals) × 100
```

"Supported" is structural (a data source exists), never per package. Without
this, Maven and Go topped out below the default threshold of 70 and could
never alert.

| Ecosystem | Stars | Downloads | deps.dev dependents |
|---|---|---|---|
| npm, PyPI, crates.io | ✓ | ✓ | ✓ |
| RubyGems, NuGet, Packagist, Pub, Hex | ✓ | ✓ | – |
| Maven | ✓ | – | ✓ |
| Go, SwiftURL, GitHub Actions | ✓ | – | – (stars alone: ≥ 3500 stars to alert) |

Repos for stars come from deps.dev's source link, the registry's metadata
(Packagist, Hex, Pub), or the package name itself (Go `github.com/...`,
SwiftURL, GitHub Actions `owner/repo`). Dependents are counted for the
package's default version on deps.dev (and the newest stable release when the
default is a prerelease).

Per-ecosystem download thresholds (configurable; each registry reports a
different window):

| Ecosystem | Window | Saturates at |
|---|---|---|
| npm | last week | 100K |
| PyPI | last month | 400K (≈ 100K/wk × 4.3) |
| RubyGems | all time | 10M |
| crates.io | last 90 days | 800K |
| NuGet | all time | 10M |
| Packagist | last month | 50K |
| Pub | last 30 days | 250K |
| Hex | last 90 days | 250K |

**Why NVD is off by default.** NVD records describe affected products as CPEs,
not package names, so an NVD-only CVE can never be scored or alert, and NVD
ids rarely match OSV/GHSA records. Measured on a live day: 97% of ingested
advisories, 0 alerts. Enable it only if you want NVD metadata stored.

## Actions

| Type | Use |
|---|---|
| `webhook` | Generic JSON POST. Configurable URL, method, headers. Pipe to internal API, n8n, etc. |
| `github_issue` | Open issue in a repo via REST. Configurable labels + assignees. |
| `shell` | Run a templated command. Payload exposed as `SEV1DAEMON_*` env vars and `{{...}}` template vars. Opt-in (dangerous by design). |

Each action accepts:

| Field | Purpose |
|---|---|
| `name` | Identifier for `sev1daemon test-action --action NAME` |
| `enabled` | Skip without removing |
| `min_score` | Per-action threshold (≥ global threshold) |
| `ecosystems` | Whitelist (e.g. `["npm", "PyPI"]`) |

The JSON payload (webhook body, `SEV1DAEMON_*` vars) carries `advisory_id`,
`advisory_class` (`cve`, `malicious_package` or `supply_chain`), `cvss`,
`summary`, `ecosystem`, `package`, `score`, `score_breakdown` (points per
signal plus the renormalization `scale` and `supported_signals`; null for
supply chain), `aliases`, `references`, `published`, `modified`, `fired_at`.

## Configuration

See `config.example.yaml` for full reference. Env vars are expanded inline:

```yaml
sources:
  github:
    token: "${GITHUB_TOKEN}"
    # or with default fallback:
    # token: "${GITHUB_TOKEN:-}"
```

### RSS supply chain feeds

```yaml
sources:
  rss:
    enabled: true
    feeds:
      - name: thehackernews
        url: "https://feeds.feedburner.com/TheHackersNews"
    keywords:
      - "supply chain"
      - "malicious package"
      - "backdoor"
      - "typosquat"
```

Add any RSS/Atom feed URL. Entries matching any keyword in title or description
are treated as supply chain alerts. Custom keywords extend the defaults.

Top-level fields:

| Field | Default | Purpose |
|---|---|---|
| `poll_interval_seconds` | 600 | Time between poll cycles |
| `cycle_timeout_seconds` | 0 (4× interval, min 120s) | Cancel a hung poll cycle |
| `lookback_minutes_on_start` | 1440 | First-run scan window (24h) |
| `min_cvss` | 9.0 | Drop advisories below this score. OSV `MAL-` malicious-package records carry no CVSS and skip it; they're scored by popularity |
| `state_db` | `./state/sev1daemon.db` | SQLite path |
| `action_log_retention_days` | 90 | Auto-prune `action_log` rows |
| `processed_packages_retention_days` | 365 | Auto-prune `processed_packages` |
| `startup_grace_seconds` | 300 | `/healthz` returns OK during startup (at least one cycle timeout) |
| `advisory_retention_days` | 365 | Prune finished advisories neither seen nor modified in this window (0 = keep) |
| `advisory_max_attempts` | 48 | Cycles an unfinished advisory is retried before it's given up on |
| `health_host` / `health_port` | `127.0.0.1:8080` | Probes + `/metrics`. Use `0.0.0.0` in Docker/k8s |
| `action_circuit_failures` | 5 | Skip an action after N errors in the window |
| `allow_private_urls` | false | Webhook SSRF guard (keep false in prod) |
| `log_level` | `INFO` | structlog level |
| `log_json` | true | JSON or console rendering |

## Operations

### Health endpoints

| Path | Use | Behavior |
|---|---|---|
| `GET /healthz` | k8s `livenessProbe` | OK during grace, then OK iff at least one source fetched completely within the stale window. Body has per-source status |
| `GET /readyz` | k8s `readinessProbe` | Strict: OK only after a source has fetched completely, no grace |
| `GET /livez` | basic liveness | Always 200, just confirms process responds |
| `GET /metrics` | Prometheus scrape | Counters/histograms for cycles, sources, actions |

Worth alerting on: `sev1daemon_source_last_success_timestamp_seconds` going
stale for any source, `sev1daemon_advisories_given_up_total`,
`sev1daemon_action_skipped_total{reason="circuit_open"}`, and
`sev1daemon_cycle_timeouts_total`.

### State

SQLite at `state_db` path, WAL mode. Tables:

| Table | Contents |
|---|---|
| `advisories` | Every advisory seen (id, source, cvss, payload, processed flag, attempts, last error) |
| `processed_packages` | Per-package score record (advisory × ecosystem × package) |
| `fired_keys` | Ids + aliases that alerted per package (cross-source dedupe) |
| `action_log` | Every action invocation or skip (status ok/error/skipped, redacted detail, timestamp) |
| `poll_state` | Per-source last success / last attempt / last error |

Inspect:

```bash
sqlite3 state/sev1daemon.db "SELECT advisory_id, action_name, status, ran_at FROM action_log ORDER BY id DESC LIMIT 20"
```

### Logs

JSON to stdout (one line per event). Pipe to whatever ships logs (Loki,
Splunk, Datadog, plain `journalctl`).

## Deployment

Deploy as a long-running systemd unit. `systemd/sev1daemon.service` ships
hardened defaults (`NoNewPrivileges`, `ProtectSystem=strict`,
`MemoryDenyWriteExecute`, etc). Creates user `sev1daemon`, state at
`/var/lib/sev1daemon`, env file at `/etc/sev1daemon/env`, config at
`/etc/sev1daemon/config.yaml`.

```bash
useradd --system --home /opt/sev1daemon sev1daemon
install -d -o sev1daemon /opt/sev1daemon /var/lib/sev1daemon /etc/sev1daemon
python3 -m venv /opt/sev1daemon/.venv
/opt/sev1daemon/.venv/bin/pip install git+https://github.com/omaiddotsh/cvedaemon
cp systemd/sev1daemon.service /etc/systemd/system/
cp config.example.yaml /etc/sev1daemon/config.yaml
install -m 600 /dev/null /etc/sev1daemon/env   # required; unit has no '-' prefix
# edit /etc/sev1daemon/config.yaml + /etc/sev1daemon/env (GITHUB_TOKEN=...)
# for systemd keep health_host: 127.0.0.1
systemctl daemon-reload
systemctl enable --now sev1daemon
journalctl -u sev1daemon -f
```

### Docker

```bash
cp config.example.yaml config.yaml
# GITHUB_TOKEN in the environment; compose sets SEV1DAEMON_HEALTH_HOST=0.0.0.0
docker compose up --build -d
curl -fsS http://127.0.0.1:8080/livez
curl -fsS http://127.0.0.1:8080/metrics | head
```

Config is **not** baked into the image. Mount `/etc/sev1daemon/config.yaml` or
the container exits on `FileNotFoundError`. State lives in
`/var/lib/sev1daemon` (uid 10001).

For local / non-systemd hosts, run `sev1daemon run --config config.yaml`
under any process supervisor (`supervisord`, `runit`, `tmux`).

## Environment variables

| Variable | Required? | Purpose |
|---|---|---|
| `GITHUB_TOKEN` | strongly recommended | GHSA ingestor + stars enrichment. Without it, GitHub rate limit drops to 60 req/h and the daemon will silently degrade. |
| `NVD_API_KEY` | optional | Only if you enable NVD: raises its rate limit from 5/30s to 50/30s |
| `WEBHOOK_TOKEN` | optional | Bearer token for the example webhook action |

Any value referenced as `${VAR}` in `config.yaml` is expanded at load time.

## CLI

```
sev1daemon run                                  # daemon loop
sev1daemon check                                # one-shot poll
sev1daemon check --dry-run                      # one-shot poll on a throwaway copy of the state DB, no actions
sev1daemon replay --advisory-id ID [--dry-run]  # re-process a stored advisory
sev1daemon test-action --action NAME            # synthetic alert to one action
sev1daemon score --ecosystem npm --name react   # score a single package
sev1daemon show-config                          # dump effective config as JSON
```

All commands accept `-c / --config` (default `config.yaml`).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the dev setup, code layout and the
delivery guarantees changes must keep. Report security issues privately as
described in [SECURITY.md](SECURITY.md).

## Troubleshooting

**`state_db parent directory not writable`** — Daemon user can't write to the
state path. With systemd, check `User=` matches directory ownership
(`chown -R sev1daemon:sev1daemon /var/lib/sev1daemon`).

**`github.no_token` warning at startup** — No `GITHUB_TOKEN` set. Daemon
continues but GHSA ingestor is rate-limited to 60 req/h and stars enrichment
is unavailable. A fine-grained token with read-only access to public
repositories is enough.

**`/readyz` returns 503 forever** — At least one ingestor must complete a
successful poll. Check `poll.source_failed` events in logs and inspect
`poll_state` table:

```bash
sqlite3 state/sev1daemon.db "SELECT * FROM poll_state"
```

**Advisory stuck pending** — its actions keep failing or being skipped.
Check `last_error`:

```bash
sqlite3 state/sev1daemon.db "SELECT id, attempts, last_error FROM advisories WHERE processed = 0"
```

After `advisory_max_attempts` cycles it is marked processed with
`last_error` starting `gave up:`; fix the action and use `sev1daemon replay`.

**Alerts firing on packages I don't care about** — Lower the per-action
`min_score` ceiling, add an `ecosystems` whitelist, or raise
`blast_radius.score_threshold` globally.

## License

[MIT](LICENSE)
