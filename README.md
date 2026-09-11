# cvedaemon

Daemon that watches critical OSS vulnerabilities (CVSS ≥ 9.0) and **supply
chain compromises** — two fundamentally different threat classes, one unified
alert stream. Fires actions only when it matters: CVEs are scored by blast
radius (popularity), supply chain attacks always fire immediately.

## Why

**CVEs:** Every feed reports thousands of CRITICAL vulnerabilities a year.
Most affect packages nobody uses. cvedaemon enriches each affected package
with popularity signals (stars, downloads, dependents) and only triggers when
a configurable score threshold is crossed.

**Supply chain attacks:** Backdoors, typosquats, dependency confusion, and
maintainer account takeovers don't get CVEs. They hit security news and
malicious-package databases before (or instead of) advisory feeds. cvedaemon
watches RSS feeds (TheHackerNews, OpenSSF Malicious Packages) for these
threats and fires immediately — popularity scoring is irrelevant when a
package is actively compromised.

## Features

### CVE monitoring
- Polls **OSV.dev**, **NVD API 2.0**, and **GitHub Global Advisories**
- Enriches across **12 ecosystems**: npm, PyPI, RubyGems, crates.io, NuGet,
  Maven, Go, Composer, Pub, Hex, Swift, GitHub Actions
- Scoring blends **GitHub stars + registry downloads + deps.dev dependents**
- Default threshold **70** — needs strong signal in 2+ dimensions to fire

### Supply chain attack early warning
- Watches **RSS/Atom feeds** for supply chain compromise reports
- Default feeds: **TheHackerNews** + **OpenSSF Malicious Packages**
- Configurable keyword filters (supply chain, backdoor, typosquat, malware, etc.)
- **Bypasses scorer entirely** — always fires at score 100
- Extracts CVE/GHSA IDs from articles when present for cross-reference
- Auto-detects mentioned ecosystems (npm, PyPI, etc.) from article text

### Infrastructure
- Four pluggable actions: **webhook**, **GitHub issue**, **shell**, **Nebari CVE response**
- SQLite-backed dedupe — no double-alerting on the same advisory
- Per-source rate-limit awareness (NVD windowing, GitHub Link-pagination)
- Async HTTP with on-disk response cache (TTL eviction on startup)
- K8s-ready `/healthz` + `/readyz` + `/livez` probes
- Structured JSON logs to stdout
- Webhook URLs auto-redacted from logs and DB (Slack/Discord/Teams hosts)

## Quick start

```bash
pip install .
cp config.example.yaml config.yaml
# edit config.yaml — set GITHUB_TOKEN at minimum
cvedaemon run --config config.yaml
```

One-shot poll without daemon loop:

```bash
cvedaemon check --config config.yaml
```

Score a single package:

```bash
cvedaemon score --ecosystem npm --name react --config config.yaml
```

## Architecture

```
             CVE PIPELINE                          SUPPLY CHAIN PIPELINE
┌──────────────┐ ┌──────────────┐ ┌────────────┐  ┌───────────────────────┐
│  OSV.dev     │ │  NVD API 2.0 │ │ GitHub GHSA│  │  RSS/Atom feeds       │
└──────┬───────┘ └──────┬───────┘ └──────┬─────┘  │  (TheHackerNews,      │
       └────────────────┼────────────────┘         │   OpenSSF Malicious)  │
                        ▼                          └───────────┬───────────┘
              ┌──────────────────┐                             │
              │  dedupe + merge  │ ←───────────────────────────┘
              └─────────┬────────┘
                        ▼
              ┌──────────────────┐
              │  OSV enrichment  │  ← cross-ref affected packages
              └─────────┬────────┘
                        ▼
                ┌───────┴───────┐
                │               │
          CVE path         Supply chain path
                │               │
                ▼               ▼
       ┌────────────┐   ┌─────────────┐
       │  enrich +  │   │  BYPASS     │
       │  score     │   │  score=100  │
       │  (0..100)  │   │  always fire│
       └─────┬──────┘   └──────┬──────┘
             └────────┬────────┘
                      ▼
            ┌──────────────────┐
            │  actions         │
            └──────────────────┘
```

Each poll cycle:

1. **Fetch** advisories from each enabled source in parallel, since the last
   successful poll (with 1-min overlap to avoid edge-misses).
2. **Merge** advisories by ID across sources (richer affected list wins).
3. **Skip** advisories already fully processed (stored in SQLite).
4. **Route** by source type:
   - **CVE path:** Enrich each affected package (stars, downloads, dependents),
     score 0..100, fire actions only if score ≥ threshold.
   - **Supply chain path:** Skip enrichment and scoring entirely. Score fixed
     at 100, always fires — popularity is irrelevant for active compromises.
5. **Fire** matching actions; record each invocation in `action_log` table.

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

A signal we can't fetch contributes 0 — conservative in the trigger direction.
Default threshold is **70**, so a package needs strong signal in at least two
of three dimensions to alert.

Per-ecosystem download thresholds (configurable):

All download thresholds normalized to ~100K weekly downloads equivalent
(window varies per registry):

| Ecosystem | Window | Default min |
|---|---|---|
| npm | weekly | 100K |
| PyPI | monthly | 400K (≈ 100K/wk × 4.3) |
| RubyGems | total | 10M (≈ 2yr of 100K/wk) |
| crates.io | recent (60d) | 800K (≈ 100K/wk × 8.5) |
| NuGet | total | 10M (≈ 2yr of 100K/wk) |
| Maven | deps.dev dependents | 1000 |
| Go | deps.dev dependents | 1000 |

## Actions

| Type | Use |
|---|---|
| `webhook` | Generic JSON POST. Configurable URL, method, headers. Pipe to internal API, n8n, etc. |
| `github_issue` | Open issue in a repo via REST. Configurable labels + assignees. |
| `shell` | Run a templated command. Payload exposed as `CVEDAEMON_*` env vars and `{{...}}` template vars. Opt-in (dangerous by design). |
| `nebari_cve_response` | Shells out to `cve_response.py` for Nebari SBOM exposure checks across customer environments. |

Each action accepts:

| Field | Purpose |
|---|---|
| `name` | Identifier for `cvedaemon test-action --action NAME` |
| `enabled` | Skip without removing |
| `min_score` | Per-action threshold (≥ global threshold) |
| `ecosystems` | Whitelist (e.g. `["npm", "PyPI"]`) |

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
      - name: openssf-malicious
        url: "https://github.com/ossf/malicious-packages/commits/main.atom"
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
| `min_cvss` | 9.0 | Drop advisories below this score |
| `state_db` | `./state/cvedaemon.db` | SQLite path |
| `action_log_retention_days` | 90 | Auto-prune `action_log` rows |
| `processed_packages_retention_days` | 365 | Auto-prune `processed_packages` |
| `startup_grace_seconds` | 300 | `/healthz` returns OK during startup |
| `health_host` / `health_port` | `127.0.0.1:8080` | Probes + `/metrics`. Use `0.0.0.0` in Docker/k8s |
| `action_circuit_failures` | 5 | Skip an action after N errors in the window |
| `allow_private_urls` | false | Webhook SSRF guard (keep false in prod) |
| `log_level` | `INFO` | structlog level |
| `log_json` | true | JSON or console rendering |

## Operations

### Health endpoints

| Path | Use | Behavior |
|---|---|---|
| `GET /healthz` | k8s `livenessProbe` | OK during grace, then OK iff a poll succeeded recently |
| `GET /readyz` | k8s `readinessProbe` | Strict: OK only after first successful poll, no grace |
| `GET /livez` | basic liveness | Always 200, just confirms process responds |
| `GET /metrics` | Prometheus scrape | Counters/histograms for cycles, sources, actions |

### State

SQLite at `state_db` path, WAL mode. Tables:

| Table | Contents |
|---|---|
| `advisories` | Every advisory seen (id, source, cvss, payload, processed flag) |
| `processed_packages` | Per-package score record (advisory × ecosystem × package) |
| `action_log` | Every action invocation (status, redacted detail, timestamp) |
| `poll_state` | Per-source last success / last attempt / last error |

Inspect:

```bash
sqlite3 state/cvedaemon.db "SELECT advisory_id, action_name, status, ran_at FROM action_log ORDER BY id DESC LIMIT 20"
```

### Logs

JSON to stdout (one line per event). Pipe to whatever ships logs (Loki,
Splunk, Datadog, plain `journalctl`).

## Deployment

Deploy as a long-running systemd unit. `systemd/cvedaemon.service` ships
hardened defaults (`NoNewPrivileges`, `ProtectSystem=strict`,
`MemoryDenyWriteExecute`, etc). Creates user `cvedaemon`, state at
`/var/lib/cvedaemon`, env file at `/etc/cvedaemon/env`, config at
`/etc/cvedaemon/config.yaml`.

```bash
useradd --system --home /opt/cvedaemon cvedaemon
install -d -o cvedaemon /opt/cvedaemon /var/lib/cvedaemon /etc/cvedaemon
python -m venv /opt/cvedaemon/.venv
/opt/cvedaemon/.venv/bin/pip install cvedaemon
cp systemd/cvedaemon.service /etc/systemd/system/
cp config.example.yaml /etc/cvedaemon/config.yaml
install -m 600 /dev/null /etc/cvedaemon/env   # required; unit has no '-' prefix
# edit /etc/cvedaemon/config.yaml + /etc/cvedaemon/env (GITHUB_TOKEN=...)
# for systemd keep health_host: 127.0.0.1
systemctl daemon-reload
systemctl enable --now cvedaemon
journalctl -u cvedaemon -f
```

### Docker

```bash
cp config.example.yaml config.yaml
# GITHUB_TOKEN in the environment; compose sets CVEDAEMON_HEALTH_HOST=0.0.0.0
docker compose up --build -d
curl -fsS http://127.0.0.1:8080/livez
curl -fsS http://127.0.0.1:8080/metrics | head
```

Config is **not** baked into the image. Mount `/etc/cvedaemon/config.yaml` or
the container exits on `FileNotFoundError`. State lives in
`/var/lib/cvedaemon` (uid 10001).

For local / non-systemd hosts, run `cvedaemon run --config config.yaml`
under any process supervisor (`supervisord`, `runit`, `tmux`).

## Environment variables

| Variable | Required? | Purpose |
|---|---|---|
| `GITHUB_TOKEN` | strongly recommended | GHSA ingestor + stars enrichment. Without it, GitHub rate limit drops to 60 req/h and the daemon will silently degrade. |
| `NVD_API_KEY` | optional | Raises NVD rate limit from 5/30s to 50/30s |
| `SCA_TOKEN` | optional | Bearer token for the example webhook action |

Any value referenced as `${VAR}` in `config.yaml` is expanded at load time.

## CLI

```
cvedaemon run                                  # daemon loop
cvedaemon check                                # one-shot poll
cvedaemon test-action --action NAME            # synthetic alert to one action
cvedaemon score --ecosystem npm --name react   # score a single package
cvedaemon show-config                          # dump effective config as JSON
```

All commands accept `-c / --config` (default `config.yaml`).

## Development

```bash
pip install -e ".[dev]"
pytest -q
ruff check src/ tests/
mypy src/
```

## Troubleshooting

**`state_db parent directory not writable`** — Daemon user can't write to the
state path. With systemd, check `User=` matches directory ownership
(`chown -R cvedaemon:cvedaemon /var/lib/cvedaemon`).

**`github.no_token` warning at startup** — No `GITHUB_TOKEN` set. Daemon
continues but GHSA ingestor is rate-limited to 60 req/h and stars enrichment
is unavailable. Generate a fine-grained token with `public_repo` read scope.

**`/readyz` returns 503 forever** — At least one ingestor must complete a
successful poll. Check `poll.source_failed` events in logs and inspect
`poll_state` table:

```bash
sqlite3 state/cvedaemon.db "SELECT * FROM poll_state"
```

**Alerts firing on packages I don't care about** — Lower the per-action
`min_score` ceiling, add an `ecosystems` whitelist, or raise
`blast_radius.score_threshold` globally.

## License

MIT
