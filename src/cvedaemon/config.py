"""Config loader. YAML + ``${ENV}`` / ``${file:path}`` expansion + pydantic validation.

Environment expansion supports three forms inside string values:

* ``${VAR}`` — replaced with ``os.environ["VAR"]`` (empty if unset).
* ``${VAR:-default}`` — replaced with the env var or the literal default.
* ``${file:/abs/path}`` — replaced with the trimmed contents of that file.
  Useful for k8s secrets mounted as files.

Validators enforce a small safety contract:

* webhook URLs parse as http(s) with a host.
* GithubIssueAction.repo is ``owner/repo`` (no path traversal).
* NebariAction.script_path exists as a regular file.
* poll_interval > 0, retention days >= 0, min_cvss in [0, 10].
* Action names are unique inside a config.
* At least one source is enabled.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field, field_validator, model_validator

ECOSYSTEMS = [
    "npm",
    "PyPI",
    "RubyGems",
    "crates.io",
    "NuGet",
    "Maven",
    "Go",
    "Packagist",
    "Pub",
    "Hex",
    "SwiftURL",
    "GitHub Actions",
]


_ENV_PATTERN = re.compile(r"\$\{([A-Z_][A-Z0-9_]*)(?::-([^}]*))?\}")
_FILE_PATTERN = re.compile(r"\$\{file:([^}]+)\}")


def _read_secret_file(path: str) -> str:
    """Read a secret file. Strips trailing whitespace (typical for newline-terminated files)."""
    try:
        return Path(path).read_text().rstrip()
    except OSError as exc:
        raise ValueError(f"failed to read secret file {path!r}: {exc}") from exc


def _expand_env(value: Any) -> Any:
    """Expand ``${VAR}``, ``${VAR:-default}``, and ``${file:/abs/path}`` recursively."""
    if isinstance(value, str):
        def sub_env(match: re.Match[str]) -> str:
            name, default = match.group(1), match.group(2)
            return os.environ.get(name, default if default is not None else "")

        def sub_file(match: re.Match[str]) -> str:
            return _read_secret_file(match.group(1))

        expanded = _ENV_PATTERN.sub(sub_env, value)
        expanded = _FILE_PATTERN.sub(sub_file, expanded)
        return expanded
    if isinstance(value, dict):
        return {k: _expand_env(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_expand_env(v) for v in value]
    return value


# ---------- source configs ----------


class OsvSourceConfig(BaseModel):
    enabled: bool = True
    base_url: str = "https://api.osv.dev"
    ecosystems: list[str] = Field(default_factory=lambda: list(ECOSYSTEMS))


class NvdSourceConfig(BaseModel):
    enabled: bool = True
    base_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    api_key: str = ""
    results_per_page: int = 200


class GithubSourceConfig(BaseModel):
    enabled: bool = True
    base_url: str = "https://api.github.com"
    token: str = ""
    severity: list[str] = Field(default_factory=lambda: ["critical"])


class RssFeed(BaseModel):
    name: str
    url: str


class RssSourceConfig(BaseModel):
    enabled: bool = False
    feeds: list[RssFeed] = Field(default_factory=list)
    keywords: list[str] = Field(
        default_factory=lambda: [
            "supply chain",
            "malicious package",
            "backdoor",
            "typosquat",
            "dependency confusion",
            "malware",
            "compromised package",
            "account takeover",
        ]
    )


class SourcesConfig(BaseModel):
    osv: OsvSourceConfig = Field(default_factory=OsvSourceConfig)
    nvd: NvdSourceConfig = Field(default_factory=NvdSourceConfig)
    github: GithubSourceConfig = Field(default_factory=GithubSourceConfig)
    rss: RssSourceConfig = Field(default_factory=RssSourceConfig)


# ---------- enrichment + scoring ----------


class StarsConfig(BaseModel):
    weight: int = 40
    saturate_at: int = 5000


class DownloadsConfig(BaseModel):
    weight: int = 40
    thresholds: dict[str, int] = Field(
        default_factory=lambda: {
            "npm": 100_000,
            "PyPI": 400_000,
            "RubyGems": 10_000_000,
            "crates.io": 800_000,
            "NuGet": 10_000_000,
            "Maven": 1_000,
            "Go": 1_000,
            "Packagist": 50_000,
            "Pub": 5_000,
            "Hex": 5_000,
            "SwiftURL": 1_000,
            "GitHub Actions": 1_000,
        }
    )


class DepsDevConfig(BaseModel):
    weight: int = 20
    saturate_at: int = 1000


class BlastRadiusConfig(BaseModel):
    score_threshold: int = 70
    stars: StarsConfig = Field(default_factory=StarsConfig)
    downloads: DownloadsConfig = Field(default_factory=DownloadsConfig)
    depsdev: DepsDevConfig = Field(default_factory=DepsDevConfig)


# ---------- actions ----------


class ActionBase(BaseModel):
    name: str
    enabled: bool = True
    min_score: int = 0
    ecosystems: list[str] = Field(default_factory=list)
    type: str

    @field_validator("name")
    @classmethod
    def _name_nonempty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("action.name required")
        return v


# GitHub repo identifier: owner/repo. Each segment is alnum + dot/dash/underscore
# but must NOT start with a dot — `..` is path traversal, and GitHub itself
# rejects leading-dot names. Accept everything else GitHub accepts (max 100 chars
# enforced by the upper bound on the segment).
_REPO_RE = re.compile(r"^[A-Za-z0-9_\-][\w\-]{0,99}/[A-Za-z0-9_\-][\w\-.]{0,99}$")


class WebhookAction(ActionBase):
    type: Literal["webhook"] = "webhook"
    url: str
    method: str = "POST"
    headers: dict[str, str] = Field(default_factory=dict)
    timeout_seconds: float = 10.0

    @field_validator("url")
    @classmethod
    def _validate_url(cls, v: str) -> str:
        from urllib.parse import urlparse

        parsed = urlparse(v)
        if parsed.scheme not in ("http", "https"):
            raise ValueError(f"webhook url must be http(s): {v!r}")
        if not parsed.hostname:
            raise ValueError(f"webhook url missing host: {v!r}")
        return v

    @field_validator("method")
    @classmethod
    def _validate_method(cls, v: str) -> str:
        if v.upper() not in ("GET", "POST", "PUT", "PATCH", "DELETE"):
            raise ValueError(f"unsupported method: {v!r}")
        return v.upper()

    @field_validator("timeout_seconds")
    @classmethod
    def _validate_timeout(cls, v: float) -> float:
        if v <= 0:
            raise ValueError("timeout_seconds must be > 0")
        return v


class GithubIssueAction(ActionBase):
    type: Literal["github_issue"] = "github_issue"
    repo: str
    token: str
    labels: list[str] = Field(default_factory=list)
    assignees: list[str] = Field(default_factory=list)

    @field_validator("repo")
    @classmethod
    def _validate_repo(cls, v: str) -> str:
        if not _REPO_RE.match(v):
            # Refuses ../foo, owner/repo/extra, empty segments, and other
            # paths that could be smuggled into the issues URL.
            raise ValueError(f"repo must match 'owner/repo': {v!r}")
        return v


class ShellAction(ActionBase):
    type: Literal["shell"] = "shell"
    command: str
    timeout_seconds: float = 60.0

    @field_validator("command")
    @classmethod
    def _command_nonempty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("shell.command must be non-empty")
        return v

    @field_validator("timeout_seconds")
    @classmethod
    def _shell_timeout(cls, v: float) -> float:
        if v <= 0:
            raise ValueError("shell.timeout_seconds must be > 0")
        return v


class NebariAction(ActionBase):
    type: Literal["nebari_cve_response"] = "nebari_cve_response"
    script_path: str
    extra_args: list[str] = Field(default_factory=list)
    timeout_seconds: float = 300.0

    @field_validator("script_path")
    @classmethod
    def _validate_script(cls, v: str) -> str:
        # Resolve to catch symlink escapes. existence check lets misconfig fail
        # at load time instead of the first matching alert.
        path = Path(v).expanduser().resolve()
        if not path.is_file():
            raise ValueError(f"nebari script_path not a file: {v!r}")
        return str(path)


AnyAction = WebhookAction | GithubIssueAction | ShellAction | NebariAction


def _build_action(raw: dict[str, Any]) -> AnyAction:
    t = raw.get("type")
    table: dict[str, type[ActionBase]] = {
        "webhook": WebhookAction,
        "github_issue": GithubIssueAction,
        "shell": ShellAction,
        "nebari_cve_response": NebariAction,
    }
    if t not in table:
        raise ValueError(f"unknown action.type: {t!r}")
    return table[t](**raw)  # type: ignore[return-value]


# ---------- top-level ----------


class Config(BaseModel):
    poll_interval_seconds: int = 600
    # Hard ceiling on _run_cycle so a wedged source download cannot starve
    # the SIGTERM handler. Defaults to 4x poll interval; clamped to ≥120s.
    cycle_timeout_seconds: int = 0
    lookback_minutes_on_start: int = 1440
    min_cvss: float = 9.0
    state_db: str = "./state/cvedaemon.db"
    action_log_retention_days: int = 90
    processed_packages_retention_days: int = 365
    startup_grace_seconds: int = 300
    log_level: str = "INFO"
    log_json: bool = True
    # Bind health/metrics to loopback by default; expose externally only via
    # an explicit override (k8s sidecar/ingress, host firewall, etc).
    health_host: str = "127.0.0.1"
    health_port: int = 8080
    http_cache_dir: str = "./state/http-cache"
    http_cache_ttl_seconds: int = 3600

    # Circuit breaker for outbound actions. If an action records this many
    # error rows in the trailing window, it's skipped until the window passes.
    action_circuit_failures: int = 5
    action_circuit_window_seconds: int = 600

    # Per-host outbound rate limiting (token bucket) for webhook + github_issue
    # actions. 0 disables.
    action_rate_per_second: float = 5.0
    action_rate_burst: int = 5

    # SSRF guard for webhook action targets. Set false only for trusted private
    # destinations (e.g. internal SOAR). Loopback/link-local always allowed
    # when allow_private_urls=true; never when false.
    allow_private_urls: bool = False

    sources: SourcesConfig = Field(default_factory=SourcesConfig)
    blast_radius: BlastRadiusConfig = Field(default_factory=BlastRadiusConfig)
    actions: list[AnyAction] = Field(default_factory=list)

    @field_validator("min_cvss")
    @classmethod
    def _cvss_range(cls, v: float) -> float:
        if not 0.0 <= v <= 10.0:
            raise ValueError("min_cvss must be between 0 and 10")
        return v

    @field_validator("poll_interval_seconds")
    @classmethod
    def _poll_positive(cls, v: int) -> int:
        if v <= 0:
            raise ValueError("poll_interval_seconds must be > 0")
        return v

    @field_validator("action_log_retention_days", "processed_packages_retention_days")
    @classmethod
    def _retention_positive(cls, v: int) -> int:
        if v < 0:
            raise ValueError("retention days must be >= 0")
        return v

    def effective_cycle_timeout(self) -> float:
        """Resolve cycle timeout. 0 = derived from poll interval."""
        if self.cycle_timeout_seconds > 0:
            return float(self.cycle_timeout_seconds)
        return float(max(self.poll_interval_seconds * 4, 120))

    @model_validator(mode="after")
    def _at_least_one_source(self) -> Config:
        s = self.sources
        if not (s.osv.enabled or s.nvd.enabled or s.github.enabled or s.rss.enabled):
            raise ValueError(
                "at least one source must be enabled "
                "(sources.osv|nvd|github|rss .enabled=true)"
            )
        return self

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> Config:
        raw = _expand_env(raw)
        raw_actions = raw.pop("actions", []) or []
        cfg = cls(**raw)
        cfg.actions = [_build_action(a) for a in raw_actions]
        # Action names must be unique inside a config — otherwise test-action
        # --action=name is ambiguous and dispatch logs collapse two distinct
        # outbound integrations onto one identity.
        seen: set[str] = set()
        for a in cfg.actions:
            if a.name in seen:
                raise ValueError(f"duplicate action name: {a.name!r}")
            seen.add(a.name)
        return cfg

    @classmethod
    def load(cls, path: str | Path) -> Config:
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"config not found: {p}")
        with p.open() as f:
            raw = yaml.safe_load(f) or {}
        if not isinstance(raw, dict):
            raise ValueError("config root must be a mapping")
        return cls.from_dict(raw)
