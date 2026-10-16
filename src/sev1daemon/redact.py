"""Redact webhook URLs + bearer tokens from log/DB text."""

from __future__ import annotations

import re

_WEBHOOK_HOSTS = (
    "hooks.slack.com",
    "discord.com/api/webhooks",
    "discordapp.com/api/webhooks",
    "outlook.office.com/webhook",
    "outlook.office.com/webhookb2",
    "office.com/webhook",
)

_URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
_BEARER_RE = re.compile(r"(?i)(bearer|token)\s+[A-Za-z0-9._\-]{8,}")
_GITHUB_TOKEN_RE = re.compile(r"gh[pousr]_[A-Za-z0-9_]{20,}")
# Match a single header value (no whitespace, stops at quotes/commas/newlines)
# so trailing fields in a log line aren't swept into the redaction.
_HEADER_TOKEN_RE = re.compile(
    r"(?i)(authorization|x-api-key|x-auth-token)\s*[:=]\s*[A-Za-z0-9._\-+/=]+",
)


def redact(text: str) -> str:
    if not text:
        return text

    def _maybe_redact_url(m: re.Match[str]) -> str:
        url = m.group(0)
        low = url.lower()
        for host in _WEBHOOK_HOSTS:
            if host in low:
                # keep scheme + host, redact path/query
                idx = low.find(host)
                end = idx + len(host)
                return url[:end] + "/<redacted>"
        return url

    out = _URL_RE.sub(_maybe_redact_url, text)
    out = _BEARER_RE.sub(lambda m: f"{m.group(1)} <redacted>", out)
    out = _GITHUB_TOKEN_RE.sub("<redacted-gh-token>", out)
    out = _HEADER_TOKEN_RE.sub(lambda m: f"{m.group(1)}: <redacted>", out)
    return out
