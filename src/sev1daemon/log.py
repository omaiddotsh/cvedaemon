"""structlog setup. JSON to stdout by default.

The ``_redact_processor`` runs after the standard structlog chain (level,
timestamp, contextvars) so anything any callsite logs gets scrubbed: webhook
URLs collapsed to ``<webhook>``, ``Bearer <token>`` headers collapsed to
``Bearer <redacted>``, raw secrets surfaced via redact patterns blanked. The
processor recurses into dicts, lists, and tuples so structured payloads
(``raw=...``, ``headers={...}``) get the same treatment as flat string
fields. Numeric / bool / None values pass through untouched.
"""

from __future__ import annotations

import logging
import sys
from typing import Any

import structlog

from sev1daemon.redact import redact

# Cap recursion depth so a malicious or buggy event payload with a circular
# reference can't trap us in a tight loop. 10 nested levels is well past any
# real log payload we emit.
_MAX_REDACT_DEPTH = 10


def _redact_value(value: Any, depth: int = 0) -> Any:
    if depth >= _MAX_REDACT_DEPTH:
        return value
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, dict):
        return {k: _redact_value(v, depth + 1) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        rebuilt = [_redact_value(v, depth + 1) for v in value]
        return type(value)(rebuilt) if isinstance(value, tuple) else rebuilt
    return value


def _redact_processor(_logger, _method, event_dict):
    for k, v in list(event_dict.items()):
        event_dict[k] = _redact_value(v)
    return event_dict


class _RedactStdlibFilter(logging.Filter):
    """Scrub stdlib log records (third-party libraries) the same way."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = redact(record.getMessage())
        record.args = None
        return True


# httpx/httpcore log every request URL at INFO, which would print webhook URLs
# and query strings outside the structlog redact chain (and as non-JSON lines).
_NOISY_STDLIB_LOGGERS = ("httpx", "httpcore")


def configure_logging(level: str = "INFO", json_output: bool = True) -> None:
    log_level = getattr(logging, level.upper(), logging.INFO)
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=log_level,
    )
    for handler in logging.getLogger().handlers:
        if not any(isinstance(f, _RedactStdlibFilter) for f in handler.filters):
            handler.addFilter(_RedactStdlibFilter())
    for name in _NOISY_STDLIB_LOGGERS:
        logging.getLogger(name).setLevel(max(log_level, logging.WARNING))
    renderer = (
        structlog.processors.JSONRenderer()
        if json_output
        else structlog.dev.ConsoleRenderer(colors=False)
    )
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            # log.exception() sets exc_info=True; without this the renderer
            # prints "exc_info": true and the traceback is lost. Rendered before
            # redaction so the traceback text is scrubbed too.
            structlog.processors.format_exc_info,
            _redact_processor,
            renderer,
        ],
        wrapper_class=structlog.make_filtering_bound_logger(log_level),
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str | None = None):
    return structlog.get_logger(name) if name else structlog.get_logger()
