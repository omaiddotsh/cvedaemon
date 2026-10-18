from sev1daemon.redact import redact


def test_slack_webhook_redacted():
    out = redact("posting to https://hooks.slack.com/services/T000/B000/secrettoken now")
    assert "secrettoken" not in out
    assert "hooks.slack.com" in out
    assert "<redacted>" in out


def test_discord_webhook_redacted():
    out = redact("https://discord.com/api/webhooks/123/abcXYZsecret/")
    assert "abcXYZsecret" not in out
    assert "<redacted>" in out


def test_teams_webhook_redacted():
    out = redact("https://outlook.office.com/webhook/aaa/IncomingWebhook/bbb")
    assert "IncomingWebhook" not in out
    assert "<redacted>" in out


def test_bearer_token_redacted():
    out = redact("Authorization: Bearer ghp_abc1234567890supersecret")
    assert "ghp_abc1234567890supersecret" not in out
    assert "<redacted>" in out


def test_github_token_redacted():
    out = redact("token is ghp_AAAAAAAAAAAAAAAAAAAA1234")
    assert "ghp_AAAAAAAAAAAAAAAAAAAA1234" not in out


def test_non_webhook_url_left_alone():
    out = redact("see https://github.com/foo/bar for details")
    assert out == "see https://github.com/foo/bar for details"


def test_stdlib_http_logs_are_quiet_and_redacted():
    import logging

    from sev1daemon.log import _RedactStdlibFilter, configure_logging

    configure_logging("INFO", json_output=True)
    # httpx logs every request URL at INFO; it must not reach the output.
    assert logging.getLogger("httpx").getEffectiveLevel() >= logging.WARNING
    assert logging.getLogger("httpcore").getEffectiveLevel() >= logging.WARNING

    # Anything else that logs through stdlib gets the same redaction as structlog.
    url = "https://hooks.slack.com/services/T000/B000/XXXXSECRETXXXX"
    record = logging.LogRecord("some.lib", logging.WARNING, __file__, 1, "posting to %s", (url,), None)
    assert _RedactStdlibFilter().filter(record) is True
    assert "XXXXSECRETXXXX" not in record.getMessage()
    assert record.getMessage().startswith("posting to ")


def test_log_exception_renders_and_redacts_the_traceback(capsys):
    """log.exception() must print the traceback (not ``"exc_info": true``),
    and the traceback text goes through the same redaction as everything else."""
    import structlog

    from sev1daemon.log import configure_logging, get_logger

    configure_logging("INFO", json_output=True)
    structlog.configure(cache_logger_on_first_use=False)
    log = get_logger("review")
    try:
        raise RuntimeError("posted to https://hooks.slack.com/services/T/B/supersecret")
    except RuntimeError:
        log.exception("action.unhandled", action="hook")
    out = capsys.readouterr().out
    assert "Traceback (most recent call last)" in out
    assert "RuntimeError" in out
    assert '"exc_info": true' not in out
    assert "supersecret" not in out
