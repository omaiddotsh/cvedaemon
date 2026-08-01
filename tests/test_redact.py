from cvedaemon.redact import redact


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
