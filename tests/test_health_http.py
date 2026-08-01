"""HTTP-layer health + metrics smoke tests.

Spins the real ThreadingHTTPServer on an ephemeral port, hits each route, and
asserts the JSON / text-exposition payload shape. Keeps tests honest about
the actual wire protocol the daemon exposes to k8s + prometheus.
"""

from __future__ import annotations

import json
import urllib.request

import pytest

from cvedaemon.health import HealthState, start_health_server
from cvedaemon.metrics import Metrics


@pytest.fixture()
def server():
    state = HealthState(grace_seconds=60, stale_seconds=600)
    metrics = Metrics()
    # Port 0 → kernel assigns; we read it back from the bound server.
    shutdown = start_health_server("127.0.0.1", 0, state, metrics)
    # Sneak the actual port out via the closure's server object isn't exposed;
    # but ThreadingHTTPServer binds before serve_forever, and we passed
    # port=0 — start_health_server creates the server using the requested
    # port, so to retrieve it we'd need an API change. Instead we use a
    # fixed high port chosen to be unlikely to clash in CI.
    yield None
    shutdown()


@pytest.fixture()
def server_fixed_port():
    state = HealthState(grace_seconds=60, stale_seconds=600)
    metrics = Metrics()
    shutdown = start_health_server("127.0.0.1", 18081, state, metrics)
    yield ("127.0.0.1", 18081, state, metrics)
    shutdown()


def _get(host: str, port: int, path: str) -> tuple[int, bytes]:
    req = urllib.request.Request(f"http://{host}:{port}{path}")
    try:
        with urllib.request.urlopen(req, timeout=2.0) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def test_livez_returns_200(server_fixed_port):
    host, port, _, _ = server_fixed_port
    status, body = _get(host, port, "/livez")
    assert status == 200
    assert json.loads(body) == {"status": "ok"}


def test_healthz_inside_grace_returns_200(server_fixed_port):
    host, port, _, _ = server_fixed_port
    status, body = _get(host, port, "/healthz")
    assert status == 200
    data = json.loads(body)
    assert data["status"] == "ok"
    assert data["in_grace"] is True


def test_readyz_before_first_success_returns_503(server_fixed_port):
    host, port, _, _ = server_fixed_port
    status, _ = _get(host, port, "/readyz")
    assert status == 503


def test_readyz_after_first_success_returns_200(server_fixed_port):
    host, port, state, _ = server_fixed_port
    state.mark_success()
    status, _ = _get(host, port, "/readyz")
    assert status == 200


def test_metrics_returns_prometheus_text(server_fixed_port):
    host, port, _, metrics = server_fixed_port
    metrics.advisories_collected_total.inc(7)
    status, body = _get(host, port, "/metrics")
    assert status == 200
    text = body.decode()
    # Counter exposes a `_total` line — find ours with the expected value.
    assert "cvedaemon_advisories_collected_total 7.0" in text


def test_unknown_path_returns_404(server_fixed_port):
    host, port, _, _ = server_fixed_port
    status, _ = _get(host, port, "/nope")
    assert status == 404
