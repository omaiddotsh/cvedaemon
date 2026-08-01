"""HTTP health + metrics endpoints.

Routes:
* ``/livez``   — always 200; signals the process is alive.
* ``/healthz`` — 200 inside startup grace OR if a poll succeeded within the
                  stale window; otherwise 503. Wire to k8s livenessProbe so a
                  wedged daemon (no successful poll) gets restarted.
* ``/readyz``  — 200 once at least one poll has succeeded. Wire to
                  readinessProbe so traffic/alerts only flow when data is fresh.
* ``/metrics`` — Prometheus text-exposition rendering of ``Metrics``.

We use ``ThreadingHTTPServer`` to keep this dependency-free. The thread pool
is implicitly bounded by ``BaseHTTPServer``'s per-request thread spawn —
fine for k8s probes (low concurrency by design) and Prometheus scrape
intervals (≥ 5s).
"""

from __future__ import annotations

import json
import threading
import time
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from cvedaemon.metrics import Metrics


class HealthState:
    """Mutable shared state between the daemon loop and the HTTP handler."""

    def __init__(self, grace_seconds: int, stale_seconds: int):
        self._started_at = time.monotonic()
        self._grace = grace_seconds
        self._stale = stale_seconds
        self._lock = threading.Lock()
        self._last_success: float | None = None
        self._poll_in_progress = False

    def mark_success(self) -> None:
        with self._lock:
            self._last_success = time.monotonic()

    def mark_poll_start(self) -> None:
        with self._lock:
            self._poll_in_progress = True

    def mark_poll_end(self) -> None:
        with self._lock:
            self._poll_in_progress = False

    def in_grace(self) -> bool:
        return (time.monotonic() - self._started_at) < self._grace

    def healthz_ok(self) -> bool:
        # OK during grace; otherwise OK iff a poll succeeded within stale window.
        if self.in_grace():
            return True
        with self._lock:
            if self._last_success is None:
                return False
            return (time.monotonic() - self._last_success) < self._stale

    def readyz_ok(self) -> bool:
        with self._lock:
            return self._last_success is not None

    def snapshot(self) -> dict[str, object]:
        with self._lock:
            last_success = self._last_success
            poll_in_progress = self._poll_in_progress
        return {
            "in_grace": self.in_grace(),
            "last_success_seconds_ago": (
                None
                if last_success is None
                else round(time.monotonic() - last_success, 1)
            ),
            "stale_seconds": self._stale,
            "poll_in_progress": poll_in_progress,
        }


def _make_handler(
    state: HealthState, metrics: Metrics | None
) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args, **_kwargs):
            # Silence stdlib access log — daemon emits its own structured JSON.
            return

        def _respond(self, code: int, body: bytes, content_type: str = "application/json") -> None:
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):  # noqa: N802
            path = self.path.split("?")[0]
            if path == "/livez":
                self._respond(200, b'{"status":"ok"}')
                return
            if path == "/healthz":
                ok = state.healthz_ok()
                payload = json.dumps({"status": "ok" if ok else "fail", **state.snapshot()})
                self._respond(200 if ok else 503, payload.encode())
                return
            if path == "/readyz":
                ok = state.readyz_ok()
                payload = json.dumps({"status": "ok" if ok else "fail", **state.snapshot()})
                self._respond(200 if ok else 503, payload.encode())
                return
            if path == "/metrics":
                if metrics is None:
                    self._respond(404, b'{"status":"metrics_disabled"}')
                    return
                body, content_type = metrics.render()
                self._respond(200, body, content_type=content_type)
                return
            self._respond(404, b'{"status":"not_found"}')

    return Handler


def start_health_server(
    host: str,
    port: int,
    state: HealthState,
    metrics: Metrics | None = None,
) -> Callable[[], None]:
    """Start HTTP server in background thread. Returns shutdown callable."""
    handler = _make_handler(state, metrics)
    server = ThreadingHTTPServer((host, port), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True, name="cvedaemon-health")
    thread.start()

    def shutdown() -> None:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2.0)

    return shutdown
