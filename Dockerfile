# syntax=docker/dockerfile:1.7

# ---------- builder ----------
# Pinned to a specific patch version so image rebuilds are reproducible. Bump
# this tag deliberately as part of a security review (CVE bulletins, base OS).
FROM python:3.12.7-slim-bookworm AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /build

# Pre-fetch deps separately to maximize layer cache hits.
COPY pyproject.toml README.md ./
COPY requirements.lock ./
COPY src/ ./src/

# Pin pip itself before installing project deps so the resolver behavior is
# reproducible. Use the locked requirements when present; fall back to
# resolving from pyproject for development builds.
RUN python -m venv /opt/venv && \
    /opt/venv/bin/pip install --upgrade "pip==24.2" && \
    /opt/venv/bin/pip install -r requirements.lock && \
    /opt/venv/bin/pip install --no-deps .

# ---------- runtime ----------
FROM python:3.12.7-slim-bookworm AS runtime

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/opt/venv/bin:${PATH}" \
    CVEDAEMON_HEALTH_PORT=8080

# Non-root user
RUN groupadd --system --gid 10001 cvedaemon && \
    useradd --system --uid 10001 --gid cvedaemon --home /var/lib/cvedaemon --shell /usr/sbin/nologin cvedaemon && \
    mkdir -p /var/lib/cvedaemon /etc/cvedaemon && \
    chown -R cvedaemon:cvedaemon /var/lib/cvedaemon

# Install only the venv from builder
COPY --from=builder /opt/venv /opt/venv

# NOTE: config.example.yaml is intentionally NOT bundled into the runtime
# image. A missing /etc/cvedaemon/config.yaml must fail loud (FileNotFoundError
# in Config.load) rather than silently fall back to an example with all
# actions disabled.

USER cvedaemon
WORKDIR /var/lib/cvedaemon

EXPOSE 8080

# Healthcheck reads the same port the daemon binds to; if you override
# health_port in config, also override CVEDAEMON_HEALTH_PORT at run time
# (-e CVEDAEMON_HEALTH_PORT=9090) so the docker healthcheck stays accurate.
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
    CMD python -c "import os,urllib.request,sys; port=os.environ.get('CVEDAEMON_HEALTH_PORT','8080'); r=urllib.request.urlopen(f'http://127.0.0.1:{port}/healthz', timeout=3); sys.exit(0 if r.status==200 else 1)"

ENTRYPOINT ["cvedaemon"]
CMD ["run", "--config", "/etc/cvedaemon/config.yaml"]
