# syntax=docker/dockerfile:1.7

# ---------- builder ----------
# Pinned to a specific patch version and digest so image rebuilds are
# reproducible. Bump both deliberately as part of a security review (CVE
# bulletins, base OS) and rescan the image (e.g. Trivy) afterwards.
FROM python:3.12.15-slim-trixie@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1 AS builder

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
    /opt/venv/bin/pip install --upgrade "pip==26.2.1" && \
    /opt/venv/bin/pip install -r requirements.lock && \
    /opt/venv/bin/pip install --no-deps . && \
    /opt/venv/bin/pip uninstall --yes pip
# pip isn't needed at runtime, and its vendored libraries (urllib3, msgpack, ...)
# show up as findings in image scans, so neither venv nor base image ships it.

# ---------- runtime ----------
FROM python:3.12.15-slim-trixie@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1 AS runtime

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/opt/venv/bin:${PATH}" \
    SEV1DAEMON_HEALTH_PORT=8080

# Non-root user; drop the base image's pip (see builder stage)
RUN python -m pip uninstall --yes --root-user-action=ignore pip && \
    groupadd --system --gid 10001 sev1daemon && \
    useradd --system --uid 10001 --gid sev1daemon --home /var/lib/sev1daemon --shell /usr/sbin/nologin sev1daemon && \
    mkdir -p /var/lib/sev1daemon /etc/sev1daemon && \
    chown -R sev1daemon:sev1daemon /var/lib/sev1daemon

# Install only the venv from builder
COPY --from=builder /opt/venv /opt/venv

# NOTE: config.example.yaml is intentionally NOT bundled into the runtime
# image. A missing /etc/sev1daemon/config.yaml must fail loud (FileNotFoundError
# in Config.load) rather than silently fall back to an example with all
# actions disabled.

USER sev1daemon
WORKDIR /var/lib/sev1daemon

EXPOSE 8080

# Healthcheck reads the same port the daemon binds to; if you override
# health_port in config, also override SEV1DAEMON_HEALTH_PORT at run time
# (-e SEV1DAEMON_HEALTH_PORT=9090) so the docker healthcheck stays accurate.
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
    CMD python -c "import os,urllib.request,sys; port=os.environ.get('SEV1DAEMON_HEALTH_PORT','8080'); r=urllib.request.urlopen(f'http://127.0.0.1:{port}/healthz', timeout=3); sys.exit(0 if r.status==200 else 1)"

ENTRYPOINT ["sev1daemon"]
CMD ["run", "--config", "/etc/sev1daemon/config.yaml"]
