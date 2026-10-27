# AEGIS community core — PreFlight server. Self-contained, zero egress at runtime.
# Pin the base by digest in your registry mirror for reproducible, air-gap-transferable
# builds (docker buildx imagetools inspect python:3.11-slim-bookworm). Tag pinned here.
FROM python:3.11-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# deps first for layer caching (runtime only — no test/security tooling in the image)
COPY requirements.txt /app/aegis/requirements.txt
RUN pip install -r /app/aegis/requirements.txt

# unprivileged runtime user; the ledger lives on a volume it owns
RUN groupadd --system --gid 10001 aegis \
 && useradd --system --uid 10001 --gid aegis --home-dir /nonexistent --shell /usr/sbin/nologin aegis \
 && mkdir -p /var/lib/aegis && chown aegis:aegis /var/lib/aegis

# the package (read-only to the runtime user)
COPY --chown=root:root . /app/aegis

USER aegis
EXPOSE 8088
# Inside the container the server must listen on all container interfaces — serve.py
# defaults to loopback, which made the published port unreachable. Exposure to the HOST
# is controlled by the compose port binding (127.0.0.1 by default), not here.
ENV AEGIS_HOST=0.0.0.0 \
    AEGIS_PORT=8088

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8088/healthz', timeout=2).status == 200 else 1)"]

# One worker by default because the community tier uses an EPHEMERAL per-process seal key.
# The ledger (single-use approvals + hash chain) is multi-process safe: every write re-syncs
# under flock. To scale out, pin AEGIS_SEAL_KEY and share AEGIS_LEDGER_PATH on a POSIX
# filesystem with working flock (local disk; not every NFS mount honours it). /metrics
# counters stay per-process.
CMD ["gunicorn", "--chdir", "/app", "--workers", "1", "--threads", "8", \
     "--bind", "0.0.0.0:8088", "--access-logfile", "-", "--timeout", "120", \
     "aegis.serve:app"]
