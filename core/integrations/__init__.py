"""In-perimeter integrations: ServiceNow (ITSM), NetBox (source of truth).

Every integration is OFF until its URL is configured, and every call is an explicit,
ledgered, operator-triggered action, never a side effect of a preflight run. The sealed
``integrity.egress: "none"`` describes the preflight run, and it stays true.

Perimeter rule (``assert_integration_url``): air-gap is the default, so an integration
URL must be loopback, or its host must be listed in ``AEGIS_INTEGRATION_HOSTS``. That list
is the operator's explicit declaration that the host (a ServiceNow MID/proxy, an internal
NetBox) is inside the perimeter. AEGIS never resolves DNS to decide this. With
``AEGIS_AIRGAP=0`` any host is allowed. Plain http is accepted only for loopback.
"""
from __future__ import annotations

import os
from urllib.parse import urlparse

from ..llm.airgap import airgap_enabled, is_loopback


class IntegrationError(Exception):
    """An integration call failed. ``str()`` is safe to show (no credentials, no body)."""


def allowed_hosts() -> set[str]:
    raw = os.environ.get("AEGIS_INTEGRATION_HOSTS") or ""
    return {h.strip().lower() for h in raw.split(",") if h.strip()}


def assert_integration_url(name: str, url: str) -> str:
    """Return the normalized base URL or raise IntegrationError (fail closed)."""
    u = urlparse((url or "").strip())
    host = (u.hostname or "").lower()
    if u.scheme not in ("https", "http") or not host:
        raise IntegrationError(f"{name}: URL must be http(s)://host")
    if u.username or u.password:
        raise IntegrationError(f"{name}: credentials must not be embedded in the URL")
    loop = is_loopback(url)
    if u.scheme == "http" and not loop:
        raise IntegrationError(f"{name}: plain http is only allowed to loopback; use https")
    if airgap_enabled() and not loop and host not in allowed_hosts():
        raise IntegrationError(
            f"{name}: host {host!r} is not declared in-perimeter (air-gap is the default; "
            "list it in AEGIS_INTEGRATION_HOSTS, or set AEGIS_AIRGAP=0)")
    return url.strip().rstrip("/")
