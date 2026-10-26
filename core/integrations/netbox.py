"""NetBox source of truth: device roles for the authority model and a sealed inventory rev.

  AEGIS_NETBOX_URL            https://netbox.corp.example (must be in-perimeter, see __init__)
  AEGIS_NETBOX_TOKEN          API token (read-only is enough)
  AEGIS_NETBOX_SPINE_ROLES    role slugs treated as spine     (default "spine,super-spine")
  AEGIS_NETBOX_UNDERLAY_ROLES role slugs treated as underlay  (default "super-spine,underlay,core")

Roles can only ADD authority flags (touches_spine / touches_underlay) on top of the
name/protocol heuristic. They never remove one, so a stale or missing NetBox record can
only make AEGIS stricter, never looser.

``inventory_rev`` is ``netbox:<sha256>`` over the sorted (name, role, status, primary IP,
last_updated) of the target devices. It is sealed in ``twin.inventory_rev`` and therefore
bound into every v2 approval token: if the inventory changes between approval and push,
the token no longer matches.
"""
from __future__ import annotations

import hashlib
import json
import os

import httpx

from . import IntegrationError, assert_integration_url

_TIMEOUT = httpx.Timeout(10.0, connect=5.0)
_MAX_DEVICES = 200


def configured() -> bool:
    return bool((os.environ.get("AEGIS_NETBOX_URL") or "").strip())


def _roles_env(name: str, default: str) -> set[str]:
    return {r.strip().lower() for r in (os.environ.get(name) or default).split(",") if r.strip()}


def spine_roles() -> set[str]:
    return _roles_env("AEGIS_NETBOX_SPINE_ROLES", "spine,super-spine")


def underlay_roles() -> set[str]:
    return _roles_env("AEGIS_NETBOX_UNDERLAY_ROLES", "super-spine,underlay,core")


def _slug(obj) -> str:
    if isinstance(obj, dict):
        return str(obj.get("slug") or obj.get("name") or "").lower()
    return str(obj or "").lower()


class NetBoxClient:
    def __init__(self, base_url: str | None = None, *, token: str | None = None,
                 transport: httpx.BaseTransport | None = None) -> None:
        url = base_url if base_url is not None else os.environ.get("AEGIS_NETBOX_URL", "")
        self.base = assert_integration_url("netbox", url)
        token = token if token is not None else (os.environ.get("AEGIS_NETBOX_TOKEN") or "")
        if not token.strip():
            raise IntegrationError("netbox: AEGIS_NETBOX_TOKEN is not set")
        self._http = httpx.Client(
            base_url=self.base, timeout=_TIMEOUT, transport=transport, trust_env=False,
            follow_redirects=False,
            headers={"Accept": "application/json", "Authorization": f"Token {token.strip()}"})

    def close(self) -> None:
        self._http.close()

    def devices(self, names: list[str]) -> list[dict]:
        names = sorted({n for n in names if n})[:_MAX_DEVICES]
        if not names:
            return []
        params = [("name", n) for n in names] + [("limit", str(_MAX_DEVICES)),
                                                 ("brief", "false")]
        try:
            r = self._http.get("/api/dcim/devices/", params=params)
        except httpx.HTTPError as exc:
            raise IntegrationError(f"netbox: {type(exc).__name__}") from exc
        if r.status_code >= 400:
            raise IntegrationError(f"netbox: HTTP {r.status_code} on /api/dcim/devices/")
        try:
            rows = r.json().get("results") or []
        except (ValueError, AttributeError) as exc:
            raise IntegrationError("netbox: non-JSON reply") from exc
        out = []
        for d in rows:
            if not isinstance(d, dict):
                continue
            ip = d.get("primary_ip") or {}
            out.append({
                "name": str(d.get("name") or ""),
                # NetBox ≥3.6 calls it "role"; older releases "device_role"
                "role": _slug(d.get("role") or d.get("device_role")),
                "status": _slug(d.get("status")),
                "primary_ip": str(ip.get("address") or "") if isinstance(ip, dict) else "",
                "last_updated": str(d.get("last_updated") or ""),
            })
        return sorted(out, key=lambda x: x["name"])

    def inventory(self, names: list[str]) -> dict:
        """{roles: {device: role}, inventory_rev, missing: [device]} for the target devices."""
        devs = self.devices(names)
        found = {d["name"] for d in devs}
        canon = json.dumps(devs, sort_keys=True, separators=(",", ":"))
        return {
            "roles": {d["name"]: d["role"] for d in devs},
            "inventory_rev": "netbox:" + hashlib.sha256(canon.encode()).hexdigest(),
            "missing": sorted({n for n in names if n} - found),
        }
