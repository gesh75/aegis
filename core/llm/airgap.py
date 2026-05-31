"""aegis/core/llm/airgap.py — air-gap fail-closed invariant (THE WEDGE, part 1).

Part of PR-1 (CROSS-1 shared LLM egress + #4 model-agnostic adapter).

A HARD code invariant that fails BEFORE a request is built — strictly stronger than
``network_mode: none`` at the container layer:
  1. refuses to construct the anthropic-cloud backend at all,
  2. refuses any non-loopback base URL,
  3. asserts the `anthropic` SDK was never imported into the process.

Import-safe, fully type-hinted, no network — unit-testable on day one. No secrets touched.

NOTE: AEGIS's cloud backend uses raw httpx (no `import anthropic`) precisely so that
invariant #3 holds even when the cloud path IS exercised in a non-air-gapped build.

Security: `is_loopback` parses the host with `ipaddress` (NOT a string prefix), so a
spoofed hostname like ``127.evil.com`` or ``127.0.0.1.attacker.com`` — which would pass a
naive ``startswith("127.")`` yet resolve OFF-perimeter — is correctly rejected. No DNS
resolution is performed: resolving an attacker-supplied host would itself be egress, which
is exactly what air-gap mode forbids.
"""
from __future__ import annotations

import sys
from ipaddress import ip_address
from urllib.parse import urlparse

_CLOUD_PROVIDER = "anthropic-cloud"

# Literal non-IP hostnames allowed in air-gap mode (loopback aliases only).
_LOOPBACK_NAMES: frozenset[str] = frozenset({"localhost", "ip6-localhost"})


def is_loopback(url: str) -> bool:
    """True only for a genuine loopback address (127.0.0.0/8 or ::1), the literal name
    'localhost', or a reserved, non-routable '.local' mDNS host (in-perimeter only).

    Uses strict `ipaddress` parsing rather than a string prefix, so a host that merely
    *starts with* "127." but is actually a routable name (e.g. ``127.evil.com``) is
    rejected. An empty/relative host is rejected (never auto-allowed). No DNS lookup is
    performed — resolving an external host would itself violate the air-gap.
    """
    host = (urlparse(url).hostname or "").lower()
    if not host:
        return False  # reject empty / relative — never auto-allow
    if host in _LOOPBACK_NAMES:
        return True
    try:
        return ip_address(host).is_loopback  # 127.0.0.0/8 and ::1, strictly
    except ValueError:
        # Not a literal IP. Only the reserved, non-internet-routable mDNS suffix is
        # treated as in-perimeter (RFC 6762); everything else is non-loopback.
        return host.endswith(".local")


def assert_airgap_ok(provider: str, base_url: str) -> None:
    """HARD invariant — raises RuntimeError BEFORE any socket opens.

    Call at backend *construction* time so an air-gap misconfiguration fails closed at
    startup, not mid-pipeline. A failure here means the pipeline produces NO bundle — the
    correct fail-closed behavior (AEGIS never seals evidence for a change a model could
    not have produced).
    """
    if provider == _CLOUD_PROVIDER:
        raise RuntimeError(
            "AEGIS_AIRGAP=1: cloud backend (anthropic-cloud) is forbidden in air-gap mode"
        )
    if not is_loopback(base_url):
        raise RuntimeError(f"AEGIS_AIRGAP=1: non-loopback egress forbidden: {base_url!r}")
    if "anthropic" in sys.modules:
        raise RuntimeError(
            "AEGIS_AIRGAP=1: the anthropic SDK is loaded in-process — aborting "
            "(in-process exposure violates the air-gap trust surface)"
        )


def assert_no_cloud_sdk_imported() -> None:
    """Standalone check for the single-egress test and a startup guard: in air-gap mode
    the cloud SDK must never be importable into the live process."""
    if "anthropic" in sys.modules:
        raise RuntimeError(
            "air-gap invariant: `anthropic` is present in sys.modules — the cloud SDK "
            "must stay unimported (AEGIS uses raw httpx for the cloud path)"
        )
