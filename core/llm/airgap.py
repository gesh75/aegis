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
"""
from __future__ import annotations

import sys
from urllib.parse import urlparse

_CLOUD_PROVIDER = "anthropic-cloud"

# Loopback hosts allowed even in air-gap mode (in-perimeter only).
_LOOPBACK_HOSTS: frozenset[str] = frozenset({"localhost", "127.0.0.1", "::1", ""})


def is_loopback(url: str) -> bool:
    """True only for loopback / .local hosts. An empty host (relative URL) counts as
    loopback because the existing http_backend posts to absolute in-perimeter URLs only;
    a bare host means same-host."""
    host = (urlparse(url).hostname or "").lower()
    if host in _LOOPBACK_HOSTS:
        return True
    if host.endswith(".local"):
        return True
    if host.startswith("127."):  # 127.0.0.0/8 is all loopback
        return True
    return False


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
