"""Air-gap enforcement tests for HttpBackend construction.

Regression for the P0 gap: HttpBackend did NO air-gap/loopback validation on its
base_url / model_runner_url even though airgap.assert_airgap_ok already existed and
was wired only into the (unused) core/llm chain.

With AEGIS_AIRGAP=1 set, constructing HttpBackend with an off-perimeter (non-loopback)
URL on EITHER base_url or model_runner_url must fail closed (RuntimeError) before any
socket opens; loopback URLs must be accepted. With air-gap mode off, no check runs.

Run:  python3 -m pytest aegis/tests/http_backend_airgap_test.py -v
"""
from __future__ import annotations

import pytest

from ..core.backends.http_backend import HttpBackend


def test_offperimeter_base_url_rejected_in_airgap(monkeypatch):
    monkeypatch.setenv("AEGIS_AIRGAP", "1")
    with pytest.raises(RuntimeError, match="non-loopback"):
        HttpBackend(base_url="http://evil.example.com:5757")


def test_offperimeter_model_runner_rejected_in_airgap(monkeypatch):
    monkeypatch.setenv("AEGIS_AIRGAP", "1")
    with pytest.raises(RuntimeError, match="non-loopback"):
        HttpBackend(model_runner_url="http://10.0.0.5:12434")


def test_spoofed_loopback_host_rejected_in_airgap(monkeypatch):
    # 127.evil.com would pass a naive startswith("127.") but resolves off-perimeter.
    monkeypatch.setenv("AEGIS_AIRGAP", "1")
    with pytest.raises(RuntimeError, match="non-loopback"):
        HttpBackend(base_url="http://127.evil.com:5757")


def test_loopback_urls_accepted_in_airgap(monkeypatch):
    monkeypatch.setenv("AEGIS_AIRGAP", "1")
    be = HttpBackend(base_url="http://127.0.0.1:5757",
                     model_runner_url="http://localhost:12434")
    assert be.base == "http://127.0.0.1:5757"
    assert be.model_runner == "http://localhost:12434"


def test_no_check_when_airgap_disabled(monkeypatch):
    monkeypatch.delenv("AEGIS_AIRGAP", raising=False)
    # Off-perimeter URL is permitted when air-gap mode is not enabled.
    be = HttpBackend(base_url="http://evil.example.com:5757")
    assert be.base == "http://evil.example.com:5757"
