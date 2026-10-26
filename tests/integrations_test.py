"""Integrations contract: ServiceNow, NetBox, post-change verification (no network: every
HTTP call goes to an httpx.MockTransport that records requests and answers like the real API).

  N1  perimeter: air-gap default refuses undeclared hosts, plain http off-loopback and
      credentials in URLs; AEGIS_INTEGRATION_HOSTS declares a host; AEGIS_AIRGAP=0 opens
  N2  ServiceNow sync: exactly one CHG by sealed change_ref; PDF + verdict JSON attached to
      change_request; work note + verdict field; blocked → on_hold; no config text leaves
  N3  ServiceNow failures fail closed: no match, HTTP 401 (body never echoed), encoded-
      query injection in change_ref, missing change_ref, missing credentials
  N4  NetBox: name filters + Token auth; role/device_role; inventory_rev deterministic and
      sensitive to last_updated; missing devices reported
  N5  roles only ADD authority (spine role → touches_spine; a leaf role never clears it)
  N6  pipeline: inventory_lookup seals twin.inventory_rev + device_roles (schema-valid) and
      the v2 inventory digest changes with the rev
  N7  post-change: junos set/delete, cisco line/no-line, missing device, comments-only,
      failing intents → verified / drift / unverifiable / failed
  N8  HTTP: integrations refuse without AEGIS_API_KEY; servicenow sync ledgers; postchange
      needs a bundle sealed by this AEGIS and ledgers the result

Usage:  python3 -m aegis.tests.integrations_test
"""
from __future__ import annotations

import json
import os
import sys

import httpx

from ..core.integrations import IntegrationError, assert_integration_url, netbox, servicenow
from ..core.postchange import verify_postchange
from ..core.risk import classify_change

FAILS: list[str] = []
CHECKS = 0
_SCHEMA = os.path.join(os.path.dirname(__file__), "..", "evidence", "schema",
                       "evidence_bundle.schema.json")
SECRET_LINE = "set system login user ops authentication encrypted-password SECRETHASH"


def check(name: str, cond: bool, detail: str = "") -> None:
    global CHECKS
    CHECKS += 1
    if not cond:
        FAILS.append(f"{name}: {detail}")


class _env:
    def __init__(self, **kv):
        self.kv, self.old = kv, {}

    def __enter__(self):
        for k, v in self.kv.items():
            self.old[k] = os.environ.get(k)
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def __exit__(self, *exc):
        for k, v in self.old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def _raises(fn, *a, **kw) -> str | None:
    try:
        fn(*a, **kw)
    except IntegrationError as exc:
        return str(exc)
    return None


# ── fake ServiceNow ─────────────────────────────────────────────────────────────

class FakeSnow:
    def __init__(self, matches=1, status=200):
        self.matches, self.status = matches, status
        self.requests: list[httpx.Request] = []

    def __call__(self, req: httpx.Request) -> httpx.Response:
        self.requests.append(req)
        if self.status != 200:
            return httpx.Response(self.status, text="<html>session=abc123 internal</html>")
        if req.method == "GET" and req.url.path == "/api/now/table/change_request":
            q = req.url.params.get("sysparm_query", "")
            num = q.split("=", 1)[1] if "=" in q else ""
            rows = [{"sys_id": f"sys{i}", "number": num, "state": "-4"}
                    for i in range(self.matches)]
            return httpx.Response(200, json={"result": rows})
        if req.method == "POST" and req.url.path == "/api/now/attachment/file":
            return httpx.Response(201, json={"result": {"sys_id": f"att{len(self.requests)}"}})
        if req.method == "PATCH":
            return httpx.Response(200, json={"result": {"sys_id": "sys0"}})
        return httpx.Response(404, json={"error": "nope"})


def _bundle(decision="blocked", change_ref="CHG0012345"):
    return {"run_id": "a" * 32, "created_utc": "2026-10-25T00:00:00+00:00", "operator": "alice",
            "change": {"change_ref": change_ref, "risk_tier": "high",
                       "authority": {"required": "hitl"},
                       "generated_configs": [{"device": "fw1", "vendor": "junos",
                                              "config": SECRET_LINE,
                                              "grounded_commands": []}]},
            "validation": {"intents": {"failed": 1, "errors": 0, "regressions": 1}},
            "verdict": {"decision": decision, "reason": "intent check: 1 failed"},
            "integrity": {"sha256": "b" * 64}}


def perimeter() -> None:
    with _env(AEGIS_AIRGAP=None, AEGIS_INTEGRATION_HOSTS=None):
        check("N1.undeclared_refused",
              "not declared" in (_raises(assert_integration_url, "x", "https://corp.service-now.com") or ""))
        check("N1.loopback_ok", assert_integration_url("x", "http://127.0.0.1:8080/") ==
              "http://127.0.0.1:8080")
        check("N1.http_offloop_refused",
              "plain http" in (_raises(assert_integration_url, "x", "http://netbox.corp") or ""))
        check("N1.creds_in_url_refused",
              "credentials" in (_raises(assert_integration_url, "x", "https://u:p@netbox.corp") or ""))
        check("N1.bad_scheme", _raises(assert_integration_url, "x", "ftp://netbox.corp") is not None)
    with _env(AEGIS_AIRGAP=None, AEGIS_INTEGRATION_HOSTS="snow-mid.corp.example, netbox.corp"):
        check("N1.declared_ok", assert_integration_url("x", "https://netbox.corp") ==
              "https://netbox.corp")
        check("N1.lookalike_refused",
              _raises(assert_integration_url, "x", "https://netbox.corp.evil.io") is not None)
    with _env(AEGIS_AIRGAP="0", AEGIS_INTEGRATION_HOSTS=None):
        check("N1.airgap_off_opens", assert_integration_url("x", "https://corp.service-now.com")
              == "https://corp.service-now.com")


def snow() -> None:
    with _env(AEGIS_AIRGAP=None, AEGIS_INTEGRATION_HOSTS="snow.corp", AEGIS_SNOW_VERDICT_FIELD=None,
              AEGIS_SNOW_HOLD_ON_BLOCKED=None):
        fake = FakeSnow()
        c = servicenow.ServiceNowClient("https://snow.corp", token="tok-xyz",
                                        transport=httpx.MockTransport(fake))
        rec = c.sync(_bundle(), b"%PDF-1.4 fake")
        methods = [(r.method, r.url.path) for r in fake.requests]
        check("N2.call_sequence", methods == [
            ("GET", "/api/now/table/change_request"),
            ("POST", "/api/now/attachment/file"), ("POST", "/api/now/attachment/file"),
            ("PATCH", "/api/now/table/change_request/sys0")], str(methods))
        get = fake.requests[0]
        check("N2.query_by_sealed_ref",
              get.url.params.get("sysparm_query") == "number=CHG0012345", str(get.url))
        check("N2.bearer", get.headers.get("authorization") == "Bearer tok-xyz")
        att = fake.requests[1:3]
        check("N2.attach_to_change",
              all(a.url.params.get("table_name") == "change_request"
                  and a.url.params.get("table_sys_id") == "sys0" for a in att))
        check("N2.attach_types", [a.headers.get("content-type") for a in att] ==
              ["application/pdf", "application/json"])
        summary = json.loads(att[1].content)
        check("N2.summary_fields", summary["decision"] == "blocked"
              and summary["bundle_sha256"] == "b" * 64 and "generated_configs" not in summary,
              str(summary))
        patch = json.loads(fake.requests[3].content)
        check("N2.patch_fields", patch.get("u_aegis_verdict") == "blocked"
              and patch.get("on_hold") == "true" and "AEGIS" in patch.get("work_notes", ""),
              str(patch))
        leaked = [r for r in fake.requests if b"SECRETHASH" in (r.content or b"")
                  or "SECRETHASH" in str(r.url)]
        check("N2.no_config_egress", not leaked, str(leaked))
        check("N2.record", rec["on_hold"] is True and rec["change_sys_id"] == "sys0"
              and len(rec["attachments"]) == 2, str(rec))

        fake = FakeSnow()
        c = servicenow.ServiceNowClient("https://snow.corp", user="svc", password="pw",
                                        transport=httpx.MockTransport(fake))
        rec = c.sync(_bundle(decision="needs_approval"), b"%PDF")
        patch = json.loads(fake.requests[-1].content)
        check("N2.no_hold_when_not_blocked", "on_hold" not in patch and rec["on_hold"] is False,
              str(patch))
        check("N2.basic_auth", fake.requests[0].headers.get("authorization", "").startswith("Basic "))
        with _env(AEGIS_SNOW_VERDICT_FIELD="", AEGIS_SNOW_HOLD_ON_BLOCKED="0"):
            fake = FakeSnow()
            c = servicenow.ServiceNowClient("https://snow.corp", token="t",
                                            transport=httpx.MockTransport(fake))
            c.sync(_bundle(), b"%PDF")
            patch = json.loads(fake.requests[-1].content)
            check("N2.field_and_hold_configurable", set(patch) == {"work_notes"}, str(patch))

        # N3 — fail closed
        for name, fake, bundle in (("no_match", FakeSnow(matches=0), _bundle()),
                                   ("two_matches", FakeSnow(matches=2), _bundle()),
                                   ("http_401", FakeSnow(status=401), _bundle()),
                                   ("query_injection", FakeSnow(),
                                    _bundle(change_ref="CHG1^ORnumberISNOTEMPTY")),
                                   ("no_change_ref", FakeSnow(), _bundle(change_ref=None))):
            c = servicenow.ServiceNowClient("https://snow.corp", token="t",
                                            transport=httpx.MockTransport(fake))
            err = _raises(c.sync, bundle, b"%PDF")
            check(f"N3.{name}", err is not None and "session=abc123" not in err, str(err))
            if name in ("query_injection", "no_change_ref"):
                check(f"N3.{name}_no_request", not fake.requests, str(fake.requests))
        check("N3.no_credentials", _raises(servicenow.ServiceNowClient, "https://snow.corp",
                                           token="", user="", password="") is not None)


class FakeNetBox:
    def __init__(self, rows):
        self.rows, self.requests = rows, []

    def __call__(self, req):
        self.requests.append(req)
        names = set(req.url.params.get_list("name"))
        return httpx.Response(200, json={"results": [r for r in self.rows if r["name"] in names]})


NB_ROWS = [
    {"name": "spine-a", "role": {"slug": "spine"}, "status": {"value": "active"},
     "primary_ip": {"address": "10.0.0.1/32"}, "last_updated": "2026-10-01T00:00:00Z"},
    {"name": "leaf-1", "device_role": {"slug": "leaf"}, "status": {"value": "active"},
     "primary_ip": None, "last_updated": "2026-10-02T00:00:00Z"},
]


def nbox() -> None:
    with _env(AEGIS_AIRGAP=None, AEGIS_INTEGRATION_HOSTS="netbox.corp"):
        fake = FakeNetBox([dict(r) for r in NB_ROWS])
        c = netbox.NetBoxClient("https://netbox.corp", token="nbtok",
                                transport=httpx.MockTransport(fake))
        inv = c.inventory(["leaf-1", "spine-a", "ghost-9"])
        req = fake.requests[0]
        check("N4.token_header", req.headers.get("authorization") == "Token nbtok")
        check("N4.name_filters", sorted(req.url.params.get_list("name")) ==
              ["ghost-9", "leaf-1", "spine-a"], str(req.url))
        check("N4.roles", inv["roles"] == {"leaf-1": "leaf", "spine-a": "spine"}, str(inv))
        check("N4.missing", inv["missing"] == ["ghost-9"], str(inv))
        check("N4.rev_shape", inv["inventory_rev"].startswith("netbox:")
              and len(inv["inventory_rev"]) == 7 + 64)
        again = c.inventory(["spine-a", "leaf-1", "ghost-9"])["inventory_rev"]
        check("N4.rev_deterministic", again == inv["inventory_rev"])
        fake.rows[1]["last_updated"] = "2026-10-25T00:00:00Z"
        check("N4.rev_tracks_change", c.inventory(["leaf-1", "spine-a"])["inventory_rev"]
              != inv["inventory_rev"])
        check("N4.no_token_refused",
              _raises(netbox.NetBoxClient, "https://netbox.corp", token="") is not None)
        bad = netbox.NetBoxClient("https://netbox.corp", token="t", transport=httpx.MockTransport(
            lambda r: httpx.Response(503, text="down")))
        check("N4.http_error_closed", "503" in (_raises(bad.inventory, ["leaf-1"]) or ""))

    leaf = [{"device": "leaf-1", "vendor": "junos", "config": "set vlans v10 vlan-id 10",
             "grounded_commands": []}]
    check("N5.no_roles_baseline", not classify_change(leaf).touches_spine)
    check("N5.spine_role_adds", classify_change(leaf, roles={"leaf-1": "spine"}).touches_spine)
    check("N5.core_role_underlay", classify_change(leaf, roles={"leaf-1": "core"}).touches_underlay)
    spine = [dict(leaf[0], device="spine-1")]
    check("N5.role_never_clears", classify_change(spine, roles={"spine-1": "leaf"}).touches_spine)


def pipeline() -> None:
    from ..core.backends.simulator import SimulatorBackend
    from ..core.orchestrator.pipeline import run_preflight
    from ..core.promote.tokens import inventory_digest
    from ..evidence.bundler import verify

    cfg = [{"device": "leaf-1", "vendor": "junos", "config": "set vlans v10 vlan-id 10"}]
    seen = {}

    def lookup(devices):
        seen["devices"] = devices
        return {"roles": {"leaf-1": "spine"}, "inventory_rev": "netbox:" + "c" * 64,
                "missing": []}

    sim = SimulatorBackend(converge_fail_rate=0.0, batfish_error_rate=0.0)
    b = run_preflight("", backend=sim, lab="single", source="config_import",
                      imported_configs=cfg, inventory_lookup=lookup)
    plain = run_preflight("", backend=sim, lab="single", source="config_import",
                          imported_configs=cfg)
    check("N6.lookup_called_with_devices", seen.get("devices") == ["leaf-1"], str(seen))
    check("N6.rev_sealed", b["twin"].get("inventory_rev") == "netbox:" + "c" * 64
          and b["twin"].get("device_roles") == {"leaf-1": "spine"} and verify(b), str(b["twin"]))
    check("N6.role_raised_authority", b["change"]["authority"]["change_class"]["touches_spine"]
          and not plain["change"]["authority"]["change_class"]["touches_spine"])
    check("N6.inventory_digest_binds_rev", inventory_digest(b) != inventory_digest(plain))
    check("N6.default_shape_unchanged", "inventory_rev" not in plain["twin"])
    try:
        import jsonschema
        with open(_SCHEMA, encoding="utf-8") as fh:
            schema = json.load(fh)
        jsonschema.validate(b, schema)
        jsonschema.validate(plain, schema)
        check("N6.schema_valid", True)
    except ImportError:
        pass


def postchange() -> None:
    def bundle(configs):
        return {"run_id": "r" * 32, "change": {"change_ref": "CHG1", "generated_configs": configs},
                "integrity": {"sha256": "d" * 64}}

    jun = {"device": "mx1", "vendor": "junos",
           "config": "set vlans v10 vlan-id 10\ndelete vlans old\n# comment"}
    running_ok = "set system host-name mx1\nset vlans v10 vlan-id 10\n"
    r = verify_postchange(bundle([jun]), [{"device": "mx1", "config": running_ok}])
    check("N7.junos_verified", r["status"] == "verified"
          and r["devices"][0]["status"] == "applied", json.dumps(r["devices"]))
    hier = "vlans {\n    v10 {\n        vlan-id 10;\n    }\n}\n"
    r = verify_postchange(bundle([jun]), [{"device": "mx1", "config": hier}])
    check("N7.junos_hierarchical_flattened", r["status"] == "verified", json.dumps(r["devices"]))
    r = verify_postchange(bundle([jun]), [{"device": "mx1", "config": running_ok +
                                           "set vlans old vlan-id 99\n"}])
    check("N7.junos_delete_still_present", r["status"] == "drift"
          and r["devices"][0]["still_present"] == ["delete vlans old"], json.dumps(r["devices"]))
    r = verify_postchange(bundle([jun]), [{"device": "mx1", "config": "set system host-name mx1"}])
    check("N7.junos_missing_line", r["status"] == "drift"
          and r["devices"][0]["missing"] == ["set vlans v10 vlan-id 10"], json.dumps(r["devices"]))
    ios = {"device": "r1", "vendor": "ios",
           "config": "interface Gi0/1\n description uplink\n no shutdown\nno ip http server\n!"}
    run = "interface Gi0/1\n  description   uplink\n no shutdown\n!\nend"
    r = verify_postchange(bundle([ios]), [{"device": "r1", "config": run}])
    check("N7.ios_verified_ws_normalized", r["status"] == "verified", json.dumps(r["devices"]))
    r = verify_postchange(bundle([ios]), [{"device": "r1", "config": run + "\nip http server"}])
    check("N7.ios_no_line_still_present", r["status"] == "drift", json.dumps(r["devices"]))
    r = verify_postchange(bundle([jun, ios]), [{"device": "mx1", "config": running_ok}])
    check("N7.missing_device_is_drift", r["status"] == "drift"
          and r["devices"][1]["status"] == "no_running_config", json.dumps(r["devices"]))
    sim = {"device": "n1", "vendor": "frr", "config": "# add vlan 10"}
    r = verify_postchange(bundle([sim]), [{"device": "n1", "config": "hostname n1"}])
    check("N7.comments_only_unverifiable", r["status"] == "unverifiable", r["status"])
    bad = {"failed": 1, "errors": 0, "regressions": 0, "results": []}
    r = verify_postchange(bundle([jun]), [{"device": "mx1", "config": running_ok}],
                          intents=[{"id": "x"}], intent_runner=lambda i, c: bad)
    check("N7.failing_intent_failed", r["status"] == "failed", r["status"])
    check("N7.record_hash", len(r["record_sha256"]) == 64)


def http() -> None:
    from .. import serve
    from ..serve import app, _LEDGER
    c = app.test_client()
    with _env(AEGIS_API_KEY=None, AEGIS_SNOW_URL="https://snow.corp"):
        r = c.post("/api/integrations/servicenow/sync", json=_bundle())
        check("N8.snow_needs_api_key", r.status_code == 503, str(r.status_code))
    with _env(AEGIS_API_KEY="ik", AEGIS_SNOW_URL=None):
        r = c.post("/api/integrations/servicenow/sync", json=_bundle(),
                   headers={"X-Aegis-Key": "ik"})
        check("N8.snow_unconfigured_503", r.status_code == 503, str(r.status_code))
    st = c.get("/api/status").get_json()
    check("N8.status_integrations", st.get("integrations") == {"servicenow": False,
                                                              "netbox": False}, str(st))

    # a sealed bundle from this server
    sealed = None
    for i in range(20):
        r = c.post("/api/preflight/run", json={
            "source": "config_import", "lab": "single", "change_ref": "CHG0012345",
            "operator": "alice",
            "configs": [{"device": f"mx{i}", "vendor": "junos",
                         "config": "set vlans v10 vlan-id 10"}]})
        b = r.get_json() if r.status_code == 200 else {}
        if isinstance(b.get("seal"), dict):
            sealed = b
            break
    check("N8.got_sealed_bundle", sealed is not None)
    if not sealed:
        return
    dev = sealed["change"]["generated_configs"][0]["device"]
    unsealed = {k: v for k, v in sealed.items() if k != "seal"}
    r = c.post("/api/postchange/verify", json={"bundle": unsealed, "running_configs": [
        {"device": dev, "vendor": "junos", "config": "set vlans v10 vlan-id 10"}]})
    check("N8.postchange_needs_seal", r.status_code == 422, str(r.status_code))
    before = _LEDGER.head()["seq"]
    r = c.post("/api/postchange/verify", json={"bundle": sealed, "running_configs": [
        {"device": dev, "vendor": "junos", "config": "set vlans v10 vlan-id 10"}]})
    rec = r.get_json() or {}
    check("N8.postchange_verified", r.status_code == 200 and rec.get("status") == "verified",
          f"{r.status_code} {json.dumps(rec)[:300]}")
    kinds = [e["kind"] for e in _LEDGER.entries()[before:]]
    check("N8.postchange_ledgered", "postchange_verified" in kinds, str(kinds))
    r = c.post("/api/postchange/verify", json={"bundle": sealed, "running_configs": "nope"})
    check("N8.postchange_bad_body_400", r.status_code == 400, str(r.status_code))

    fake = FakeSnow()
    orig = servicenow.ServiceNowClient

    class Patched(orig):
        def __init__(self, *a, **kw):
            super().__init__(*a, transport=httpx.MockTransport(fake), **kw)

    with _env(AEGIS_API_KEY="ik", AEGIS_SNOW_URL="https://snow.corp",
              AEGIS_INTEGRATION_HOSTS="snow.corp", AEGIS_SNOW_TOKEN="t", AEGIS_AIRGAP=None):
        serve.servicenow.ServiceNowClient = Patched
        try:
            before = _LEDGER.head()["seq"]
            r = c.post("/api/integrations/servicenow/sync", json=sealed,
                       headers={"X-Aegis-Key": "ik"})
            check("N8.snow_sync_200", r.status_code == 200
                  and (r.get_json() or {}).get("change_ref") == "CHG0012345",
                  f"{r.status_code} {r.get_data(as_text=True)[:200]}")
            kinds = [e["kind"] for e in _LEDGER.entries()[before:]]
            check("N8.snow_ledgered", "itsm_synced" in kinds, str(kinds))
            forged = dict(sealed, verdict={"decision": "ship_ready", "reason": "forged"})
            r = c.post("/api/integrations/servicenow/sync", json=forged,
                       headers={"X-Aegis-Key": "ik"})
            check("N8.snow_tampered_422", r.status_code == 422, str(r.status_code))
            fake.status = 500
            r = c.post("/api/integrations/servicenow/sync", json=sealed,
                       headers={"X-Aegis-Key": "ik"})
            check("N8.snow_failure_502_ledgered", r.status_code == 502
                  and "itsm_sync_failed" in [e["kind"] for e in _LEDGER.entries()[-1:]],
                  str(r.status_code))
        finally:
            serve.servicenow.ServiceNowClient = orig


def main() -> int:
    perimeter()
    snow()
    nbox()
    pipeline()
    postchange()
    http()
    if FAILS:
        print("\n=== INTEGRATIONS TEST: FAIL ===")
        for f in FAILS:
            print("  -", f)
        return 1
    print(f"=== INTEGRATIONS TEST: PASS ({CHECKS} checks) ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
