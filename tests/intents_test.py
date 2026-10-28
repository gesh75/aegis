"""Intent engine contract — pure, no Batfish (a fixture oracle answers).

  I1  spec: valid docs normalize; unknown kind/field, bad IP/port/id, dup id → IntentSpecError
  I2  reachability deny: any SUCCESS flow → fail (examples cited); none → pass
  I3  reachability allow: any FAILURE flow → fail; no SUCCESS at all → error (vacuous)
  I4  bgp / undefined refs / dead ACL lines: fail with examples, pass when clean
  I5  fidelity gate: a FAILED-to-parse candidate turns every intent into error
  I6  differential: pass→fail is flagged regression; before is recorded
  I7  fail closed: no engine → every intent error; oracle exceptions → error rows
  I8  snapshot materialization: junos set-merge, replace, new; reference untouched
  I9  pipeline: a failing/unevaluable intent blocks the verdict, bundle is schema-valid
      v1.4 and integrity-verifies; no intents → validation.intents is null
  I10 runner without AEGIS_BATFISH_HOST fails closed (never "skipped")
  I11 HTTP: bad intents → 400; valid intents without an engine → blocked bundle; status +
      metrics report the engine; PDF/CAB render the intent rows
  I12 firewall_policy: zones resolve to @enter() start locations; an unknown zone is an error;
      deny/allow semantics as reachability; spec rejects bad zone/node names
  I13 nat: translated/untranslated against post-NAT headers; undelivered flow fails; no
      trace is an error; ECMP traces must all agree; spec enforces field combinations
  I14 duplicate devices in one change are rejected (one device = one snapshot file); the
      rejection names the device and every intent becomes an error row, never a pass
  I15 a non-Junos config may replace a reference file only when it is shown to be complete
      (no dropped block, no net line loss); a truncated snippet is rejected fail closed

Usage:  python3 -m aegis.tests.intents_test
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import types

from ..core import intents as _intents_pkg
from ..core.intents import IntentSpecError, OracleError, check_intents, parse_intents
from ..core.intents.runner import run_intents
from ..core.intents.snapshot import SnapshotError, materialize
from ..core.orchestrator.pipeline import run_preflight
from ..core.backends.simulator import SimulatorBackend
from ..evidence.bundler import verify

FAILS: list[str] = []
CHECKS = 0
_SCHEMA = os.path.join(os.path.dirname(__file__), "..", "evidence", "schema",
                       "evidence_bundle.schema.json")


def check(name: str, cond: bool, detail: str = "") -> None:
    global CHECKS
    CHECKS += 1
    if not cond:
        FAILS.append(f"{name}: {detail}")


class Fixture:
    name = "fixture"

    def __init__(self, *, success=(), failure=(), bgp=(), refs=(), dead=(),
                 parse=(("configs/r1.cfg", "PASSED"),), boom=False, zones=None, traces=()):
        self.success, self.failure = list(success), list(failure)
        self.zones = zones or {}
        self.traces = list(traces)
        self.starts: list[str | None] = []
        self.bgp, self.refs, self.dead = list(bgp), list(refs), list(dead)
        self.parse = [{"file": f, "status": s} for f, s in parse]
        self.boom = boom

    def parse_status(self):
        return self.parse

    def reachability(self, *, start, src_ips, dst_ips, protocols, dst_ports, action):
        if self.boom:
            raise OracleError("engine down")
        self.starts.append(start)
        self.actions = getattr(self, "actions", []) + [action]
        return self.failure if action == "FAILURE" else self.success

    def zone_interfaces(self, node, zone):
        return list(self.zones.get((node, zone), []))

    def traceroute(self, *, start, src_ip, dst_ip, protocol, dst_port):
        return self.traces

    def bgp_sessions(self, nodes):
        return self.bgp

    def undefined_references(self):
        if self.boom:
            raise RuntimeError("kaboom")
        return self.refs

    def unreachable_filter_lines(self, nodes):
        return self.dead


DENY = {"id": "guest-x-cde", "kind": "reachability", "start": "@enter(r1[Gi0/1])",
        "src_ips": "10.50.0.0/16", "dst_ips": "10.10.0.0/24", "protocols": ["tcp"],
        "dst_ports": "22", "expect": "deny", "control": "PCI DSS v4.0 1.3.1"}
ALLOW = {"id": "web-ok", "kind": "reachability", "src_ips": "10.50.0.0/16",
         "dst_ips": "10.20.0.10", "protocols": ["tcp"], "dst_ports": "443", "expect": "allow"}


def spec() -> None:
    doc = {"intents": [DENY, ALLOW,
                       {"id": "bgp", "kind": "bgp_sessions", "expect": "all_established"},
                       {"id": "refs", "kind": "undefined_references", "expect": "none"},
                       {"id": "acl", "kind": "filter_line_reachability", "expect": "none"}]}
    got = parse_intents(doc)
    check("I1.parse_ok", [i["id"] for i in got] == ["guest-x-cde", "web-ok", "bgp", "refs", "acl"])
    check("I1.protocols_normalized", got[0]["protocols"] == ["tcp"])
    bad_cases = {
        "unknown_kind": [{"id": "a", "kind": "pingable", "expect": "none"}],
        "unknown_field": [dict(DENY, dst_port="22")],
        "bad_ip": [dict(DENY, dst_ips="10.10.0.300/24")],
        "bad_port": [dict(DENY, dst_ports="70000")],
        "bad_expect": [dict(DENY, expect="maybe")],
        "dup_id": [DENY, DENY],
        "bad_id": [dict(DENY, id="has space")],
        "no_source": [{k: v for k, v in DENY.items() if k not in ("start", "src_ips")}],
        "bad_protocol": [dict(DENY, protocols=["gre"])],
        "not_list": {"intents": "nope"},
    }
    for name, doc in bad_cases.items():
        try:
            parse_intents(doc)
            check(f"I1.reject_{name}", False, "accepted")
        except IntentSpecError:
            check(f"I1.reject_{name}", True)


def semantics() -> None:
    ints = parse_intents([DENY])
    r = check_intents(ints, candidate=Fixture(success=["flow 10.50.1.1->10.10.0.5:22"]),
                      engine="fixture")
    check("I2.deny_leak_fails", r["results"][0]["status"] == "fail" and r["failed"] == 1
          and r["results"][0]["examples"], json.dumps(r["results"][0]))
    r = check_intents(ints, candidate=Fixture(), engine="fixture")
    check("I2.deny_clean_passes", r["results"][0]["status"] == "pass", r["results"][0]["evidence"])
    check("I2.control_carried", r["results"][0].get("control") == "PCI DSS v4.0 1.3.1")

    ints = parse_intents([ALLOW])
    r = check_intents(ints, candidate=Fixture(success=["ok"], failure=["dropped"]), engine="f")
    check("I3.allow_partial_fails", r["results"][0]["status"] == "fail")
    r = check_intents(ints, candidate=Fixture(success=["ok"]), engine="f")
    check("I3.allow_passes", r["results"][0]["status"] == "pass")
    r = check_intents(ints, candidate=Fixture(), engine="f")
    check("I3.vacuous_allow_is_error", r["results"][0]["status"] == "error" and r["errors"] == 1,
          r["results"][0]["evidence"])

    bgp = parse_intents([{"id": "bgp", "kind": "bgp_sessions", "expect": "all_established"}])
    r = check_intents(bgp, candidate=Fixture(bgp=[{"node": "r1", "remote": "r2",
                                                   "status": "ESTABLISHED"},
                                                  {"node": "r1", "remote": "r3",
                                                   "status": "NOT_ESTABLISHED"}]), engine="f")
    check("I4.bgp_down_fails", r["results"][0]["status"] == "fail"
          and "r3" in r["results"][0]["examples"][0])
    r = check_intents(bgp, candidate=Fixture(bgp=[{"node": "r1", "remote": "r2",
                                                   "status": "ESTABLISHED"}]), engine="f")
    check("I4.bgp_ok", r["results"][0]["status"] == "pass")
    r = check_intents(bgp, candidate=Fixture(), engine="f")
    check("I4.bgp_none_is_error", r["results"][0]["status"] == "error")
    refs = parse_intents([{"id": "refs", "kind": "undefined_references", "expect": "none"}])
    check("I4.refs_fail", check_intents(refs, candidate=Fixture(refs=["r1: acl MISSING"]),
                                        engine="f")["results"][0]["status"] == "fail")
    acl = parse_intents([{"id": "acl", "kind": "filter_line_reachability", "expect": "none"}])
    check("I4.dead_acl_fail", check_intents(acl, candidate=Fixture(dead=["GUEST_IN: deny tcp"]),
                                            engine="f")["results"][0]["status"] == "fail")

    both = parse_intents([DENY, ALLOW])
    r = check_intents(both, candidate=Fixture(parse=(("configs/r1.cfg", "FAILED"),),
                                              success=["x"]), engine="f")
    check("I5.fidelity_gate", all(x["status"] == "error" for x in r["results"])
          and r["fidelity"]["failed"] == 1, json.dumps(r["fidelity"]))
    r = check_intents(both, candidate=Fixture(parse=()), engine="f")
    check("I5.empty_snapshot_gate", all(x["status"] == "error" for x in r["results"]))

    r = check_intents(parse_intents([DENY]), reference=Fixture(),
                      candidate=Fixture(success=["leak"]), engine="f")
    row = r["results"][0]
    check("I6.regression", row["before"] == "pass" and row["status"] == "fail"
          and row.get("regression") is True and r["regressions"] == 1, json.dumps(row))
    r = check_intents(parse_intents([DENY]), reference=Fixture(success=["leak"]),
                      candidate=Fixture(success=["leak"]), engine="f")
    check("I6.preexisting_not_regression", r["regressions"] == 0
          and r["results"][0]["before"] == "fail")

    r = check_intents(both, candidate=None, unavailable_reason="no host")
    check("I7.unavailable_all_error", r["errors"] == 2 and r["engine"] == "unavailable"
          and all(x["status"] == "error" for x in r["results"]))
    r = check_intents(parse_intents([DENY, {"id": "refs", "kind": "undefined_references",
                                            "expect": "none"}]),
                      candidate=Fixture(boom=True), engine="f")
    check("I7.oracle_exceptions_error", [x["status"] for x in r["results"]] == ["error", "error"],
          json.dumps(r["results"]))


def snapshots() -> None:
    base = {"mx1": 'system { host-name mx1; }\nprotocols { bgp { group G { neighbor 1.1.1.1; } } }',
            "r1": "hostname r1\n!\ninterface Gi0/0\n ip address 10.0.0.1 255.255.255.0\n"}
    cfgs = [{"device": "mx1", "vendor": "junos",
             "config": 'set protocols bgp group G authentication-key "$9$x"'},
            {"device": "r1", "vendor": "ios",
             "config": "hostname r1\n! full replacement\n!\ninterface Gi0/0\n"
                       " ip address 10.0.0.9 255.255.255.0\n"},
            {"device": "new-leaf", "vendor": "junos", "config": "set system host-name new-leaf"}]
    ref, cand, log = materialize(cfgs, base)
    modes = {m["device"]: m["mode"] for m in log}
    check("I8.modes", modes == {"mx1": "junos-set-merge", "r1": "replace", "new-leaf": "new"},
          str(modes))
    mx = cand["configs/mx1.cfg"]
    check("I8.junos_merge", mx.startswith("#RANCID-CONTENT-TYPE: juniper")
          and "set protocols bgp group G neighbor 1.1.1.1" in mx
          and mx.rstrip().endswith('authentication-key "$9$x"'), mx)
    check("I8.replace", cand["configs/r1.cfg"].startswith("hostname r1\n! full"))
    check("I8.reference_untouched", ref["configs/r1.cfg"] == base["r1"]
          and "authentication-key" not in ref["configs/mx1.cfg"])
    check("I8.new_device", "configs/new-leaf.cfg" in cand and "configs/new-leaf.cfg" not in ref)
    ref2, cand2, _ = materialize([{"device": "../../etc/passwd", "vendor": "ios", "config": "x"}],
                                 {})
    check("I8.no_base_no_reference", ref2 is None)
    check("I8.path_sanitized", all(".." not in k and k.startswith("configs/") for k in cand2),
          str(list(cand2)))


def pipeline() -> None:
    try:
        import jsonschema
        schema = json.load(open(_SCHEMA))
    except ImportError:
        jsonschema = None
    ints = parse_intents([DENY])

    def leak_runner(intents, configs):
        return check_intents(intents, reference=Fixture(), candidate=Fixture(success=["leak"]),
                             engine="fixture")

    def clean_runner(intents, configs):
        return check_intents(intents, reference=Fixture(), candidate=Fixture(), engine="fixture")

    sim = SimulatorBackend(converge_fail_rate=0.0, batfish_error_rate=0.0)
    b = run_preflight("add vlan 10 to leaf-1", backend=sim, lab="single", operator="ci",
                      intents=ints, intent_runner=leak_runner)
    check("I9.leak_blocks", b["verdict"]["decision"] == "blocked"
          and "intent check" in b["verdict"]["reason"]
          and "regression" in b["verdict"]["reason"], b["verdict"]["reason"])
    check("I9.leak_sealed_in_bundle", b["validation"]["intents"]["regressions"] == 1 and verify(b))
    check("I9.severity_critical", b["validation"]["blast_radius"]["severity"] == "critical")
    if jsonschema:
        try:
            jsonschema.validate(b, schema)
            check("I9.schema_valid_with_intents", True)
        except jsonschema.ValidationError as e:
            check("I9.schema_valid_with_intents", False, e.message)
    b2 = run_preflight("add vlan 10 to leaf-1", backend=sim, lab="single", operator="ci",
                       intents=ints, intent_runner=clean_runner)
    check("I9.clean_not_blocked_by_intents", "intent" not in b2["verdict"]["reason"],
          b2["verdict"]["reason"])
    b3 = run_preflight("add vlan 10 to leaf-1", backend=sim, lab="single", operator="ci")
    check("I9.no_intents_null", b3["validation"]["intents"] is None
          and b3["bundle_version"] == "1.4")
    if jsonschema:
        try:
            jsonschema.validate(b3, schema)
            check("I9.schema_valid_without_intents", True)
        except jsonschema.ValidationError as e:
            check("I9.schema_valid_without_intents", False, e.message)

    saved = os.environ.pop("AEGIS_BATFISH_HOST", None)
    try:
        r = run_intents(ints, [])
        check("I10.no_host_fails_closed", r["errors"] == 1 and r["engine"] == "unavailable"
              and "AEGIS_BATFISH_HOST" in r["results"][0]["evidence"], json.dumps(r))
        b4 = run_preflight("add vlan 10 to leaf-1", backend=sim, lab="single", operator="ci",
                           intents=ints)
        check("I10.pipeline_blocks_without_engine", b4["verdict"]["decision"] == "blocked",
              b4["verdict"]["reason"])
    finally:
        if saved is not None:
            os.environ["AEGIS_BATFISH_HOST"] = saved


def http() -> None:
    from ..serve import app
    saved = os.environ.pop("AEGIS_BATFISH_HOST", None)
    try:
        c = app.test_client()
        r = c.post("/api/preflight/run", json={"intent": "add vlan 10", "lab": "single",
                                               "intents": [{"id": "x", "kind": "nope",
                                                            "expect": "none"}]})
        check("I11.bad_intents_400", r.status_code == 400 and "intents:" in r.get_data(as_text=True),
              f"{r.status_code} {r.get_data(as_text=True)[:120]}")
        r = c.post("/api/preflight/run", json={"intent": "add vlan 10", "lab": "single",
                                               "operator": "ci", "intents": [DENY, ALLOW]})
        b = r.get_json() or {}
        ir = (b.get("validation") or {}).get("intents") or {}
        check("I11.no_engine_blocks", r.status_code == 200
              and b.get("verdict", {}).get("decision") == "blocked" and ir.get("errors") == 2,
              f"{r.status_code} {str(b.get('verdict'))[:160]}")
        cab = c.post("/api/preflight/evidence/cab", json=b).get_json() or {}
        check("I11.cab_intents", (cab.get("intents") or {}).get("errors") == 2, str(cab.get("intents")))
        pdf = c.post("/api/preflight/evidence/pdf", json=b)
        check("I11.pdf_renders", pdf.status_code == 200 and pdf.data[:5] == b"%PDF-",
              str(pdf.status_code))
        st = c.get("/api/status").get_json() or {}
        check("I11.status_engine", st.get("intents_engine") == "unconfigured"
              and st.get("baseline_intents") == 0, str(st))
        m = c.get("/metrics").get_data(as_text=True)
        check("I11.metrics", 'aegis_intent_results_total{status="error"}' in m, m[-400:])
    finally:
        if saved is not None:
            os.environ["AEGIS_BATFISH_HOST"] = saved


FW = {"id": "untrust-x-trust", "kind": "firewall_policy", "node": "fw1",
      "from_zone": "untrust", "to_zone": "trust", "dst_ips": "10.1.0.0/24",
      "protocols": ["tcp"], "dst_ports": "1-65535", "expect": "deny"}
ZONES = {("fw1", "untrust"): ["ge-0/0/1.0"], ("fw1", "trust"): ["ge-0/0/0.0", "ge-0/0/3.0"]}
NAT = {"id": "web-dnat", "kind": "nat", "start": "@enter(fw1[ge-0/0/1.0])",
       "src_ip": "198.51.100.7", "dst_ip": "203.0.113.10", "protocol": "tcp", "dst_port": 443,
       "expect": "translated", "translated_dst_ip": "10.2.0.10"}


def _trace(disp="DELIVERED_TO_SUBNET", dst="10.2.0.10", src="198.51.100.7", changes=None):
    return {"disposition": disp, "final": {"srcIp": src, "dstIp": dst, "srcPort": "49152",
                                           "dstPort": "443"},
            "changes": changes if changes is not None else [f"fw1: dstIp 203.0.113.10→{dst}"],
            "text": "fw1 ..."}


def firewall() -> None:
    ints = parse_intents([FW])
    fx = Fixture(zones=ZONES, success=["10.9.9.9->10.1.0.5:22"])
    r = check_intents(ints, candidate=fx, engine="fixture")["results"][0]
    check("I12.deny_leak_fails", r["status"] == "fail" and "untrust→trust" in r["evidence"],
          json.dumps(r))
    check("I12.start_from_zone", fx.starts and fx.starts[0] == "@enter(fw1[ge-0/0/1.0])",
          str(fx.starts))
    check("I12.transit_dispositions_only",
          fx.actions[0] == "DELIVERED_TO_SUBNET,EXITS_NETWORK", str(fx.actions))
    r = check_intents(ints, candidate=Fixture(zones=ZONES), engine="fixture")["results"][0]
    check("I12.deny_clean_passes", r["status"] == "pass", json.dumps(r))
    r = check_intents(parse_intents([dict(FW, from_zone="untrsut")]),
                      candidate=Fixture(zones=ZONES), engine="fixture")["results"][0]
    check("I12.unknown_zone_error", r["status"] == "error" and "untrsut" in r["evidence"],
          json.dumps(r))
    allow = dict(FW, id="trust-to-untrust", from_zone="trust", to_zone="untrust",
                 dst_ips="203.0.113.0/24", expect="allow")
    fx = Fixture(zones=ZONES, success=["ok"])
    r = check_intents(parse_intents([allow]), candidate=fx, engine="fixture")["results"][0]
    check("I12.allow_passes", r["status"] == "pass", json.dumps(r))
    check("I12.multi_iface_start", fx.starts[0] == "@enter(fw1[ge-0/0/0.0]),@enter(fw1[ge-0/0/3.0])",
          str(fx.starts))
    r = check_intents(parse_intents([allow]), candidate=Fixture(zones=ZONES), engine="fixture")
    check("I12.allow_vacuous_error", r["results"][0]["status"] == "error",
          json.dumps(r["results"][0]))
    for name, bad in {"zone_space": dict(FW, from_zone="un trust"),
                      "missing_zone": {k: v for k, v in FW.items() if k != "to_zone"},
                      "bad_expect": dict(FW, expect="translated"),
                      "start_not_allowed": dict(FW, start="@enter(fw1[x])")}.items():
        try:
            parse_intents([bad])
            check(f"I12.reject_{name}", False, "accepted")
        except IntentSpecError:
            check(f"I12.reject_{name}", True)


def nat() -> None:
    ints = parse_intents([NAT])
    r = check_intents(ints, candidate=Fixture(traces=[_trace()]), engine="fixture")["results"][0]
    check("I13.translated_pass", r["status"] == "pass" and "10.2.0.10" in r["evidence"],
          json.dumps(r))
    r = check_intents(ints, candidate=Fixture(traces=[_trace(dst="10.2.0.99")]),
                      engine="fixture")["results"][0]
    check("I13.wrong_target_fails", r["status"] == "fail" and "10.2.0.99" in r["examples"][0],
          json.dumps(r))
    r = check_intents(ints, candidate=Fixture(traces=[_trace(disp="DENIED_IN")]),
                      engine="fixture")["results"][0]
    check("I13.undelivered_fails", r["status"] == "fail" and "DENIED_IN" in r["examples"][0],
          json.dumps(r))
    r = check_intents(ints, candidate=Fixture(traces=[_trace(), _trace(dst="203.0.113.10",
                                                                        changes=[])]),
                      engine="fixture")["results"][0]
    check("I13.ecmp_all_must_agree", r["status"] == "fail", json.dumps(r))
    r = check_intents(ints, candidate=Fixture(traces=[]), engine="fixture")["results"][0]
    check("I13.no_trace_error", r["status"] == "error", json.dumps(r))
    keep = {"id": "east-west-real-src", "kind": "nat", "start": "@enter(fw1[ge-0/0/0.0])",
            "src_ip": "10.1.0.5", "dst_ip": "10.2.0.10", "protocol": "tcp", "dst_port": 443,
            "expect": "untranslated"}
    r = check_intents(parse_intents([keep]), candidate=Fixture(traces=[_trace(
        src="10.1.0.5", changes=[])]), engine="fixture")["results"][0]
    check("I13.untranslated_pass", r["status"] == "pass", json.dumps(r))
    r = check_intents(parse_intents([keep]), candidate=Fixture(traces=[_trace(
        src="203.0.113.1", changes=["fw1: srcIp 10.1.0.5→203.0.113.1"])]),
        engine="fixture")["results"][0]
    check("I13.untranslated_fails_on_snat", r["status"] == "fail", json.dumps(r))
    ref = Fixture(traces=[_trace()])
    cand = Fixture(traces=[_trace(dst="10.2.0.99")])
    rec = check_intents(ints, candidate=cand, reference=ref, engine="fixture")
    check("I13.regression", rec["regressions"] == 1 and rec["results"][0]["regression"] is True,
          json.dumps(rec["results"][0]))
    for name, bad in {"no_translation_target": {k: v for k, v in NAT.items()
                                                if k != "translated_dst_ip"},
                      "untranslated_with_target": dict(NAT, expect="untranslated"),
                      "prefix_not_ip": dict(NAT, dst_ip="203.0.113.0/24"),
                      "tcp_without_port": {k: v for k, v in NAT.items() if k != "dst_port"},
                      "icmp_with_port": dict(NAT, protocol="icmp"),
                      "port_range": dict(NAT, dst_port=70000),
                      "bool_port": dict(NAT, dst_port=True)}.items():
        try:
            parse_intents([bad])
            check(f"I13.reject_{name}", False, "accepted")
        except IntentSpecError:
            check(f"I13.reject_{name}", True)
    # schema: new kinds are valid in a sealed bundle
    try:
        import jsonschema
    except ImportError:
        return
    b = run_preflight("add vlan 10 to leaf-1", backend=SimulatorBackend(), lab="single",
                      intents=parse_intents([FW, NAT]),
                      intent_runner=lambda i, c: check_intents(
                          i, candidate=Fixture(zones=ZONES, traces=[_trace()]),
                          engine="fixture"))
    with open(_SCHEMA, encoding="utf-8") as fh:
        jsonschema.validate(b, json.load(fh))
    check("I13.schema_valid_new_kinds", verify(b)
          and {r["kind"] for r in b["validation"]["intents"]["results"]} == {"firewall_policy",
                                                                            "nat"})


FIX = os.path.join(os.path.dirname(__file__), "fixtures", "batfish")


def _read(*parts: str) -> str:
    with open(os.path.join(FIX, *parts), encoding="utf-8") as fh:
        return fh.read()


class _FakeBatfish:
    """Stands in for batfish_oracle (pybatfish is optional). It records the snapshots it is
    handed and 'verifies' them as clean, which is what a real Batfish says about a truncated
    config: the flows end in NO_ROUTE, so every deny intent passes."""
    seen: list = []

    def __init__(self, host, network, reference, candidate):
        _FakeBatfish.seen.append((reference, candidate))

    def __enter__(self):
        return Fixture(), Fixture()

    def __exit__(self, *exc):
        return False


def _with_engine(base: dict[str, str], fn):
    """Run ``fn()`` with AEGIS_BATFISH_HOST set, a reference snapshot dir holding ``base``
    ({name: text}) and the fake Batfish module; everything is restored afterwards."""
    keys = ("AEGIS_BATFISH_HOST", "AEGIS_BATFISH_SNAPSHOT_DIR")
    saved = {k: os.environ.get(k) for k in keys}
    modname = _intents_pkg.__name__ + ".batfish_oracle"
    prev_mod = sys.modules.get(modname)
    fake = types.ModuleType(modname)
    fake.BatfishSnapshots = _FakeBatfish
    _FakeBatfish.seen = []
    try:
        with tempfile.TemporaryDirectory() as tmp:
            os.makedirs(os.path.join(tmp, "configs"))
            for name, text in base.items():
                with open(os.path.join(tmp, "configs", f"{name}.cfg"), "w",
                          encoding="utf-8") as fh:
                    fh.write(text)
            os.environ["AEGIS_BATFISH_HOST"] = "127.0.0.1"
            os.environ["AEGIS_BATFISH_SNAPSHOT_DIR"] = tmp
            sys.modules[modname] = fake
            return fn()
    finally:
        if prev_mod is None:
            sys.modules.pop(modname, None)
        else:
            sys.modules[modname] = prev_mod
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def _rejects(configs: list[dict], base: dict[str, str], replace: bool = False) -> str | None:
    """The SnapshotError text, or None when materialize accepted the change."""
    try:
        materialize(configs, base, replace=replace)
    except SnapshotError as exc:
        return str(exc)
    return None


def duplicates() -> None:
    mx = "#RANCID-CONTENT-TYPE: juniper\nset system host-name r1\n"
    base = {"r1": mx, "r2": "hostname r2\n"}
    permit = {"device": "r1", "vendor": "junos", "config":
              "set security policies from-zone untrust to-zone trust policy x then permit"}
    harmless = {"device": "r1", "vendor": "junos", "config": "set system host-name r1"}
    msg = _rejects([permit, harmless], base)
    check("I14.dup_rejected", msg is not None and "r1" in msg, str(msg))
    for variant in ("r1 ", " r1", "r1_", "r1.", "R1", "r1\t"):
        msg = _rejects([permit, dict(harmless, device=variant)], base)
        check(f"I14.dup_variant_{variant!r}", msg is not None, "collapsed onto the same file")
    check("I14.distinct_devices_ok",
          _rejects([permit, dict(harmless, device="r2")], base) is None)
    check("I14.dup_rejected_replace_mode",
          _rejects([permit, harmless], base, replace=True) is not None)
    check("I14.dup_rejected_new_devices",
          _rejects([dict(permit, device="leaf9"), dict(harmless, device="LEAF9")], {}) is not None)
    check("I14.error_names_only_a_short_device",
          len(_rejects([dict(permit, device="d" * 500), dict(harmless, device="d" * 500)],
                       {}) or "") < 400)
    # the reference file is replaced whatever the device name's case
    _, cand, _ = materialize([{"device": "R1", "vendor": "ios", "config": "hostname r1\n"}],
                             {"r1": "hostname r1\n"})
    check("I14.case_replaces_reference_file", sorted(cand) == ["configs/r1.cfg"], str(sorted(cand)))

    # through the runner: nothing reaches the engine, every intent is an error row naming r1
    ints = parse_intents([DENY, ALLOW])

    def runner_case():
        return run_intents(ints, [permit, harmless])

    rec = _with_engine(base, runner_case)
    check("I14.runner_blocks", rec["errors"] == 2 and rec["engine"] == "unavailable"
          and rec["failed"] == 0 and all(r["status"] == "error" for r in rec["results"])
          and "r1" in rec["results"][0]["evidence"], json.dumps(rec)[:400])
    check("I14.engine_never_called", _FakeBatfish.seen == [], str(len(_FakeBatfish.seen)))
    ok = _with_engine(base, lambda: run_intents(parse_intents([DENY]), [permit]))
    check("I14.single_entry_still_runs", ok["engine"] == "batfish" and ok["errors"] == 0
          and ok["results"][0]["status"] == "pass", json.dumps(ok)[:400])
    check("I14.single_entry_snapshot_has_it",
          "permit" in _FakeBatfish.seen[-1][1]["configs/r1.cfg"], str(_FakeBatfish.seen[-1]))

    # the whole pipeline: duplicate config_import entries can never be ship_ready
    sim = SimulatorBackend(converge_fail_rate=0.0, batfish_error_rate=0.0)

    def pipe_case():
        return run_preflight("", backend=sim, lab="single", source="config_import",
                             operator="ci", imported_configs=[permit, harmless],
                             intents=parse_intents([DENY]))

    b = _with_engine(base, pipe_case)
    check("I14.pipeline_blocks", b["verdict"]["decision"] == "blocked"
          and b["validation"]["intents"]["errors"] == 1 and verify(b),
          f"{b['verdict']} {b['validation']['intents']['errors']}")


_R1_BASE = _read("reference", "configs", "r1.cfg")
_FW2_BASE = _read("firewall", "reference", "configs", "fw2.cfg")
_MX_BASE = ("system {\n    host-name mx1;\n}\nprotocols {\n    bgp {\n        group G {\n"
            "            neighbor 192.0.2.1;\n        }\n    }\n}\n")


def _ios(config: str, device: str = "r1") -> list[dict]:
    return [{"device": device, "vendor": "ios", "config": config}]


def completeness() -> None:
    base = {"r1": _R1_BASE}
    # complete configs are replaced: the shipped fixtures, an edited line, an added block
    _, cand, log = materialize(_ios(_read("candidate_r1.cfg")), base)
    check("I15.fixture_candidate_accepted", log[0]["mode"] == "replace"
          and cand["configs/r1.cfg"].startswith("!\nhostname r1"), str(log))
    check("I15.same_config_accepted", _rejects(_ios(_R1_BASE), base) is None)
    edited = _R1_BASE.replace("10.20.0.1 255.255.255.0", "10.20.0.9 255.255.255.0")
    check("I15.edited_line_accepted", _rejects(_ios(edited), base) is None)
    check("I15.added_block_accepted",
          _rejects(_ios(_R1_BASE.replace("!\nend\n", "!\ninterface Loopback9\n ip address "
                                         "192.0.2.9 255.255.255.255\n!\nend\n")), base) is None)
    _, cand, log = materialize([{"device": "fw2", "vendor": "panos",
                                 "config": _read("firewall", "candidate_fw2.cfg")}],
                               {"fw2": _FW2_BASE})
    check("I15.panos_full_accepted", log[0]["mode"] == "replace", str(log))

    # the finding's PoC: CDE interface left out, guest ACL opened -> rejected, named
    poc = ("hostname r1\n!\ninterface GigabitEthernet0/1\n description GUEST\n"
           " ip address 10.50.0.1 255.255.0.0\n ip access-group OPEN in\n!\n"
           "interface GigabitEthernet0/2\n description WEB\n"
           " ip address 10.20.0.1 255.255.255.0\n!\nip access-list extended OPEN\n"
           " permit ip any any\n!\nend\n")
    msg = _rejects(_ios(poc), base)
    check("I15.poc_rejected", msg is not None and "r1" in msg and "GigabitEthernet0/0" in msg,
          str(msg))
    cases = {
        "one_line": "hostname r1\n",
        "changed_acl_only": "ip access-list extended GUEST_IN\n permit ip any any\n",
        "one_interface_only": "interface GigabitEthernet0/1\n ip address 10.50.0.1 255.255.0.0\n",
        "empty": "",
        "comments_only": "! nothing\n!\nend\n",
        "block_header_without_body": _R1_BASE.replace(
            " description CDE\n ip address 10.10.0.1 255.255.255.0\n", ""),
        "pure_line_deletion": _R1_BASE.replace(" deny   ip 10.50.0.0 0.0.255.255 "
                                               "10.10.0.0 0.0.0.255\n", ""),
    }
    for name, text in cases.items():
        msg = _rejects(_ios(text), base)
        check(f"I15.truncated_{name}", msg is not None and "r1" in msg, str(msg))
    msg = _rejects([{"device": "fw2", "vendor": "panos", "config": "\n".join(
        _FW2_BASE.splitlines()[:10]) + "\n"}], {"fw2": _FW2_BASE})
    check("I15.panos_truncated_rejected", msg is not None and "fw2" in msg, str(msg))
    # Junos curly-brace full configs are compared as set lines
    mx = {"mx1": _MX_BASE}
    full = _MX_BASE.replace("neighbor 192.0.2.1;", "neighbor 192.0.2.1;\n            "
                            "neighbor 192.0.2.5;")
    check("I15.junos_hier_full_accepted",
          _rejects([{"device": "mx1", "vendor": "junos", "config": full}], mx) is None)
    check("I15.junos_hier_truncated_rejected",
          _rejects([{"device": "mx1", "vendor": "junos",
                     "config": "system {\n    host-name mx1;\n}\n"}], mx) is not None)
    # not applied where it must not be: post-change running configs, new devices, junos deltas
    check("I15.replace_mode_unrestricted", _rejects(_ios("hostname r1\n"), base,
                                                    replace=True) is None)
    check("I15.new_device_accepted", _rejects(_ios("hostname n9\n", "n9"), base) is None)
    _, _, log = materialize([{"device": "mx1", "vendor": "junos",
                              "config": "set system host-name mx1"}], mx)
    check("I15.junos_delta_still_merges", log[0]["mode"] == "junos-set-merge", str(log))

    # end to end (fake engine says "clean"): the truncated config can never be ship_ready,
    # the complete one is judged by the intents as before
    ints = parse_intents([DENY])
    sim = SimulatorBackend(converge_fail_rate=0.0, batfish_error_rate=0.0)

    def pipe(config):
        return run_preflight("", backend=sim, lab="single", source="config_import",
                             operator="ci", imported_configs=_ios(config), intents=ints)

    bad = _with_engine(base, lambda: pipe(poc))
    check("I15.pipeline_truncated_blocked", bad["verdict"]["decision"] == "blocked"
          and bad["validation"]["intents"]["errors"] == 1
          and "GigabitEthernet0/0" in bad["validation"]["intents"]["results"][0]["evidence"]
          and verify(bad), f"{bad['verdict']}")
    good = _with_engine(base, lambda: pipe(_read("candidate_r1.cfg")))
    check("I15.pipeline_complete_not_blocked_by_snapshot",
          good["validation"]["intents"]["errors"] == 0
          and good["validation"]["intents"]["engine"] == "batfish",
          json.dumps(good["validation"]["intents"])[:300])


def main() -> int:
    http()
    firewall()
    nat()
    spec()
    semantics()
    snapshots()
    duplicates()
    completeness()
    pipeline()
    if FAILS:
        print("\n=== INTENTS TEST: FAIL ===")
        for f in FAILS:
            print("  -", f)
        return 1
    print(f"\n=== INTENTS TEST: PASS ({CHECKS} checks) ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
