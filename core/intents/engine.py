"""Intent evaluation — pure, deterministic, fail-closed.

An ``IntentOracle`` answers questions about ONE snapshot (Batfish in production). The engine
asks the same questions of the REFERENCE (before) and CANDIDATE (after) oracles and reports,
per intent, ``before`` and ``status`` (after). A change that turns a passing intent into a
failing one is a **regression**; the verdict blocks on any failing or un-evaluable intent.

Parse fidelity gates trust: if the candidate snapshot has files Batfish could not parse,
every intent is reported as ``error`` — a check over a config the engine did not understand
is not evidence.
"""
from __future__ import annotations

from typing import Protocol, runtime_checkable

import re

PASS, FAIL, ERROR = "pass", "fail", "error"
_MAX_EXAMPLES = 3
# Batfish success dispositions; anything else (DENIED_IN/OUT, NO_ROUTE, NULL_ROUTED, LOOP,
# INSUFFICIENT_INFO, ...) means the flow was not delivered.
DELIVERED = {"ACCEPTED", "DELIVERED_TO_SUBNET", "EXITS_NETWORK"}
# firewall_policy is about TRANSIT traffic: a flow ACCEPTED by the firewall itself (its own
# interface IP — control/management plane) never crosses a zone policy.
TRANSIT = "DELIVERED_TO_SUBNET,EXITS_NETWORK"
_BARE = re.compile(r"^[A-Za-z0-9/._:-]+$")


class OracleError(Exception):
    """The oracle could not answer (engine down, snapshot rejected, question failed)."""


@runtime_checkable
class IntentOracle(Protocol):
    name: str

    def parse_status(self) -> list[dict]:
        """[{file, status}] — status PASSED | PARTIALLY_UNRECOGNIZED | FAILED | ..."""
        ...

    def reachability(self, *, start: str | None, src_ips: str | None, dst_ips: str,
                     protocols: list[str] | None, dst_ports: str | None,
                     action: str) -> list[str]:
        """Example flows (as text) matching ``action`` — SUCCESS | FAILURE, or a comma list
        of Batfish dispositions (e.g. DELIVERED_TO_SUBNET,EXITS_NETWORK); [] = none."""
        ...

    def bgp_sessions(self, nodes: str | None) -> list[dict]:
        """[{node, remote, status}] — status ESTABLISHED | NOT_ESTABLISHED | ..."""
        ...

    def undefined_references(self) -> list[str]:
        ...

    def unreachable_filter_lines(self, nodes: str | None) -> list[str]:
        ...

    def zone_interfaces(self, node: str, zone: str) -> list[str]:
        """Interface names on ``node`` that belong to security zone ``zone``; [] = none."""
        ...

    def traceroute(self, *, start: str, src_ip: str, dst_ip: str, protocol: str,
                   dst_port: int | None) -> list[dict]:
        """One concrete flow → [{disposition, final:{srcIp,dstIp,srcPort,dstPort},
        changes:[text], text}] — one entry per trace (ECMP may yield several)."""
        ...


def _q(name: str) -> str:
    """Quote a node/interface name for a Batfish specifier when it has special chars."""
    return name if _BARE.match(name) else '"' + name.replace('"', "") + '"'


def _row(intent: dict, status: str, evidence: str, examples: list[str] | None = None) -> dict:
    row = {"id": intent["id"], "kind": intent["kind"], "expect": intent["expect"],
           "status": status, "evidence": evidence,
           "examples": [str(e)[:300] for e in (examples or [])][:_MAX_EXAMPLES]}
    if intent.get("control"):
        row["control"] = intent["control"]
    return row


def _reach(intent: dict, oracle: IntentOracle, start: str | None, label: str,
           success: str = "SUCCESS") -> dict:
    """deny: no flow may succeed. allow: every flow must succeed AND at least one exists.
    ``success`` narrows what counts as success (firewall_policy: transit dispositions)."""
    q = dict(start=start, src_ips=intent.get("src_ips"), dst_ips=intent["dst_ips"],
             protocols=intent.get("protocols"), dst_ports=intent.get("dst_ports"))
    if intent["expect"] == "deny":
        leaks = oracle.reachability(action=success, **q)
        if leaks:
            return _row(intent, FAIL, f"{label}{len(leaks)}+ flow(s) succeed that must be "
                        "denied", leaks)
        return _row(intent, PASS, f"{label}no flow in the header space succeeds (denied)")
    fails = oracle.reachability(action="FAILURE", **q)
    if fails:
        return _row(intent, FAIL, f"{label}{len(fails)}+ flow(s) fail that must be allowed",
                    fails)
    ok = oracle.reachability(action=success, **q)
    if not ok:
        # an empty header space (e.g. no matching start location) proves nothing
        return _row(intent, ERROR, f"{label}no flow matched the constraints — check the "
                    "start location / zones / prefixes (vacuous allow is not a pass)")
    return _row(intent, PASS, f"{label}every flow in the header space succeeds (allowed)", ok)


_WANT = (("translated_src_ip", "srcIp"), ("translated_dst_ip", "dstIp"),
         ("translated_dst_port", "dstPort"))


def _nat(intent: dict, oracle: IntentOracle) -> dict:
    """The flow must be delivered, and its post-NAT header must match the intent."""
    traces = oracle.traceroute(start=intent["start"], src_ip=intent["src_ip"],
                               dst_ip=intent["dst_ip"], protocol=intent["protocol"],
                               dst_port=intent.get("dst_port"))
    if not traces:
        return _row(intent, ERROR, "traceroute produced no trace — check the start location")
    bad: list[str] = []
    seen: list[str] = []
    for t in traces:
        disp = str(t.get("disposition", "")).upper()
        final = t.get("final") or {}
        changes = [str(c) for c in t.get("changes") or []]
        seen.extend(changes)
        if disp not in DELIVERED:
            bad.append(f"not delivered ({disp}): {t.get('text', '')}")
            continue
        if intent["expect"] == "translated":
            for field, key in _WANT:
                if field in intent and str(final.get(key)) != str(intent[field]):
                    bad.append(f"{key} after NAT is {final.get(key)} (expected "
                               f"{intent[field]})" + (f"; {'; '.join(changes)}" if changes else ""))
        elif changes:
            bad.append("translated: " + "; ".join(changes))
    if bad:
        return _row(intent, FAIL, f"{len(bad)} trace(s) violate the NAT intent", bad)
    what = "; ".join(dict.fromkeys(seen)) or "no translation"
    return _row(intent, PASS, f"{len(traces)} trace(s) delivered — {what}"[:300])


def _eval_one(intent: dict, oracle: IntentOracle) -> dict:
    kind = intent["kind"]
    try:
        if kind == "reachability":
            return _reach(intent, oracle, intent.get("start"), "")
        if kind == "firewall_policy":
            node = intent["node"]
            src_if = oracle.zone_interfaces(node, intent["from_zone"])
            dst_if = oracle.zone_interfaces(node, intent["to_zone"])
            for zone, ifs in ((intent["from_zone"], src_if), (intent["to_zone"], dst_if)):
                if not ifs:
                    return _row(intent, ERROR, f"zone {zone!r} has no interfaces on {node} "
                                "(typo, or zones are not modeled for this config)")
            start = ",".join(f"@enter({_q(node)}[{_q(i)}])" for i in src_if)
            return _reach(intent, oracle, start,
                          f"{node} {intent['from_zone']}→{intent['to_zone']} (transit): ",
                          success=TRANSIT)
        if kind == "nat":
            return _nat(intent, oracle)
        if kind == "bgp_sessions":
            sessions = oracle.bgp_sessions(intent.get("nodes"))
            if not sessions:
                return _row(intent, ERROR, "no BGP sessions found — nothing to assert")
            down = [f"{s.get('node')}→{s.get('remote')}: {s.get('status')}"
                    for s in sessions if str(s.get("status", "")).upper() != "ESTABLISHED"]
            if down:
                return _row(intent, FAIL, f"{len(down)}/{len(sessions)} session(s) not "
                            "established", down)
            return _row(intent, PASS, f"all {len(sessions)} BGP session(s) established")
        if kind == "undefined_references":
            refs = oracle.undefined_references()
            if refs:
                return _row(intent, FAIL, f"{len(refs)} undefined reference(s)", refs)
            return _row(intent, PASS, "no undefined references")
        if kind == "filter_line_reachability":
            dead = oracle.unreachable_filter_lines(intent.get("nodes"))
            if dead:
                return _row(intent, FAIL, f"{len(dead)} ACL/filter line(s) can never match "
                            "(shadowed or unreachable)", dead)
            return _row(intent, PASS, "every ACL/filter line is reachable")
    except OracleError as exc:
        return _row(intent, ERROR, f"oracle error: {exc}")
    except Exception as exc:  # noqa: BLE001 — an unexpected oracle failure is an error row
        return _row(intent, ERROR, f"oracle failure: {type(exc).__name__}")
    return _row(intent, ERROR, f"unsupported kind {kind!r}")


def _fidelity(oracle: IntentOracle) -> dict:
    try:
        files = oracle.parse_status()
    except Exception as exc:  # noqa: BLE001
        return {"files": 0, "failed": 0, "partial": 0, "ok": False,
                "issues": [f"parse status unavailable: {type(exc).__name__}"]}
    failed = [f["file"] for f in files if str(f.get("status")).upper() == "FAILED"]
    partial = [f["file"] for f in files
               if str(f.get("status")).upper() == "PARTIALLY_UNRECOGNIZED"]
    issues = ([f"{n}: FAILED to parse" for n in failed]
              + [f"{n}: partially unrecognized" for n in partial])
    return {"files": len(files), "failed": len(failed), "partial": len(partial),
            "ok": bool(files) and not failed, "issues": issues[:20]}


def evaluate(intents: list[dict], oracle: IntentOracle) -> tuple[list[dict], dict]:
    fid = _fidelity(oracle)
    if not fid["ok"]:
        why = "; ".join(fid["issues"][:3]) or "snapshot has no parseable files"
        return [_row(i, ERROR, f"snapshot fidelity: {why}") for i in intents], fid
    return [_eval_one(i, oracle) for i in intents], fid


def check_intents(intents: list[dict], *, candidate: IntentOracle | None,
                  reference: IntentOracle | None = None, engine: str = "unknown",
                  snapshot: dict | None = None, unavailable_reason: str = "") -> dict:
    """The sealed ``validation.intents`` record. ``candidate=None`` → every intent is an
    error (fail closed: intents were requested but no engine could evaluate them)."""
    if candidate is None:
        rows = [_row(i, ERROR, f"intent engine unavailable: {unavailable_reason or 'none'}")
                for i in intents]
        for r in rows:
            r["before"] = None
        return {"engine": "unavailable", "snapshot": snapshot or {}, "fidelity": None,
                "results": rows, "failed": 0, "errors": len(rows), "regressions": 0}
    after, fid = evaluate(intents, candidate)
    before_by_id: dict[str, str | None] = {i["id"]: None for i in intents}
    if reference is not None:
        before, _ = evaluate(intents, reference)
        before_by_id = {r["id"]: r["status"] for r in before}
    regressions = 0
    for r in after:
        r["before"] = before_by_id.get(r["id"])
        if r["before"] == PASS and r["status"] != PASS:
            r["regression"] = True
            regressions += 1
    return {
        "engine": engine,
        "snapshot": snapshot or {},
        "fidelity": fid,
        "results": after,
        "failed": sum(1 for r in after if r["status"] == FAIL),
        "errors": sum(1 for r in after if r["status"] == ERROR),
        "regressions": regressions,
    }
