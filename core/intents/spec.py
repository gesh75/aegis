"""Intent spec: parse + validate. Fail closed — an unknown kind or field is an error, never
silently ignored (a typo in a security intent must not turn into "no check ran").

    {"intents": [
      {"id": "guest-cannot-reach-cde", "kind": "reachability",
       "start": "@enter(fw1[ge-0/0/1])", "src_ips": "10.50.0.0/16",
       "dst_ips": "10.10.0.0/24", "protocols": ["tcp"], "dst_ports": "1-65535",
       "expect": "deny", "control": "PCI DSS v4.0 1.3.1"},
      {"id": "bgp-up",        "kind": "bgp_sessions",             "expect": "all_established"},
      {"id": "no-undef-refs", "kind": "undefined_references",     "expect": "none"},
      {"id": "no-dead-acl",   "kind": "filter_line_reachability", "expect": "none"},
      {"id": "untrust-x-trust", "kind": "firewall_policy", "node": "fw1",
       "from_zone": "untrust", "to_zone": "trust", "dst_ips": "10.1.0.0/24", "expect": "deny"},
      {"id": "web-dnat", "kind": "nat", "start": "@enter(fw1[ge-0/0/1.0])",
       "src_ip": "198.51.100.7", "dst_ip": "203.0.113.10", "protocol": "tcp", "dst_port": 443,
       "expect": "translated", "translated_dst_ip": "10.2.0.10"}
    ]}
"""
from __future__ import annotations

import ipaddress
import json
import re

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_PORTS = re.compile(r"^\d{1,5}(-\d{1,5})?(,\d{1,5}(-\d{1,5})?)*$")
_LOCATION = re.compile(r"^[A-Za-z0-9@()\[\]/:._,\- ]{1,200}$")
_PROTOCOLS = {"tcp", "udp", "icmp", "ip"}
_NAME = re.compile(r"^[A-Za-z0-9._:~-]{1,100}$")         # node / zone names
MAX_INTENTS = 200

KINDS: dict[str, dict] = {
    "reachability": {
        "expect": {"allow", "deny"},
        "required": {"dst_ips"},
        "optional": {"start", "src_ips", "protocols", "dst_ports"},
    },
    "bgp_sessions": {"expect": {"all_established"}, "required": set(),
                     "optional": {"nodes"}},
    "undefined_references": {"expect": {"none"}, "required": set(), "optional": set()},
    "filter_line_reachability": {"expect": {"none"}, "required": set(),
                                 "optional": {"nodes"}},
    # zone-to-zone policy on one firewall (Juniper SRX, Palo Alto, any zone-based NSC)
    "firewall_policy": {
        "expect": {"allow", "deny"},
        "required": {"node", "from_zone", "to_zone", "dst_ips"},
        "optional": {"src_ips", "protocols", "dst_ports"},
    },
    # one concrete flow through NAT (traceroute): is it translated, and to what?
    "nat": {
        "expect": {"translated", "untranslated"},
        "required": {"start", "src_ip", "dst_ip"},
        "optional": {"protocol", "dst_port", "translated_src_ip", "translated_dst_ip",
                     "translated_dst_port"},
    },
}
_COMMON = {"id", "kind", "expect", "control", "description"}


class IntentSpecError(ValueError):
    """The intent document is malformed. Callers must treat this as a guard rejection."""


def _ips(value, field: str, iid: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise IntentSpecError(f"{iid}: {field} must be a non-empty string")
    for part in value.split(","):
        try:
            ipaddress.ip_network(part.strip(), strict=False)
        except ValueError as exc:
            raise IntentSpecError(f"{iid}: {field} {part.strip()!r} is not an IP/prefix") from exc
    return value.replace(" ", "")


def _ip(value, field: str, iid: str) -> str:
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError as exc:
        raise IntentSpecError(f"{iid}: {field} {value!r} must be a single IP address") from exc


def _port(value, field: str, iid: str) -> int:
    try:
        port = int(value)
    except (TypeError, ValueError) as exc:
        raise IntentSpecError(f"{iid}: {field} must be an integer port") from exc
    if isinstance(value, bool) or not 0 < port <= 65535:
        raise IntentSpecError(f"{iid}: {field} {value!r} out of range")
    return port


def _name(value, field: str, iid: str) -> str:
    if not isinstance(value, str) or not _NAME.match(value):
        raise IntentSpecError(f"{iid}: {field} must match {_NAME.pattern}")
    return value


def _flow_fields(raw: dict, out: dict, iid: str) -> None:
    """protocols / dst_ports shared by reachability and firewall_policy."""
    if "protocols" in raw:
        protos = raw["protocols"]
        if (not isinstance(protos, list) or not protos
                or any(str(p).lower() not in _PROTOCOLS for p in protos)):
            raise IntentSpecError(f"{iid}: protocols must be a list of {sorted(_PROTOCOLS)}")
        out["protocols"] = sorted({str(p).lower() for p in protos})
    if "dst_ports" in raw:
        ports = str(raw["dst_ports"]).replace(" ", "")
        if not _PORTS.match(ports) or any(int(p) > 65535 for p in re.findall(r"\d+", ports)):
            raise IntentSpecError(f"{iid}: dst_ports {raw['dst_ports']!r} invalid")
        out["dst_ports"] = ports


def _one(raw: dict, seen: set[str]) -> dict:
    if not isinstance(raw, dict):
        raise IntentSpecError("each intent must be an object")
    iid = raw.get("id")
    if not isinstance(iid, str) or not _ID.match(iid):
        raise IntentSpecError(f"intent id {iid!r} must match {_ID.pattern}")
    if iid in seen:
        raise IntentSpecError(f"duplicate intent id {iid!r}")
    kind = raw.get("kind")
    if kind not in KINDS:
        raise IntentSpecError(f"{iid}: unknown kind {kind!r} (one of {sorted(KINDS)})")
    rule = KINDS[kind]
    allowed = _COMMON | rule["required"] | rule["optional"]
    extra = set(raw) - allowed
    if extra:
        raise IntentSpecError(f"{iid}: unknown field(s) {sorted(extra)} for kind {kind}")
    missing = rule["required"] - set(raw)
    if missing:
        raise IntentSpecError(f"{iid}: missing required field(s) {sorted(missing)}")
    expect = raw.get("expect")
    if expect not in rule["expect"]:
        raise IntentSpecError(f"{iid}: expect must be one of {sorted(rule['expect'])}")
    out: dict = {"id": iid, "kind": kind, "expect": expect}
    for opt in ("control", "description"):
        if opt in raw:
            if not isinstance(raw[opt], str) or len(raw[opt]) > 200:
                raise IntentSpecError(f"{iid}: {opt} must be a string ≤200 chars")
            out[opt] = raw[opt]
    if kind == "reachability":
        out["dst_ips"] = _ips(raw["dst_ips"], "dst_ips", iid)
        if "src_ips" in raw:
            out["src_ips"] = _ips(raw["src_ips"], "src_ips", iid)
        if "start" in raw:
            if not isinstance(raw["start"], str) or not _LOCATION.match(raw["start"]):
                raise IntentSpecError(f"{iid}: start is not a valid location specifier")
            out["start"] = raw["start"]
        _flow_fields(raw, out, iid)
        if "start" not in out and "src_ips" not in out:
            raise IntentSpecError(f"{iid}: reachability needs start and/or src_ips")
    if kind == "firewall_policy":
        for f in ("node", "from_zone", "to_zone"):
            out[f] = _name(raw[f], f, iid)
        out["dst_ips"] = _ips(raw["dst_ips"], "dst_ips", iid)
        if "src_ips" in raw:
            out["src_ips"] = _ips(raw["src_ips"], "src_ips", iid)
        _flow_fields(raw, out, iid)
    if kind == "nat":
        if not isinstance(raw["start"], str) or not _LOCATION.match(raw["start"]):
            raise IntentSpecError(f"{iid}: start is not a valid location specifier")
        out["start"] = raw["start"]
        out["src_ip"] = _ip(raw["src_ip"], "src_ip", iid)
        out["dst_ip"] = _ip(raw["dst_ip"], "dst_ip", iid)
        proto = str(raw.get("protocol", "tcp")).lower()
        if proto not in ("tcp", "udp", "icmp"):
            raise IntentSpecError(f"{iid}: protocol must be tcp, udp or icmp")
        out["protocol"] = proto
        if "dst_port" in raw:
            if proto == "icmp":
                raise IntentSpecError(f"{iid}: dst_port does not apply to icmp")
            out["dst_port"] = _port(raw["dst_port"], "dst_port", iid)
        elif proto != "icmp":
            raise IntentSpecError(f"{iid}: dst_port is required for {proto}")
        for f in ("translated_src_ip", "translated_dst_ip"):
            if f in raw:
                out[f] = _ip(raw[f], f, iid)
        if "translated_dst_port" in raw:
            out["translated_dst_port"] = _port(raw["translated_dst_port"],
                                               "translated_dst_port", iid)
        wants = [f for f in ("translated_src_ip", "translated_dst_ip", "translated_dst_port")
                 if f in out]
        if out["expect"] == "translated" and not wants:
            raise IntentSpecError(f"{iid}: expect translated needs translated_src_ip, "
                                  "translated_dst_ip and/or translated_dst_port")
        if out["expect"] == "untranslated" and wants:
            raise IntentSpecError(f"{iid}: expect untranslated takes no translated_* fields")
    if "nodes" in raw:
        nodes = raw["nodes"]
        if not isinstance(nodes, str) or not _LOCATION.match(nodes):
            raise IntentSpecError(f"{iid}: nodes must be a node specifier string")
        out["nodes"] = nodes
    seen.add(iid)
    return out


def parse_intents(doc) -> list[dict]:
    """Accept {"intents": [...]} or a bare list. Returns normalized intents."""
    items = doc.get("intents") if isinstance(doc, dict) else doc
    if not isinstance(items, list):
        raise IntentSpecError("intent document must be a list or {\"intents\": [...]}")
    if len(items) > MAX_INTENTS:
        raise IntentSpecError(f"too many intents ({len(items)} > {MAX_INTENTS})")
    seen: set[str] = set()
    return [_one(raw, seen) for raw in items]


def load_intents(path: str) -> list[dict]:
    """Load from a .json, or .yml/.yaml file (YAML needs PyYAML; absent → explicit error)."""
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    if path.lower().endswith((".yml", ".yaml")):
        try:
            import yaml  # type: ignore
        except ImportError as exc:
            raise IntentSpecError("YAML intents need PyYAML; install it or use .json") from exc
        doc = yaml.safe_load(text)
    else:
        try:
            doc = json.loads(text)
        except json.JSONDecodeError as exc:
            raise IntentSpecError(f"{path}: invalid JSON ({exc.msg})") from exc
    return parse_intents(doc)
