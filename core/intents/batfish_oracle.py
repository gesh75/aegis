"""Batfish-backed IntentOracle (pybatfish → in-perimeter batfish/allinone service).

Optional dependency: ``pip install -r requirements-batfish.txt``. Importing this module
without pybatfish raises ImportError, which the runner turns into a fail-closed result.

Snapshots are uploaded under unique names and deleted on exit, so concurrent preflights
never read each other's candidate and a crashed run does not leave a snapshot behind
(best-effort delete; Batfish also garbage-collects on restart).
"""
from __future__ import annotations

import os
import tempfile
import uuid

from pybatfish.client.session import Session  # noqa: F401 — ImportError is the signal
from pybatfish.datamodel.flow import HeaderConstraints, PathConstraints

from .engine import OracleError


def _g(obj, key, default=None):
    """Attribute OR mapping access — pybatfish returns dataclasses, older versions dicts."""
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def _iface_name(value) -> tuple[str, str]:
    """(hostname, interface) from a NodeInterfacePair, its dict form or 'host[iface]' text."""
    host, name = _g(value, "hostname"), _g(value, "interface")
    if host is not None and name is not None:
        return str(host), str(name)
    text = str(value)
    if "[" in text and text.endswith("]"):
        host, _, name = text[:-1].partition("[")
        return host, name
    return "", text


def _zone_matches(found, zone: str) -> bool:
    # Palo Alto zones may be namespaced per vsys in Batfish's model ("vsys1~trust")
    z = str(found or "")
    return z == zone or z.rsplit("~", 1)[-1] == zone


def _rows(frame) -> list[dict]:
    try:
        return frame.to_dict(orient="records")
    except Exception as exc:  # noqa: BLE001
        raise OracleError(f"unexpected answer shape: {type(exc).__name__}") from exc


class BatfishOracle:
    name = "batfish"

    def __init__(self, bf: Session, snapshot: str) -> None:
        self.bf = bf
        self.snapshot = snapshot

    def _ask(self, question):
        try:
            return _rows(question.answer(snapshot=self.snapshot).frame())
        except OracleError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise OracleError(f"{type(exc).__name__}: {str(exc)[:200]}") from exc

    def parse_status(self) -> list[dict]:
        return [{"file": str(r.get("File_Name")), "status": str(r.get("Status"))}
                for r in self._ask(self.bf.q.fileParseStatus())]

    def reachability(self, *, start, src_ips, dst_ips, protocols, dst_ports, action):
        hdr: dict = {"dstIps": dst_ips}
        if src_ips:
            hdr["srcIps"] = src_ips
        if protocols and "ip" not in protocols:
            hdr["ipProtocols"] = [p.upper() for p in protocols]
        if dst_ports:
            hdr["dstPorts"] = dst_ports
        kwargs: dict = {"headers": HeaderConstraints(**hdr), "actions": action}
        if start:
            kwargs["pathConstraints"] = PathConstraints(startLocation=start)
        return [str(r.get("Flow")) for r in self._ask(self.bf.q.reachability(**kwargs))]

    def bgp_sessions(self, nodes):
        q = self.bf.q.bgpSessionStatus(nodes=nodes) if nodes else self.bf.q.bgpSessionStatus()
        return [{"node": str(r.get("Node")),
                 "remote": str(r.get("Remote_Node") or r.get("Remote_IP")),
                 "status": str(r.get("Established_Status"))} for r in self._ask(q)]

    def undefined_references(self):
        return [f"{r.get('File_Name')}: {r.get('Struct_Type')} '{r.get('Ref_Name')}' "
                f"({r.get('Context')})" for r in self._ask(self.bf.q.undefinedReferences())]

    def unreachable_filter_lines(self, nodes):
        q = (self.bf.q.filterLineReachability(nodes=nodes) if nodes
             else self.bf.q.filterLineReachability())
        return [f"{r.get('Sources')}: {r.get('Unreachable_Line')} — {r.get('Reason')}"
                for r in self._ask(q)]

    def zone_interfaces(self, node, zone):
        rows = self._ask(self.bf.q.interfaceProperties(nodes=node, properties="Zone_Name"))
        return sorted({_iface_name(r.get("Interface"))[1] for r in rows
                       if _zone_matches(r.get("Zone_Name"), zone)})

    def traceroute(self, *, start, src_ip, dst_ip, protocol, dst_port):
        hdr: dict = {"srcIps": src_ip, "dstIps": dst_ip, "ipProtocols": [protocol.upper()]}
        if dst_port:
            hdr["dstPorts"] = str(dst_port)
        out: list[dict] = []
        for r in self._ask(self.bf.q.traceroute(startLocation=start,
                                                headers=HeaderConstraints(**hdr))):
            flow = r.get("Flow")
            for t in r.get("Traces") or []:
                final = {k: _g(flow, k) for k in ("srcIp", "dstIp", "srcPort", "dstPort")}
                changes: list[str] = []
                for hop in _g(t, "hops") or []:
                    for step in _g(hop, "steps") or []:
                        for fd in _g(_g(step, "detail"), "flowDiffs") or []:
                            key = str(_g(fd, "fieldName"))
                            final[key] = _g(fd, "newValue")
                            changes.append(f"{_g(hop, 'node')}: {key} {_g(fd, 'oldValue')}"
                                           f"→{_g(fd, 'newValue')}")
                out.append({"disposition": str(_g(t, "disposition")),
                            "final": {k: (None if v is None else str(v))
                                      for k, v in final.items()},
                            "changes": changes, "text": str(t)[:300]})
        return out


class BatfishSnapshots:
    """Context manager: upload reference (optional) + candidate, yield two oracles, clean up."""

    def __init__(self, host: str, network: str, reference: dict[str, str] | None,
                 candidate: dict[str, str]) -> None:
        self.host, self.network = host, network
        self.reference, self.candidate = reference, candidate
        self.bf: Session | None = None
        self.names: list[str] = []
        self._tmp = tempfile.TemporaryDirectory(prefix="aegis-bf-")

    def _upload(self, files: dict[str, str], label: str) -> str:
        root = os.path.join(self._tmp.name, label)
        for rel, text in files.items():
            path = os.path.join(root, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(text)
        name = f"aegis-{label}-{uuid.uuid4().hex[:12]}"
        self.bf.init_snapshot(root, name=name, overwrite=True)
        self.names.append(name)
        return name

    def __enter__(self):
        try:
            self.bf = Session(host=self.host)
            self.bf.set_network(self.network)
            ref = None
            if self.reference:
                ref = BatfishOracle(self.bf, self._upload(self.reference, "reference"))
            cand = BatfishOracle(self.bf, self._upload(self.candidate, "candidate"))
        except BaseException:
            self.__exit__()          # __exit__ is not called when __enter__ raises
            raise
        return ref, cand

    def __exit__(self, *exc) -> None:
        for name in self.names if self.bf is not None else []:
            try:
                self.bf.delete_snapshot(name)
            except Exception:  # noqa: BLE001 — cleanup is best-effort
                pass
        self._tmp.cleanup()
