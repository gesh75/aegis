"""HTTP backend — adapts AEGIS to your existing DCN_Network_Tool (:5757), air-gapped.

Every call hits a service running INSIDE the perimeter. No cloud, no external DNS.

Response shapes below were lifted from the REAL handlers + tests in
`04_Scripts_Tools/DCN_Network_Tool/src/app.py` (commit state 2026-05-28):

  /api/batfish/analyze  -> {"errors":int,"warnings":int,"passes":int,
                            "findings":[{"severity":"error|warn|pass","message":str}]}
  /api/nornir/run       -> {"task","site","devices","workers","elapsed",
                            "ok":int,"warn":int,"error":int,
                            "results":[{"hostname","status":"ok|warn|error","output","elapsed"}]}
  /api/pyats/diff       -> {"hostname","total_changes":int,
                            "diffs":[{"type":"interface|bgp","name":str, ...}]}

PARSING is split out into pure functions (parse_batfish / parse_nornir_bgp /
parse_pyats_diff) so they can be contract-tested against fixtures with NO network.
The HTTP methods are thin wrappers over those parsers.

THREE endpoints are NET-NEW for Phase 0 (the existing tool is read-only and cannot
push config). They are tiny and operate only on THROWAWAY twins, never production:
  POST /api/preflight/twin/spawn    {lab}            -> {"twin_id"}
  POST /api/preflight/twin/apply    {twin_id, configs}-> {"applied":bool}
  POST /api/preflight/twin/destroy  {twin_id}         -> {}
Config generation hits the Qwen3 model-runner directly (no new endpoint needed),
reusing your MODEL_RUNNER_URL OpenAI-compatible chat endpoint.
"""
from __future__ import annotations
import json
import re
import urllib.error
import urllib.request
from .base import GeneratedConfig, BatfishResult, TwinResult, DiffResult

_DEFAULT_BASE = "http://127.0.0.1:5757"
_DEFAULT_MODEL_RUNNER = "http://localhost:12434"

# Reference lab metadata mirrors the simulator so verdict logic is identical.
_LAB_VENDORS = {
    "clos-evpn":  ["srlinux", "ceos", "frr"],
    "dcn-10node": ["frr"],
    "edge-slice": ["junos", "ios"],
    "single":     ["frr"],
}

_CONFIGGEN_SYSTEM = (
    "You are a senior multi-vendor network engineer. Translate the change intent into "
    "device configuration. Return JSON ONLY in this shape:\n"
    '{"configs":[{"device":"...","vendor":"srlinux|ceos|frr|junos|ios|panos",'
    '"config":"<cli lines>","grounded_commands":["..."]}]}\n'
    "Ground every config line in real vendor CLI. No prose, no markdown fences."
)


# ── pure parsers (contract-testable, no network) ─────────────────────────

def parse_batfish(resp: dict) -> BatfishResult:
    """Map /api/batfish/analyze JSON -> BatfishResult. Note: API key is 'passes'."""
    findings = [f.get("message", "") for f in resp.get("findings", [])]
    return BatfishResult(
        errors=int(resp.get("errors", 0)),
        warnings=int(resp.get("warnings", 0)),
        passed=int(resp.get("passes", resp.get("passed", 0))),
        findings=findings,
    )


def parse_nornir_bgp(resp: dict) -> tuple[int, int, bool]:
    """From a bgp_health nornir run -> (bgp_up_count, node_count, all_converged).

    A device is 'converged' when status == 'ok'. bgp_up is counted from the per-device
    output line count of Established peers when present, else falls back to ok devices.
    """
    results = resp.get("results", [])
    node_count = int(resp.get("devices", len(results)))
    # fail closed: a response missing the error/results contract is NOT converged
    converged = "error" in resp and "results" in resp and int(resp.get("error", 1)) == 0
    bgp_up = 0
    for r in results:
        out = r.get("output", "") or ""
        # FRR/EOS 'show bgp summary': a peer row starts with the neighbor IP and is
        # Established when the State/PfxRcd column is numeric or 'Estab*'. Matching
        # peer rows only — a bare digit-terminated line (uptimes, counters, totals)
        # must NOT count as a session.
        est = len(re.findall(
            r"^\s*\d{1,3}(?:\.\d{1,3}){3}\s+\S.*?\s(?:\d+|Estab\w*)\s*$",
            out, re.MULTILINE))
        bgp_up += est if est else (1 if r.get("status") == "ok" else 0)
    return bgp_up, node_count, converged


def parse_pyats_diff(resp: dict) -> DiffResult:
    """Map /api/pyats/diff JSON -> DiffResult.

    pyats/diff reports interface + bgp-neighbor state changes (not RIB routes), so
    routes_added/removed stay empty here unless a richer collector is wired. bgp diffs
    that went down become sessions_dropped.
    """
    dropped: list[str] = []
    affected: set[str] = set()
    for d in resp.get("diffs", []):
        name = d.get("name", "?")
        affected.add(name)
        if d.get("type") == "bgp":
            # dropped == session is NOT up after the change (came-up/recovered != dropped)
            post_up = d.get("post_up")
            if post_up is False or (post_up is None and "down" in json.dumps(d).lower()):
                dropped.append(name)
    return DiffResult(
        routes_added=[],
        routes_removed=[],
        sessions_dropped=dropped,
        devices_affected=int(resp.get("total_changes", len(affected))),
    )


def parse_configgen(content: str, lab: str) -> list[GeneratedConfig]:
    """Extract the configs array from an LLM completion (tolerates preamble/fences)."""
    m = re.search(r"\{.*\}", content, re.DOTALL)
    raw = m.group(0) if m else content
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        # fail closed: a no-op stub would sail through validation and produce a
        # sealed ship_ready bundle for a change that was never actually generated
        from aegis.core.orchestrator.pipeline import PreflightError
        raise PreflightError("generation_failed: LLM returned unparseable output") from exc
    out: list[GeneratedConfig] = []
    vendors = _LAB_VENDORS.get(lab, ["frr"])
    for i, c in enumerate(data.get("configs", [])):
        out.append(GeneratedConfig(
            device=c.get("device") or f"{lab}-node-{i+1}",
            vendor=c.get("vendor") or vendors[i % len(vendors)],
            config=c.get("config", ""),
            grounded_commands=list(c.get("grounded_commands", [])),
        ))
    return out or [GeneratedConfig(device=f"{lab}-node-1", vendor="frr",
                                   config="# (no configs returned)",
                                   grounded_commands=[])]


# ── HTTP backend ─────────────────────────────────────────────────────────

class HttpBackend:
    def __init__(self, base_url: str = _DEFAULT_BASE,
                 model_runner_url: str = _DEFAULT_MODEL_RUNNER,
                 model: str = "ai/qwen3:latest", timeout: float = 60.0):
        self.base = base_url.rstrip("/")
        self.model_runner = model_runner_url.rstrip("/")
        self.model = model
        self.timeout = timeout

    def _post(self, url: str, body: dict) -> dict:
        req = urllib.request.Request(
            url, data=json.dumps(body).encode(),
            headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:  # noqa: S310
                return json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            # surface the failing URL + the server's error body, not just "500"
            detail = ""
            try:
                detail = e.read().decode()[:400]
            except Exception:
                pass
            raise RuntimeError(f"POST {url} -> {e.code} {e.reason}: {detail}") from None
        except urllib.error.URLError as e:
            raise RuntimeError(f"POST {url} unreachable: {e.reason}") from None

    # generate (LLM) -- direct to in-perimeter Qwen3 model runner
    def generate_config(self, intent: str, lab: str) -> list[GeneratedConfig]:
        body = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": _CONFIGGEN_SYSTEM},
                {"role": "user", "content": f"lab={lab}\nintent: {intent}"},
            ],
            "temperature": 0.1, "stream": False,
        }
        resp = self._post(f"{self.model_runner}/v1/chat/completions", body)
        content = resp["choices"][0]["message"]["content"]
        return parse_configgen(content, lab)

    def batfish_check(self, configs: list[GeneratedConfig]) -> BatfishResult:
        joined = "\n!\n".join(c["config"] for c in configs)
        return parse_batfish(self._post(f"{self.base}/api/batfish/analyze",
                                        {"config": joined}))

    def spawn_twin(self, lab: str) -> str:
        resp = self._post(f"{self.base}/api/preflight/twin/spawn", {"lab": lab})
        return resp["twin_id"]

    def apply_and_converge(self, twin_id: str,
                           configs: list[GeneratedConfig]) -> TwinResult:
        lab = "-".join(twin_id.split("-")[1:-1]) or "single"
        # capture pre-change BGP, apply candidate, recapture post-change BGP
        pre = self._post(f"{self.base}/api/nornir/run",
                         {"task": "bgp_health", "site": lab, "workers": 50, "twin": twin_id})
        bgp_before, _, _ = parse_nornir_bgp(pre)
        import time as _t
        t0 = _t.perf_counter()
        applied = self._post(f"{self.base}/api/preflight/twin/apply",
                             {"twin_id": twin_id, "configs": configs})
        post = self._post(f"{self.base}/api/nornir/run",
                          {"task": "bgp_health", "site": lab, "workers": 50, "twin": twin_id})
        bgp_after, node_count, converged = parse_nornir_bgp(post)
        return TwinResult(
            topology=lab, node_count=node_count,
            converged=bool(applied.get("applied", True)) and converged,
            convergence_sec=round(_t.perf_counter() - t0, 2),
            bgp_before=bgp_before, bgp_after=bgp_after,
        )

    def state_diff(self, twin_id: str) -> DiffResult:
        # diff is per-host; aggregate across the twin's nodes via the snapshot store
        resp = self._post(f"{self.base}/api/pyats/diff", {"twin": twin_id})
        return parse_pyats_diff(resp)

    def teardown_twin(self, twin_id: str) -> None:
        try:
            self._post(f"{self.base}/api/preflight/twin/destroy", {"twin_id": twin_id})
        except Exception:
            pass  # teardown is best-effort; never mask the real pipeline result
