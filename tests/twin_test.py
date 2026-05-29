"""AEGIS twin safety + management-isolation harness.

SCOPE — what this proves, and what it does not
-----------------------------------------------
The real containerlab twin (a TwinManager that shells out to `clab deploy/destroy`)
lives in the integrated *live* deployment, NOT in this community core — `serve.py`
runs sim-tier only. What this repository *does* ship is the twin **client and
orchestration contract**:

  - HttpBackend         the in-perimeter twin client (spawn / apply / diff / destroy)
  - run_preflight(...)  guarantees the twin is ALWAYS torn down (a `finally`)

This suite drives the *real* pipeline over a RECORDING transport (no Docker, no
sockets) across thousands of randomized + adversarial runs, plus a concurrency pass,
and asserts the isolation invariants that make a throwaway twin safe to operate
beside production:

  ISO-1  no twin leak       every spawned twin is torn down  (spawns == destroys)
  ISO-2  twin-scoped ops     every apply/diff/destroy targets a twin_id spawned THIS
                             run — never a production site or topology fragment
  ISO-3  named isolation     twin_ids are unique; concurrent runs never share one
  ISO-4  egress: none        every outbound call stays on the in-perimeter base /
                             model-runner host — no external host is ever contacted
  ISO-5  injection-safe      the transport is pure JSON-over-HTTP: adversarial intent
                             tokens never become a shell command — they ride as JSON
                             values and are carried intact, byte-for-byte
  ISO-6  teardown-on-failure when apply/diff raises mid-run, the twin is STILL
                             destroyed (no leak on the error path)

Usage:  python3 -m aegis.tests.twin_test [N]
"""
from __future__ import annotations
import json
import random
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlsplit

from ..core.backends.http_backend import HttpBackend
from ..core.orchestrator.pipeline import run_preflight, PreflightError

# Shell/abuse tokens that must never escape JSON into a command (ISO-5).
INJECTION = [";rm -rf /", "$(reboot)", "`id`", "&& curl evil.example", "| nc x 1",
             "../../etc/passwd", "${IFS}cat /etc/shadow", "spine1\nshutdown"]
# Production topology/container fragments a twin op must NEVER target (ISO-2).
PROD_FRAGMENTS = ["clab-clos-evpn-spine1", "de-fra-core-01", "uk-lon-core-01",
                  "clab-minimal-", "prod-core"]
LABS = ["clos-evpn", "dcn-10node", "edge-slice", "single"]

_TWIN_URLS = ("/api/preflight/twin/spawn", "/api/preflight/twin/apply",
              "/api/preflight/twin/destroy")


def _body_strings(obj):
    """Yield every string anywhere inside a JSON-able structure."""
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from _body_strings(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _body_strings(v)


class _RecordingBackend(HttpBackend):
    """HttpBackend with its transport replaced by an in-memory recorder.

    Records every (url, body) and returns canned, well-formed shapes for the
    model-runner, batfish, twin spawn/apply/destroy, nornir and pyats endpoints —
    with NO real network. `fail_on` makes a chosen endpoint raise, to exercise the
    teardown-on-failure path (ISO-6).
    """

    def __init__(self, *args, fail_on: str | None = None, **kwargs):
        super().__init__(*args, **kwargs)
        self.calls: list[tuple[str, dict]] = []
        self._lock = threading.Lock()
        self._twin_seq = 0
        self.spawned: list[str] = []
        self.fail_on = fail_on

    def _post(self, url: str, body: dict) -> dict:
        with self._lock:
            self.calls.append((url, dict(body)))
            if self.fail_on and self.fail_on in url:
                raise RuntimeError(f"simulated transport failure at {url}")
            if url.endswith("/v1/chat/completions"):
                cfg = {"configs": [{"device": "leaf1", "vendor": "frr",
                                    "config": "router bgp 65010\n neighbor 10.0.0.1",
                                    "grounded_commands": ["router bgp"]}]}
                return {"choices": [{"message": {"content": json.dumps(cfg)}}]}
            if url.endswith("/api/batfish/analyze"):
                return {"errors": 0, "warnings": 0, "passes": 1, "findings": []}
            if url.endswith("/api/preflight/twin/spawn"):
                self._twin_seq += 1
                lab = body.get("lab", "single")
                tid = f"twin-{lab}-{self._twin_seq:05d}"
                self.spawned.append(tid)
                return {"twin_id": tid}
            if url.endswith("/api/nornir/run"):
                return {"devices": 4, "error": 0,
                        "results": [{"hostname": f"n{i}", "status": "ok",
                                     "output": "Established"} for i in range(4)]}
            if url.endswith("/api/preflight/twin/apply"):
                return {"applied": True}
            if url.endswith("/api/pyats/diff"):
                return {"hostname": "n0", "total_changes": 0, "diffs": []}
            if url.endswith("/api/preflight/twin/destroy"):
                return {}
            return {}

    # convenience accessors over the recorded transport ------------------
    def _hosts(self) -> set[str]:
        return {urlsplit(u).netloc for u, _ in self.calls}

    def _allowed_hosts(self) -> set[str]:
        return {urlsplit(self.base).netloc, urlsplit(self.model_runner).netloc}

    def _twin_calls(self, suffix: str) -> list[dict]:
        return [b for u, b in self.calls if u.endswith(suffix)]


def _check_run(bk: _RecordingBackend, token: str | None, fails: list[str]) -> None:
    """Assert ISO-1/2/4/5 for a single completed run on a fresh backend."""
    spawns = bk._twin_calls("/api/preflight/twin/spawn")
    destroys = bk._twin_calls("/api/preflight/twin/destroy")
    applies = bk._twin_calls("/api/preflight/twin/apply")

    # ISO-1: exactly one spawn, and it was torn down.
    if len(spawns) != 1:
        fails.append(f"ISO-1 expected 1 spawn, got {len(spawns)}")
    if len(destroys) != 1:
        fails.append(f"ISO-1 twin leaked: {len(spawns)} spawn / {len(destroys)} destroy")
    if not bk.spawned:
        fails.append("ISO-1 no twin_id handed out")
        return
    tid = bk.spawned[0]

    # ISO-2: every apply/destroy targets THIS twin — never a prod fragment.
    for b in applies + destroys:
        if b.get("twin_id") != tid:
            fails.append(f"ISO-2 op targeted {b.get('twin_id')!r}, not spawned {tid!r}")
        if any(frag in str(b.get("twin_id", "")) for frag in PROD_FRAGMENTS):
            fails.append(f"ISO-2 op targeted a PRODUCTION fragment: {b.get('twin_id')!r}")

    # ISO-4: no call ever left the perimeter.
    stray = bk._hosts() - bk._allowed_hosts()
    if stray:
        fails.append(f"ISO-4 egress to non-perimeter host(s): {stray}")

    # ISO-5: the transport is JSON; an injected token rides intact in a body value
    #        (survives a JSON round-trip losslessly) and NEVER appears inside a URL
    #        — so it can never be interpolated into a shell command or path.
    if token is not None:
        in_url = [u for u, _ in bk.calls if token in u]
        if in_url:
            fails.append(f"ISO-5 token leaked into URL(s): {in_url}")
        carried = any(
            token in s
            for _, b in bk.calls
            for s in _body_strings(json.loads(json.dumps(b)))  # prove JSON round-trips
        )
        if not carried:
            fails.append(f"ISO-5 token not carried losslessly as a JSON value: {token!r}")


def _one_run(seed: int) -> tuple[_RecordingBackend, str | None, str]:
    """Execute one randomized pipeline run on its own fresh recording backend."""
    rng = random.Random(seed)
    bk = _RecordingBackend()
    lab = rng.choice(LABS)
    token = rng.choice(INJECTION) if rng.random() < 0.5 else None

    if rng.random() < 0.30:  # config_import path (no LLM) — operator-supplied configs
        dev = token or "leaf1"
        cfgs = [{"device": dev, "vendor": "frr",
                 "config": f"router bgp 65010 {token or ''}".strip()}]
        run_preflight("", backend=bk, lab=lab, source="config_import",
                      imported_configs=cfgs, operator="stress")
        return bk, token, "config_import"

    intent = f"add bgp peer 10.0.0.5 {token or 'to leaf1'}".strip()
    run_preflight(intent, backend=bk, lab=lab, source="nl_intent", operator="stress")
    return bk, token, "nl_intent"


def run(n: int = 8000) -> int:
    fails: list[str] = []
    total_spawn = total_destroy = 0

    # ── randomized + adversarial single runs (ISO-1/2/4/5) ──────────────
    for i in range(n):
        bk, token, _ = _one_run(i + 1)
        _check_run(bk, token, fails)
        total_spawn += len(bk._twin_calls("/api/preflight/twin/spawn"))
        total_destroy += len(bk._twin_calls("/api/preflight/twin/destroy"))
        if fails and len(fails) > 20:  # fail fast on a systemic break
            break

    # ── ISO-6: failure mid-pipeline still tears the twin down ───────────
    iso6_checked = iso6_leaks = 0
    for i, stage in enumerate(("/api/preflight/twin/apply", "/api/nornir/run",
                               "/api/pyats/diff")):
        bk = _RecordingBackend(fail_on=stage)
        raised = False
        try:
            run_preflight(f"add vlan {i}", backend=bk, lab="single",
                          source="nl_intent", operator="iso6")
        except Exception:  # noqa: BLE001 — the pipeline error must surface
            raised = True
        iso6_checked += 1
        if not raised:
            fails.append(f"ISO-6 failure at {stage} did not surface")
        # a twin was spawned, so a destroy MUST have been attempted (finally)
        if bk.spawned and len(bk._twin_calls("/api/preflight/twin/destroy")) != 1:
            iso6_leaks += 1
            fails.append(f"ISO-6 twin leaked when {stage} failed")

    # ── ISO-3: concurrency — one SHARED twin client, many pipelines at once.
    #    A shared backend is the realistic case: the id space must stay unique and
    #    every twin must still be torn down with no cross-run bleed.
    shared = _RecordingBackend()

    def _run_shared(seed: int) -> None:
        rng = random.Random(20_000 + seed)
        run_preflight(f"add vlan {rng.randint(1, 4094)} to leaf-{seed}",
                      backend=shared, lab=rng.choice(LABS),
                      source="nl_intent", operator="conc")

    with ThreadPoolExecutor(max_workers=16) as ex:
        list(ex.map(_run_shared, range(256)))

    conc_spawn = len(shared._twin_calls("/api/preflight/twin/spawn"))
    conc_destroy = len(shared._twin_calls("/api/preflight/twin/destroy"))
    shared_ids = shared.spawned

    if conc_spawn != conc_destroy:
        fails.append(f"ISO-3 concurrent leak: {conc_spawn} spawn / {conc_destroy} destroy")
    if len(set(shared_ids)) != len(shared_ids):
        dupes = len(shared_ids) - len(set(shared_ids))
        fails.append(f"ISO-3 {dupes} duplicate twin_id(s) across concurrent runs")
    # every apply/destroy on the shared client referenced a real, spawned twin_id
    known = set(shared_ids)
    for b in shared._twin_calls("/api/preflight/twin/apply") + \
            shared._twin_calls("/api/preflight/twin/destroy"):
        if b.get("twin_id") not in known:
            fails.append(f"ISO-3 op referenced unknown twin_id {b.get('twin_id')!r}")
            break

    # ── report ──────────────────────────────────────────────────────────
    print(json.dumps({
        "runs": n,
        "ISO-1_spawn_eq_destroy": f"{total_spawn} == {total_destroy}",
        "ISO-3_concurrent": f"{conc_spawn} spawn / {conc_destroy} destroy, "
                            f"{len(set(shared_ids))} unique ids",
        "ISO-6_failure_paths_checked": iso6_checked,
        "ISO-6_leaks_on_failure": iso6_leaks,
    }, indent=2))

    if total_spawn != total_destroy:
        fails.append(f"ISO-1 aggregate leak: {total_spawn} spawn / {total_destroy} destroy")

    if fails:
        print("\n=== TWIN SAFETY + ISOLATION: FAIL ===")
        for f in fails[:25]:
            print("  -", f)
        return 1
    print(f"\n=== TWIN SAFETY + ISOLATION: PASS "
          f"({n} runs, 6 invariants, +concurrency +failure-path) ===")
    return 0


def main() -> int:
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
    return run(n)


if __name__ == "__main__":
    sys.exit(main())
