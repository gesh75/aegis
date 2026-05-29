# AEGIS Phase-0 Stress Test Results

**Date:** 2026-05-28 · **Build:** `aegis 0.1.0-phase0` · **Python 3.10.12**
**Backend under test:** `SimulatorBackend` (in-process, deterministic, failure-injecting)
**Command:** `python3 -m aegis.tests.stress_test 25000`

> The simulator models the *behaviour* of the real stack (Qwen3 config-gen → Batfish →
> containerlab convergence → Nornir diff) so the **identical deterministic pipeline** that
> will run air-gapped against `:5757` is exercised here with no external dependencies. The
> simulator is the contract the `HttpBackend` adapters must satisfy in Phase 0.

## Headline

**PASS** — 25,000 randomized + adversarial preflight runs and 2,000 concurrent runs, with
**zero** invariant violations. Wall time 7.95 s (~10,300 runs/s, single core).

## Invariants checked (all held)

| ID | Invariant | Result |
|---|---|---|
| INV-1 | Every evidence bundle validates against `evidence_bundle.schema.json` | ✅ 0 schema failures / 25,000 |
| INV-2 | Every integrity `sha256` re-computes (tamper-evidence works) | ✅ 0 hash failures |
| INV-3 | Determinism — same intent ⇒ identical bundle (minus run_id/timestamp) | ✅ 200/200 identical |
| INV-4 | **Safety** — a Batfish error / dropped BGP session / non-converged twin is **never** `ship_ready` | ✅ 0 unsafe ships |
| INV-5 | **Approval gate** — every high-risk run without an approver is gated, not shipped | ✅ 0 ungated high-risk ships |
| INV-6 | `integrity.egress` is always `"none"` | ✅ 25,000/25,000 |
| INV-7 | No twin leaks (every spawned throwaway twin is torn down) | ✅ leak = 0 |
| INV-8 | Guard rejects empty / oversized / prompt-injection intents pre-twin | ✅ 1,624 rejected before any twin spawn |

## Verdict distribution (25,000 runs)

| Decision | Count | Share |
|---|---:|---:|
| `ship_ready` | 11,043 | 44.2% |
| `blocked` | 6,374 | 25.5% |
| `needs_approval` | 5,959 | 23.8% |
| guard-rejected (pre-twin) | 1,624 | 6.5% |

This spread matters: the blocked + needs_approval + rejected buckets (≈56%) confirm the
dangerous-path logic is actually *exercised*, not merely absent. The safety and gate
invariants held across all 13,957 of those non-trivial decisions.

## Performance (per-run latency, simulator backend)

| Metric | Value |
|---|---|
| p50 | 0.10 ms |
| p95 | 0.13 ms |
| p99 | 0.17 ms |
| max | 1.65 ms |
| mean | 0.10 ms |
| throughput | ~10,300 runs/s (1 core) |

These are *orchestrator-overhead* numbers — the deterministic glue costs microseconds. In
production the wall time is dominated by the real twin converging (the simulator returns a
modeled 1.2–6.5 s `convergence_sec`); the orchestrator never becomes the bottleneck.

## Concurrency

2,000 runs across an 8-worker thread pool: **0 failures**. Every bundle still schema-valid
and integrity-verified under concurrent execution — no shared-state corruption.

## Worked examples (saved bundles)

**1. Adversarial — `add vlan 40 with plaintext bgp authentication-key abc123`**
(`tests/sample_bundles/blocked_plaintext_key.json`)
```
verdict      : blocked — "static analysis found 6 error(s)"
risk_tier    : high
batfish      : 6 errors — "plaintext BGP auth-key (PCI 8.3.1 fail)" + missing export policy
PCI controls : 1.2.1 → fail, 8.3.1 → fail
```
The pipeline catches a plaintext secret the LLM was coaxed into emitting, blocks the change
before the twin verdict, and the failure is auto-mapped to the exact PCI controls — the
audit story working end to end.

**2. Clean — `add static route 10.5.0.0/16 via edge-1`** (approver supplied)
(`tests/sample_bundles/clean_route_add.json`)
```
verdict   : ship_ready — "medium-risk change verified in twin, no regressions"
risk_tier : medium
```

## What this does and does not prove

**Proven:** the deterministic orchestrator, schema, integrity-sealing, risk tiering,
approval gate, rollback emission, and compliance mapping are correct, stable, leak-free, and
concurrency-safe across a large adversarial sweep. The "guarded agentic" boundary holds —
no AI output ever reaches a `ship_ready` verdict without passing the deterministic gates.

**Not yet proven (Phase 0 live work):** the three `HttpBackend` methods that map your real
`:5757` responses into these types, and a real containerlab convergence timing. The
simulator defines the exact contract those must meet; swapping it for `HttpBackend` is the
only remaining step to run this against the live fabric inside the air gap.

## Reproduce

```bash
cd <repo-root-containing aegis/>
pip install -r aegis/requirements.txt      # jsonschema only
python3 -m aegis.tests.stress_test 25000    # exit 0 = PASS, 1 = FAIL (CI-ready)
python3 -m aegis.tests.contract_test        # HttpBackend parsers vs real :5757 shapes
```

## Related: twin write-endpoint stress (Phase 0T)

The three net-new write endpoints (`/api/preflight/twin/{spawn,apply,destroy}`) live in
`04_Scripts_Tools/DCN_Network_Tool/src/preflight_twin.py` and have their own safety stress:

```bash
python3 src/tests/test_preflight_twin.py 20000
```

**Result: PASS** over 20,000 randomized + adversarial ops (~15k issued commands):
0 production-container hits (ISO-1 prod isolation), 0 injection tokens reaching a command
(ISO-3/6), 0 non-arg-list commands, 0 twin leaks (ISO-5), 0 concurrency errors across 60
parallel spawn→apply→destroy cycles. Bad labs rejected (ISO-2), over-limit spawns 429'd
(ISO-4), non-twin destroys refused (403).
