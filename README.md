<p align="center"><img src="docs/assets/hero.svg" alt="AEGIS — architecture" width="100%"></p>

# AEGIS

## 📖 Live documentation

[![AEGIS — live documentation](docs/assets/preview.png)](https://gesh75.github.io/aegis/)

> 🌐 **Live:** <https://gesh75.github.io/aegis/> — an animated single-page guide: architecture diagrams, data flow, tech stack, and quickstart.
>
> 🗂️ Part of the **[gesh75 documentation hub](https://gesh75.github.io/)** — all my network & AI engineering project docs in one place.


> **Air-gapped Evidence-Grade Inspection System** — preflight network changes against a
> *real* digital twin, entirely inside your perimeter. No cloud. No data egress. Ever.

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![tests](https://github.com/gesh75/aegis/actions/workflows/test.yml/badge.svg)](https://github.com/gesh75/aegis/actions/workflows/test.yml)
[![python](https://img.shields.io/badge/python-3.10%2B-3776ab.svg)](#)
[![egress](https://img.shields.io/badge/egress-none-2ea44f.svg)](#)
[![status](https://img.shields.io/badge/status-Phase_2-8a5cf6.svg)](docs/PHASES.md)

The air-gapped, self-hosted answer to Forward Predict / NetPilot: those are
cloud-by-architecture, so regulated networks that legally cannot send topology/config
off-prem are locked out of them. AEGIS runs the same **change → twin → validate → evidence**
loop on a self-hosted LLM + containerlab, and emits a tamper-evident, framework-mapped,
examiner-ready evidence bundle.

![AEGIS architecture](docs/architecture.svg)

## Demo

[![AEGIS PreFlight — full feature tour](docs/video_poster.png)](docs/aegis_feature_tour_andrew.mp4)

▶ **[Watch the 3-minute feature tour](docs/aegis_feature_tour_andrew.mp4)** (narrated) — every stage
on the live PreFlight UI: intent → digital twin → grounded config → PCI/SOC 2/NIST → sealed evidence →
offline Ed25519 verify → the **BLOCKED** guardrail → config-import → live mode.

Shorter cuts: **[64-second overview](docs/overview_video.mp4)** (silent, captioned) ·
**[narrated overview](docs/overview_video_narrated.mp4)** · **[real-product demo](docs/demo_video_narrated.mp4)**

<!-- INLINE PLAYER (optional, after first push): create a GitHub Release, drag
     docs/overview_video.mp4 into it, copy the https://github.com/gesh75/aegis/assets/…
     URL GitHub generates, and paste it here as a bare line — GitHub renders a video player. -->

## How it works

```
intent | paste-config ─▶ guard ─▶ generate (LLM) ─▶ batfish ─▶ spawn twin ─▶ apply+converge
                     ─▶ diff ─▶ compliance ─▶ risk tier ─▶ rollback ─▶ verdict ─▶ evidence bundle
```

Only `generate` touches an LLM — and the **config-import** path skips even that. Every step
after the proposal is **deterministic verification** (the "guarded agentic" pattern). That is
what makes the evidence auditable: the LLM proposes, the pipeline verifies, a human
authorizes, and the sealed bundle proves nothing left the perimeter.

## Why it's different

| | Forward Predict | NetPilot | **AEGIS** |
|---|---|---|---|
| Twin | math model | cloud emulation | **real on-host emulation (containerlab)** |
| Hosting | SaaS | cloud | **on-prem / air-gapped** |
| LLM | cloud | cloud | **self-hosted (zero egress)** |
| Output | report | — | **sealed, PCI/SOC2/NIST-mapped evidence + PDF** |

## 🏛️ Architecture

Everything runs inside an **air-gapped perimeter**: the operator submits a change, a
self-hosted Qwen3 LLM proposes config, a throwaway containerlab twin verifies it, and an
auditor consumes the sealed PDF — no actor or line ever reaches outside the wall.

```mermaid
flowchart LR
    OP([Operator - change author]):::actor
    APP([Approver - grants token]):::actor
    AUD([Auditor - examiner]):::actor

    subgraph PERIM["Air-gapped perimeter - egress none"]
        direction LR
        AEGIS{{"AEGIS - preflight and evidence engine"}}:::core
        QWEN[/"Self-hosted Qwen3 - only AI dependency"/]:::ai
        TWIN[("containerlab twin - multi-vendor routers")]:::twin
        DCN["DCN_Network_Tool 5757 - batfish, nornir, pyats"]:::svc
    end

    PROD[("Production devices - approval-gated push")]:::prod

    OP -->|"intent or config"| AEGIS
    APP -->|approval token| AEGIS
    AEGIS -->|generate_config| QWEN
    AEGIS -->|"spawn, apply, converge"| TWIN
    AEGIS -.->|live tier| DCN
    AEGIS -->|sealed PDF bundle| AUD
    AEGIS -.->|gated dry-run connector| PROD

    classDef actor fill:#475569,stroke:#94a3b8,color:#fff
    classDef core fill:#0d9488,stroke:#5eead4,color:#fff
    classDef ai fill:#7c3aed,stroke:#a78bfa,color:#fff
    classDef twin fill:#059669,stroke:#34d399,color:#fff
    classDef svc fill:#0ea5e9,stroke:#38bdf8,color:#fff
    classDef prod fill:#c0392b,stroke:#fb7185,color:#fff
    class PERIM core
```

📐 **Full architecture** — system context, container/component map, primary sequence, data
flow, the `Backend` Protocol class map, and the verdict/promotion-gate decision tree — lives in
**[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)**.

## Run the demo (community / sim tier — fully offline)

```bash
docker compose up                 # then open http://localhost:8088/preflight
# or, without Docker:
pip install -r requirements.txt
python -m aegis.serve             # from the directory ABOVE aegis/
```

Type a change (or paste a config), Run PreFlight, watch the verdict + sealed evidence
bundle, and download the examiner-ready PDF. The PDF is a rendering of a self-consistent
bundle — before handing it to an examiner, verify the detached Ed25519 receipt
(`POST /api/seal/verify`) against the pinned key. See [`docs/EVIDENCE.md`](docs/EVIDENCE.md).
Live mode (real Qwen3 + containerlab twin) ships in the integrated air-gapped product —
see [`docs/GO_LIVE.md`](docs/GO_LIVE.md).

### Air-gapped install (zero egress)

```bash
docker compose build && docker save aegis:local -o aegis-local.tar   # online, once
# carry aegis-local.tar across the air gap on signed media, then:
docker load -i aegis-local.tar
docker compose -f docker-compose.yml -f docker-compose.airgap.yml up  # network_mode: none
```

## Test — 6 suites, 0 violations

```bash
pip install -r requirements.txt
python -m aegis.tests.stress_test 25000      # pipeline invariants (8 invariants, adversarial)
python -m aegis.tests.contract_test          # HttpBackend parsers vs real :5757 shapes
python -m aegis.tests.pdf_test               # evidence PDF validity
python -m aegis.tests.promote_test           # Phase 2 approval-gate safety
```

| Suite | Scale | Result |
|---|---|---|
| pipeline invariants | 25,000 runs | ✅ PASS |
| HttpBackend contract | real API shapes | ✅ PASS |
| evidence PDF | 1,500 bundles | ✅ PASS |
| promotion gate | 6,000 bundles | ✅ PASS |
| Flask test-client | 10 tests | ✅ PASS |
| twin safety + mgmt isolation | 8,000 ops | ✅ PASS |

## Layout

```
core/orchestrator/   deterministic pipeline · guards · rollback
core/backends/       pluggable: simulator (CI) | http (live :5757)
core/promote/        Phase 2 approval gate + connectors (dry-run default)
evidence/            bundler · sha256 integrity · detached Ed25519 seal · PDF · JSON schema
ui/                  self-contained PreFlight dashboard
serve.py             standalone community server (sim tier)
docs/                PHASES.md · GO_LIVE.md · EVIDENCE.md · architecture.svg
```

## Project history & roadmap

Every phase — research → positioning → scaffold → live adapters → twin endpoints → UI →
evidence PDF → config-import → mgmt isolation → packaging → Phase 2 promotion gate — is
logged in [`docs/PHASES.md`](docs/PHASES.md). Changelog: [`CHANGELOG.md`](CHANGELOG.md).

## License

Apache-2.0 (see [LICENSE](LICENSE)). The community core is open; live production-push
connectors, RBAC, and hosted multi-tenant compute are the commercial tier.
