<p align="center"><img src="assets/hero.svg" alt="AEGIS — architecture" width="100%"></p>

# 🏛️ AEGIS — Architecture

**AEGIS** (Air-gapped Evidence-Grade Inspection System) is a self-hosted Python tool that
preflights network changes against a *real* containerlab digital twin entirely inside the
perimeter, then emits a tamper-evident, framework-mapped, examiner-ready evidence bundle.

It runs a **guarded-agentic** loop: a self-hosted LLM proposes config from a natural-language
intent (or the operator pastes config and skips the LLM), and every step afterward — static
analysis, twin spawn/converge, diff, compliance mapping, risk tiering, rollback, verdict — is
**deterministic verification**. A pluggable `Backend` Protocol lets the identical pipeline run
in an in-process simulator (CI / community tier) or against an in-perimeter HTTP stack (live
tier); a Phase 2 promotion gate can push an approved, sealed bundle to production through a
dry-run-by-default connector.

> **Design invariant:** only `generate_config` touches an LLM. Everything after it verifies.
> No line ever crosses the air-gap perimeter outward — only a sealed evidence badge leaves.

---

## Table of Contents

1. [System Context](#1-system-context)
2. [Container & Component Map](#2-container--component-map)
3. [Primary Flow (sequence)](#3-primary-flow-sequence)
4. [Data Flow Pipeline](#4-data-flow-pipeline)
5. [Backend Protocol (class map)](#5-backend-protocol-class-map)
6. [Verdict & Promotion-Gate Decision Tree](#6-verdict--promotion-gate-decision-tree)
7. [Tech Stack](#7-tech-stack)

---

## 1. System Context

Everything sits inside an **air-gapped perimeter**. The operator submits a change through the
PreFlight UI; a self-hosted Qwen3 LLM proposes config; a throwaway containerlab twin verifies
it; an auditor consumes the sealed PDF. No actor or line reaches outside the wall.

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

---

## 2. Container & Component Map

The codebase splits into four colored layers: the **orchestrator** drives the loop, the
**backends** abstract where work runs, **evidence** seals and renders the output, and
**promote** gates a verified bundle toward production. `serve.py` + the HTML UI expose the
community sim tier.

```mermaid
flowchart TB
    UI["serve.py and ui preflight_screen.html - Flask sim-tier server"]:::edge

    subgraph ORCH["core/orchestrator - deterministic engine"]
        direction LR
        PIPE["pipeline.py - run_preflight"]:::core
        GUARD["guards.py - precheck, risk_tier, approval"]:::core
        ROLL["rollback.py - build_rollback_plan"]:::core
    end

    subgraph BACK["core/backends - pluggable Protocol"]
        direction LR
        BASE["base.py - Backend Protocol and TypedDicts"]:::proto
        SIM["simulator.py - seeded, zero-dep"]:::svc
        HTTP["http_backend.py - 5757 and Qwen3"]:::svc
    end

    subgraph EVID["evidence - seal and render"]
        direction LR
        BUND["bundler.py - sha256 seal, egress none"]:::data
        COMP["compliance.py - PCI, SOC2, NIST crosswalk"]:::accent
        PDF["pdf.py - examiner-ready PDF"]:::accent
        SCHEMA["schema - evidence_bundle.schema.json"]:::data
    end

    subgraph PROM["core/promote - Phase 2 gate"]
        direction LR
        GATE["gate.py - G1-G4 rules"]:::accent
        PROMO["promote.py - sealed promotion record"]:::accent
        CONN["connectors.py - DryRun default, live inert"]:::edge
    end

    UI --> PIPE
    PIPE --> GUARD
    PIPE --> BASE
    BASE --> SIM
    BASE --> HTTP
    PIPE --> COMP
    PIPE --> ROLL
    PIPE --> BUND
    BUND --> SCHEMA
    BUND --> PDF
    BUND --> GATE
    GATE --> PROMO
    PROMO --> CONN

    classDef edge fill:#475569,stroke:#94a3b8,color:#fff
    classDef core fill:#0d9488,stroke:#5eead4,color:#fff
    classDef proto fill:#7c3aed,stroke:#a78bfa,color:#fff
    classDef svc fill:#0ea5e9,stroke:#38bdf8,color:#fff
    classDef data fill:#059669,stroke:#34d399,color:#fff
    classDef accent fill:#d97706,stroke:#fbbf24,color:#fff
```

---

## 3. Primary Flow (sequence)

One end-to-end PreFlight run: the UI POSTs an intent, the guard layer prechecks it before any
twin resources are spent, the backend proposes and verifies the change against a throwaway
twin, and the bundler seals the result. The twin is **always** torn down in a `finally` block.

```mermaid
sequenceDiagram
    autonumber
    actor Op as Operator
    participant Srv as serve.py
    participant Pipe as run_preflight
    participant G as guards
    participant B as Backend
    participant Ev as bundler

    Op->>Srv: POST /api/preflight/run intent, lab, frameworks
    Srv->>Pipe: run_preflight SimulatorBackend
    Pipe->>G: precheck_intent intent
    alt unsafe input
        G-->>Srv: PreflightError to HTTP 400
    else valid
        Pipe->>B: generate_config - LLM, only AI step
        Pipe->>B: batfish_check - static analysis
        Pipe->>B: spawn_twin and apply_and_converge
        Pipe->>B: state_diff - routes and sessions delta
        Pipe->>G: risk_tier and approval_required
        Pipe->>Pipe: map_controls, rollback, verdict
        Pipe->>Ev: build_bundle to sha256 seal, egress none
        Note over Pipe,B: finally teardown_twin always
        Ev-->>Srv: sealed JSON bundle
        Srv-->>Op: bundle plus optional PDF or promotion
    end
```

---

## 4. Data Flow Pipeline

The change flows left-to-right through eleven deterministic stages. Only the **generate** step
(violet) is AI; the **batfish** gate (crimson) can block, and the final **seal** (amber) pins
egress to none. Everything between is teal verification.

```mermaid
flowchart LR
    IN(["intent or pasted config"]):::in
    GU["guard - precheck"]:::ver
    GEN["generate - LLM propose"]:::ai
    BF{"batfish - static check"}:::gate
    TWIN["spawn twin - apply and converge"]:::ver
    DIFF["state diff - blast radius"]:::ver
    RISK["risk tier - and approval"]:::ver
    MAP["compliance - crosswalk"]:::accent
    RB["rollback - plan"]:::ver
    VERD{verdict}:::gate
    SEAL[("sealed bundle - sha256, egress none")]:::seal

    IN --> GU --> GEN --> BF
    BF -->|errors| VERD
    BF -->|clean| TWIN --> DIFF --> RISK --> MAP --> RB --> VERD
    VERD --> SEAL

    classDef in fill:#475569,stroke:#94a3b8,color:#fff
    classDef ai fill:#7c3aed,stroke:#a78bfa,color:#fff
    classDef ver fill:#0d9488,stroke:#5eead4,color:#fff
    classDef gate fill:#c0392b,stroke:#fb7185,color:#fff
    classDef accent fill:#d97706,stroke:#fbbf24,color:#fff
    classDef seal fill:#059669,stroke:#34d399,color:#fff
```

---

## 5. Backend Protocol (class map)

The `Backend` Protocol is the **guarded-agentic boundary**: it declares six operations, but
only `generate_config` touches an LLM — the rest are verification. Two implementations satisfy
it identically, so the same pipeline runs in CI and against the live :5757 stack.

```mermaid
classDiagram
    class Backend {
        <<Protocol>>
        +generate_config(intent) configs
        +batfish_check(configs) findings
        +spawn_twin(lab) twin
        +apply_and_converge(twin) bgp
        +state_diff(twin) delta
        +teardown_twin(twin) void
    }
    class SimulatorBackend {
        +seeded off intent
        +failure injection rates
        +zero external deps
    }
    class HttpBackend {
        +DCN_Network_Tool :5757
        +self-hosted Qwen3 runner
        +pure parse_* functions
    }
    class BundleShapes {
        <<TypedDict>>
        +Change, Twin, Validation
        +Compliance, Rollback, Verdict
    }
    Backend <|.. SimulatorBackend : implements
    Backend <|.. HttpBackend : implements
    Backend ..> BundleShapes : produces
```

---

## 6. Verdict & Promotion-Gate Decision Tree

The verdict resolves to one of three outcomes from batfish errors, twin convergence, BGP
regression, and approval state. A `ship_ready` bundle may pass through the Phase 2 gate, whose
four rules (G1–G4) decide whether the change reaches a connector — dry-run by default.

```mermaid
stateDiagram-v2
    [*] --> Verdict
    Verdict --> Blocked: batfish errors or BGP regression
    Verdict --> NeedsApproval: medium or high risk
    Verdict --> ShipReady: clean and low risk

    Blocked --> [*]
    NeedsApproval --> Gate: approver + token
    ShipReady --> Gate

    state Gate {
        [*] --> G1
        G1 --> G2: integrity re-verified
        G2 --> G3: verdict promotable
        G3 --> G4: approval token valid
        G4 --> DryRun: safe default
        G4 --> Live: explicit opt-in
    }
    Gate --> Record: sealed promotion record
    Record --> [*]
```

---

## 7. Tech Stack

| Layer | Technologies |
|---|---|
| **Language** | Python 3.10+ (pure stdlib core, backend-agnostic via `typing.Protocol`) |
| **Orchestration** | Deterministic pipeline · dataclasses · frozen dataclasses (promote) |
| **AI (only step)** | Self-hosted Qwen3, OpenAI-compatible `/v1/chat/completions` |
| **Twin** | containerlab + Docker (srlinux / ceos / frr / junos / ios / panos) |
| **Static analysis** | Batfish-style check via DCN_Network_Tool `:5757` |
| **Evidence** | `hashlib` sha256 seal · canonical JSON · JSON Schema draft-07 · `jsonschema` 3.2.0 |
| **PDF** | `reportlab` (A4 platypus tables) — air-gap safe |
| **Server / UI** | Flask 3.x (loopback-bound, strict CSP, 2 MB cap) · single inline-asset HTML |
| **Networking** | `urllib` only — no cloud, no external DNS |
| **CI / tests** | 6 invariant + contract suites (`stress`, `promote`, `twin`, `pdf`, `contract`, `api`) |

---

<p align="center"><sub>AEGIS · the LLM proposes inside the wall · the twin verifies · only a sealed badge leaves</sub></p>
