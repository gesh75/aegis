# AEGIS: strategy, gap analysis and roadmap (October 2026)

**Scope.** This covers the `gesh75/aegis` repository on branch
`claude/repo-audit-competitive-analysis-5psds9` and its fit as a **network-team security
control**.

**Method.** Every finding below was checked against the code.

- The earlier session's findings A1–A10 were re-verified, not copied.
- The test suites were run locally: 13 of 15 against the real libraries. Two Flask-dependent
  suites ran through a local Flask stand-in, and CI runs them against real Flask.
- Competitor facts come from vendor sources gathered on 2026-10-22, with a URL for each.
  Confidence labels follow your convention: **Confirmed / Inferred / Unverified / Unknown**.

**Out of scope.** Argus is not reachable from this session. The earlier session's R1–R8 for
Argus are carried forward **unverified** in §9.

---

## 1. Executive summary

**AEGIS can be credible as a network-change security control, but only now.**

Before this branch, three controls *looked* enforced and were not:

- the promotion gate trusted a self-hashed bundle;
- approvals were neither single-use nor tied to a person;
- the evidence claimed "rollback tested in twin" for a rollback that was never run.

This branch closes those three. It also makes the compliance checks correct for Junos,
which they were not: every Junos BGP peer was invisible to them. It moves every proof suite
into CI and adds a fail-closed production mode.

**Where AEGIS stands against the market (§3).** Forward, IP Fabric and NetBrain are
mature network assurance platforms. AEGIS cannot out-model them, and it should not try.

AEGIS's original pitch, "the air-gapped answer to cloud-only Forward/NetPilot", **no longer
holds by itself**. Forward Enterprise documents on-prem deployment (whether Predict has
on-prem parity is **Unknown**), Forward Predict went GA on 2026-09-29, and NetPilot
*claims* an air-gapped option (vendor claim only; its own pricing page conflicts).

The defensible niche is the **independent evidence and governance layer** for network
change, including changes proposed by AI agents. It combines:

- signed, **offline-verifiable** evidence (no vendor portal needed);
- separation of duties and single-use approvals;
- a record of which AI model proposed a change and that its autonomy was bounded;
- a per-change, multi-framework crosswalk;
- an open-source core.

No competitor source shows offline-verifiable evidence of this kind. That evidence maps to
the change-control clauses auditors actually test: NIST CM-3/CM-4, PCI DSS 6.5.1–6.5.2,
HITRUST 09.b, and DORA Art. 17 as a benchmark.

**The biggest product gap is coverage, not security.**

- Only BGP session counts are verified in the twin. There is no reachability, ACL or firewall
  policy analysis, which is where most network security risk lives.
- There is no post-change verification against production.
- There is no ServiceNow, NetBox or Batfish-native integration yet.

**Recommendation.** Pilot AEGIS in **production mode** as a *pre-change evidence gate*
attached to ServiceNow normal changes for a single domain: DC fabric BGP/EVPN on Junos.
Keep promotion on the dry-run connector. Fund three roadmap items before calling it a
control of record:

1. Batfish reachability and ACL intent checks;
2. a ServiceNow change-record integration;
3. a post-change "did production match the twin" verification.

---

## 2. What changed on this branch (verified, tested)

| ID | Finding (earlier session) | Verified? | Status on this branch | Evidence |
|---|---|---|---|---|
| A1 | Gate trusts the self-hashed bundle; a forged `ship_ready` passes; exports render forged seals | **Confirmed** (`gate.py` G1 = `verify()` only; `pdf.py` printed any `seal` blob) | **Fixed.** New G0 verifies Ed25519 at the gate (server always). Exports return 422 on an invalid seal and print an `authenticity` line. | `core/promote/gate.py`, `serve.py:_authenticity`, `tests/hardening_test.py` H1/H2 |
| A2 | Approver is free text; the shared API key mints for anyone; no SoD | **Confirmed** | **Fixed (bridge).** SoD (approver ≠ operator) at gate and mint. `AEGIS_APPROVER_KEYS` per-person credential, and identity comes from the credential. SSO is still roadmap. | `core/promote/approvers.py`, H3/H7 |
| A3 | Fail-open defaults (no API key = open; no HMAC = any string approves) | **Confirmed** | **Fixed for production.** `AEGIS_MODE=production` refuses to start unconfigured and denies `asserted-unverified`. Community stays demo-friendly by design. | `core/runtime.py`, H6 |
| A4 | Token nonce minted but never tracked → replay for up to 7 days | **Confirmed** (`tokens.py` never stores `n`) | **Fixed.** Single-use claim in the ledger before the first push, which survives restart. | `core/promote/promote.py`, H4 |
| A5 | No persistent audit trail | **Confirmed** | **Fixed.** Hash-chained JSONL ledger, `/api/ledger/verify`, offline `aegis.verify --ledger`. | `evidence/ledger.py`, H5/H10 |
| A6 | Container unreachable (127.0.0.1 inside the container), root, dev server | **Confirmed by reading.** The container job now proves the fix. | **Fixed.** `AEGIS_HOST=0.0.0.0` in the image, gunicorn, UID 10001, healthcheck, loopback publish, read-only FS. The air-gap overlay port conflict is also fixed. | `Dockerfile`, `docker-compose*.yml`, CI `container` job |
| A7 | No SAST/SCA in CI; 5 proof suites local-only; jsonschema 2019 pin | **Confirmed** | **Fixed.** 15 suites in CI, Bandit (HIGH gates), pip-audit, Dependabot, dev/runtime split. | `.github/workflows/test.yml` |
| A8 | Keys in env; no KMS/rotation; PIV signer planned | **Confirmed** | **Open (roadmap P2).** Documented rotation procedure in `SECURITY.md`. | `docs/PIV_HARDWARE_SIGNER_PLAN.md` |
| A9 | "Plaintext secret" = demo string match | **Confirmed** | **Fixed.** Vendor-aware detection plus redaction in exports. | `evidence/secrets.py` |
| A10 | CSP `unsafe-inline`, raw exception text, no SECURITY.md | **Confirmed** | **Fixed.** `script-src 'self'` (UI script externalized; verified in headless Chromium with zero CSP violations). Production hides internals and `SECURITY.md` is added. `style-src 'unsafe-inline'` remains, which is low risk. | `serve.py`, `ui/preflight.js` |

### New findings from this audit (not in the earlier report)

| ID | Finding | Severity | Status |
|---|---|---|---|
| N1 | `rollback.tested_in_twin` was set to **forward convergence**, so every converged run claimed a tested rollback. `cab.py` already said the opposite, so the sealed evidence contradicted itself. | High (false assurance) | **Fixed.** It is now `false`, with `verification: plan-only`. |
| N2 | **Junos invisible to compliance.** The DISA peer regex was Cisco-only (`neighbor X remote-as`), so every Junos BGP peer was missed and hierarchical configs were not parsed. For a Juniper shop, the DISA rows were wrong in both directions. | High (for One Call) | **Fixed.** `{}`→`set` normalizer (inactive dropped), plus neighbor, group, global and routing-instance auth, with 9 Junos self-tests. |
| N3 | **MD5 counted as FIPS 198-1** (CISC-RT-000050 accepted `message-digest` / `authentication mode`). | Medium (false PASS) | **Fixed.** Only HMAC-SHA, AES-CMAC or TCP-AO pass. |
| N4 | The UI **hard-coded `approver: "noc-lead"`**, so every demo run self-approved high-risk changes. Two UI lab options did not exist in the backend. | Medium | **Fixed.** |
| N5 | The rollback plan for real CLI printed `revert -> <same line>`, which re-applies the change. | Medium | **Fixed.** Vendor-aware (`no` in parent mode; Junos `delete` plus `commit confirmed` / `rollback 1`). |
| N6 | Secrets (including type 7, `$9$` and hashes) were printed verbatim into the examiner PDF. | Medium | **Fixed.** Redacted in the PDF. **Still present in the bundle JSON** (see §7, decision D3). |
| N7 | Bundle strings entered ReportLab markup unescaped: a 500 on `<`, and markup injection into the PDF. | Medium | **Fixed.** `_esc` everywhere. |
| N8 | OSCAL export used non-UUID ids and missed required AR fields, so GRC ingestion would reject it. | Low | **Improved** (RFC 4122, `import-ap`, `target`, `collected`). **Not yet validated against the NIST schema.** |
| N9 | **Every BGP neighbor add is BLOCK by default.** `classify_change` treats `remote-as` / `peer-as` (the *peer's* AS) as fabric identity, so the most common NetOps change can never be sealed or promoted. Measured: 0 of 1,000 "peer BGP" sim runs were sealable. | High (product) | **Default unchanged. An opt-in switch `AEGIS_PEER_AS_POLICY=hitl` ships (D1).** |
| N10 | Compliance hot path recomputed the normalized config about 23 times per run. | Low (perf) | **Fixed.** Memoized, 0.80 → 0.43 ms/run with 11 frameworks (about 1.9×). |

**Test evidence (Confirmed).**

- **Locally**, all 15 suites pass at CI scale: 25k stress, 6k promote, 8k twin, 1.5k PDF,
  101 compliance checks, 65 hardening checks, and the rest.
- **GitHub Actions run #71** (`workflow_dispatch` on this branch, commit `be97089`) was
  **green on all three jobs**:
  - `test` ran all 15 suites against real Flask 3 and Python 3.11.
  - `security`: Bandit found **0 high**, 1 medium (B310 `urlopen`, since fixed with an
    http(s) scheme pin) and 4 low. pip-audit reported **"No known vulnerabilities found"**.
  - `container`: the image built, gunicorn 23 listens on `0.0.0.0:8088` inside the
    container, it runs as UID 10001, and `/healthz`, `/api/preflight/run` and `/metrics`
    all returned 200.
- Runs **#72** (`workflow_dispatch`) and **#73** (the `pull_request` event for PR #32) on the
  final head `e1b4629` were green on all jobs. **PR #32 was merged to `main` on 2026-10-23**
  as `ff886ea`.
- CI notice: `actions/checkout` and `setup-python` pins target the deprecated Node 20.
  Dependabot has already pushed bump branches: checkout 7.0.1, setup-python 7.0.0, plus the pip
  bumps for bandit, cryptography, gunicorn, httpx and reportlab. Review them on their own CI.

---

## 3. Competitive landscape

Researched 2026-10-23 from vendor pages, press releases and trade press (sources in §3.8).

**How to read the confidence labels.** Most competitor material is vendor marketing.

- **Confirmed** means a vendor document or press release states it.
- **Inferred** means the claim is well established but no source was cited in this pass.
- **Unknown** means no source was found. Absence from a vendor's pages is **not** proof the
  capability is missing; ask in the RFP (§3.7).

### 3.1 Headline: "the air-gapped answer to cloud-only tools" no longer holds by itself

The README, the Pages site and the launch material all position AEGIS against Forward
Predict and NetPilot as "cloud-by-architecture". The 2026 evidence **contradicts** that
claim (**Conflicting**):

| Competitor | 2026 evidence | Confidence |
|---|---|---|
| **Forward** | Forward Enterprise "can be deployed on-premises or as a SaaS solution". The on-prem options are an OVA and a "Forward Cluster". **Forward Predict** became **generally available on 2026-09-29**. It runs BGP, OSPF, ACL, NAT and firewall changes against the mathematical twin and exposes them to AI agents over REST/MCP. | On-prem deployment: Confirmed (datasheet; the community FAQ is dated 2023). Predict GA: Confirmed. **Whether Predict and Forward AI run fully on-prem with no hosted LLM: Unknown.** |
| **NetPilot** | Offers an on-prem option "via Contact Sales" for "compliance, data-residency, or air-gapped requirements": a local LLM, a "signed offline bundle", "no outbound calls at runtime". | Vendor claim only (no independent source). Its own pricing page also lists cloud AI providers for self-hosted installs, which is **Conflicting**. |

**Implication.** Air-gap capability is becoming table stakes, not a moat. AEGIS's defensible
position is the **evidence and governance layer** described in §3.5, together with being
open source. The README and Pages copy are corrected in the same commit as this section.
The older launch posts, blog and video still carry the claim and are flagged for revision in §8.

### 3.2 Market map

| Product | Category | How it predicts or checks a change | Deployment | AI / agent features | Notable 2025–26 | Confidence |
|---|---|---|---|---|---|---|
| **Forward Enterprise + Predict** (Forward) | Network digital twin and assurance | **Mathematical model** of the network. Predict traces control-plane changes into the data plane and runs packet-path analysis on the predicted snapshot. | Enterprise: on-prem or SaaS (Confirmed). **Predict on-prem availability and parity: Unknown.** | Forward AI: agentic, multi-step plans reaching the twin and systems such as ServiceNow (announced 2026-01-29, GA Apr 2026). Predict exposed as MCP/REST tools. | Predict GA 2026-09-29, with beta customers in financial services (IG Group named) | Confirmed (vendor and press) |
| **IP Fabric** | Network assurance, discovered-state twin | Read-only discovery. Compares actual state with intended state, using "100+" built-in checks plus custom ones. | Appliance (on-prem) | MCP server built into appliances (v6.0+) | v8.1 (Sep 2026): application awareness and a cloud-native model. NetBox integration for continuous validation (May 2026). | Confirmed (vendor and newswire) |
| **NetBrain** | Network automation and assurance | Change runbooks tagged pre-change / post-change, with automatic before and after pairing. Codified "intents" for validation and drift. | Inferred commercial on-prem/SaaS (not sourced) | Planned "Change Agent" (natural language to governed runbook) is on the **Q4 2026 roadmap**, not shipping | ServiceNow and Jira integrations | Confirmed (vendor) |
| **Batfish** | Open-source config analysis | **Static** analysis of planned or current configs (no emulation) | Self-hosted container; Apache-2.0 | None | AWS-managed open source since 2022 (licensing deal). Batfish Enterprise status is Conflicting. | Confirmed (batfish.org, GeekWire) |
| **Juniper Apstra / Data Center Director** (HPE) | Intent-based DC automation | Generates config from intent, "pre-validates every change", and validates the live state continuously | Inferred on-prem | Inferred (Marvis/Mist integration, not sourced) | **HPE closed its acquisition of Juniper on 2025-07-02** | Confirmed (HPE, Juniper) |
| **Cisco Nexus Dashboard Insights** | DC assurance | **Pre-change analysis** against the latest snapshot (formerly Network Assurance Engine) plus delta analysis | On-prem appliance or cluster | Unknown | Documentation is ACI-focused; pre-change support for NDFC/NX-OS is unclear | Confirmed (Cisco docs) |
| **Arista ANTA (+ AVD)** | Open-source test framework | Post-state test catalog (pass/fail) on EOS | Self-hosted; Apache-2.0 | None | AVD `eos_validate_state` ANTA mode is in **preview** | Confirmed (Arista) |
| **Nokia EDA Digital Sandbox** | Automation platform with emulated twin | Containerized emulation of production; "merge to main" equals push to production | Kubernetes cluster (on-prem) | Unknown | Sandbox ships with EDA | Confirmed (Nokia docs) |
| **NetPilot** | AI-built emulation labs | An agent builds a mirror lab on real NOS containers (Cisco IOL, cRPD, cEOS, SR Linux, FRR, bring-your-own image), then snapshots before and after and diffs them | Cloud by default; on-prem on request | MCP server for Claude, Cursor or in-house agents | Free tier and 14-day trial. The "2-minute lab" claim is unverified. | Vendor claims only |
| **Tufin / AlgoSec / FireMon** | Network security policy management | Firewall policy modelling and change-risk analysis. FireMon says pre-change compliance validation is in its base platform. | Inferred on-prem and SaaS | Unknown | **Skybox shut down 2025-02-24; Tufin bought assets** and runs a migration offer. PeerSpot mid-2026: AlgoSec #1 (8.7), FireMon #3 (8.1), and all three are losing mindshare. | Confirmed (SecurityWeek, Ctech, PeerSpot); feature claims are vendor marketing |
| **Itential / Gluware** | Network automation and orchestration | Pre/post validation and rollback (Itential). Compliance and ServiceNow (Gluware). | Inferred commercial | Itential positions itself for the "agentic era" | Gartner Peer Insights lists both | Vendor and analyst-review claims |
| **NetBox Labs Assurance** | Source-of-truth drift detection | Compares discovered state with intended design in NetBox, and tracks drift history | Commercial add-on (NetBox Cloud or Enterprise) | Part of the June 2026 "Infrastructure Intelligence" platform | Open-source NetBox core; Assurance is paid | Confirmed (NetBox Labs) |

### 3.3 Capability matrix, part 1: assurance depth

Legend: ● Confirmed by a cited source · ◑ Inferred (well known, not cited here) ·
◐ Partial · ○ No (by product design) · ? Unknown, not found.

| Capability | **AEGIS today** | Forward | IP Fabric | NetBrain | Batfish | Apstra | Cisco NDI | Nokia EDA | NetPilot | Tufin / AlgoSec / FireMon |
|---|---|---|---|---|---|---|---|---|---|---|
| Pre-change verification | ◐ BGP session health in twin + config checks | ● Predict | ? (validates discovered state) | ● | ● (planned configs) | ● | ● (ACI) | ● | ● | ● (firewall policy) |
| Network-wide reachability / path analysis | ○ | ● | ◑ | ◑ | ◑ | ? | ◑ | ? | ◐ (in the lab) | ◑ |
| Firewall / ACL / NAT policy analysis | ○ | ● | ◑ | ? | ◑ | ? | ? | ? | ? | ● |
| Emulation on real NOS images | ◐ (containerlab design; live tier is outside this repo, community tier is a simulator) | ○ (mathematical model) | ○ (discovered model) | ? | ○ (static) | ? | ○ (snapshot model) | ● | ● | ○ |
| Post-change verification | ○ | ◑ | ● (continuous) | ● | ○ | ● (continuous) | ● (delta) | ? | ◐ (lab, not production) | ? |
| Continuous drift / compliance monitoring | ○ | ◑ | ● | ● | ○ | ● | ◑ | ● (event-driven) | ○ | ◑ |
| Multi-vendor depth | ◐ (6 vendor ids; compliance tuned for Cisco and Junos) | ◑ | ◑ | ◑ | ◑ | ◑ | ○ (Cisco) | ◐ | ● (5+ NOS, BYO) | ◑ |

### 3.4 Capability matrix, part 2: governance and evidence (where AEGIS competes)

| Capability | **AEGIS today** | Forward | IP Fabric | NetBrain | NetPilot | Tufin / AlgoSec / FireMon | NetBox Assurance |
|---|---|---|---|---|---|---|---|
| Signed, **offline-verifiable** evidence (public key + CLI, no vendor server) | ● (Ed25519 seal, `aegis.verify`) | ? | ? | ? | ? | ? | ? |
| Proposing AI model identity + autonomy bound sealed per change | ● | ? | ? | ? | ? | ○ | ○ |
| Approval gate with SoD, single-use, bound to config and inventory | ● | ? | ? | ◐ (Jira/ServiceNow approvals) | ? | ◐ (ITSM workflow, actions logged) | ○ |
| Hash-chained audit ledger + SIEM anchor | ● | ? | ? | ? | ? | ◐ ("logs every action") | ◐ (drift history) |
| Per-change compliance crosswalk (multi-framework) | ● (11 frameworks, labelled config-checked or process-mapped) | ◑ (compliance verification) | ◐ (best-practice checks) | ? | ? | ◑ (PCI and similar reports) | ○ |
| OSCAL output | ◐ (AR-shaped, not schema-validated) | ? | ? | ? | ? | ? | ? |
| ServiceNow integration | ○ (`change_ref` field only) | ● (Forward AI) | ? | ● | ? | ● (Tufin ITSM), ◐ (FireMon) | ? |
| NetBox integration | ○ | ● (`fwd-netbox`) | ● | ? | ? | ? | ● |
| MCP / agent tool surface | ○ (REST only) | ● | ● | ◐ (roadmap) | ● | ? | ? |
| Self-hosted LLM enforced (zero egress) | ● (loopback-only check) | ? | n/a | ? | ◐ (claimed on-prem; Conflicting) | n/a | n/a |
| Open source, inspectable gate logic | ● (Apache-2.0) | ○ | ○ | ○ | ○ (has a GitHub org; product is commercial) | ○ | ◐ (NetBox core only) |

### 3.5 Gaps and advantages

**Where AEGIS is behind**, ranked by impact for a network security team:

| # | Gap | Who does it | Impact | Fix |
|---|---|---|---|---|
| G1 | No reachability, ACL or firewall analysis | Forward Predict, Batfish, NSPM vendors | **Critical.** Most network security risk is segmentation and policy, not BGP session counts. | **In progress (2026-10-24):** intent engine on Batfish (`docs/INTENTS.md`) covering reachability allow/deny, BGP, undefined references and shadowed ACL lines, with a before/after differential. A real-engine CI job is added. Still open: firewall/NAT zone policies (PAN-OS, SRX) and F5. |
| G2 | No ServiceNow integration | NetBrain, Tufin, Forward AI | High. CAB evidence has to be attached by hand. | P3: attach the verdict and PDF to the CHG, and block CAB on `blocked` |
| G3 | No post-change verification or drift detection | IP Fabric, Apstra, NetBox Assurance, Cisco NDI | High. You prove the plan, not the outcome. | P4: snapshot production after the push and diff it against the twin |
| G4 | Twin fidelity unproven in this repo (community tier is a simulator) | NetPilot and Nokia EDA (real NOS); Forward (mathematical model at scale) | High. Credibility. | Pilot with cRPD/vJunos on the DC fabric lab and publish fidelity results |
| G5 | Firewall and load-balancer domains (PAN-OS, F5) | NSPM vendors | Medium | P4, a second domain. Or *consume* NSPM results as evidence instead of rebuilding them. |
| G6 | No NetBox source-of-truth | IP Fabric, Forward, NetBox Assurance | Medium. Roles are guessed from device names. | P3: NetBox roles and `inventory_rev` |
| G7 | No MCP tool surface | Forward, IP Fabric, NetPilot | Medium. Agents will call whatever exposes MCP. | Expose `preflight`, `verify` and `promote` as MCP tools behind the same gate |
| G8 | Support, scale and bus factor (one maintainer) | Every commercial vendor | Medium for a control of record | Internal ownership plus a RACI (§4.3); keep the open-source core |

**Where AEGIS is ahead**, the position to own:

| # | Advantage | Why it matters to One Call | Proof in the repo |
|---|---|---|---|
| V1 | **Evidence an auditor verifies alone**: a sealed bundle plus a public key plus an offline CLI | HITRUST, PCI and SOC 2 examiners get proof, not screenshots. No vendor portal is needed. | `core/seal`, `verify.py`, H10 tests |
| V2 | **Governance built into the gate**: SoD, single-use approval tokens, binding to config and inventory, fail-closed production mode | Maps directly to CM-3, CM-5, AC-5 and DORA Art. 17 segregation of duties | `core/promote/*`, H3/H4/H6/H7 |
| V3 | **AI accountability**: which model proposed the change, and that its autonomy was bounded, sealed per change | Every vendor is shipping agentic change (Forward AI, Predict MCP, NetBrain Change Agent, NetPilot). AEGIS can be the **independent guardrail and evidence layer** in front of any of them. | `core/llm/identity.py`, `core/risk/authority.py` |
| V4 | **Per-change multi-framework crosswalk** with honesty labels, plus OSCAL and CAB exports | One run produces PCI, HIPAA, NIST and CIS evidence rows | `evidence/frameworks/*` |
| V5 | **Open source, no licence cost, inspectable rules** | InfoSec can read the exact gate logic. There's no vendor-viability risk of the Skybox kind. | Apache-2.0 |
| V6 | **Vendor-neutral complement** | Batfish is integrated today (`core/intents/`, the oracle seam). Ingesting IP Fabric or Forward results as evidence inputs is **proposed, not built**: it would be a new `IntentOracle` implementation per vendor. | `core/intents/engine.py` (`IntentOracle` protocol) |

### 3.6 Market signals

| Signal | Evidence | So what for AEGIS |
|---|---|---|
| **Agentic change is shipping** | Forward AI (GA Apr 2026), Forward Predict MCP (GA 2026-09-29), IP Fabric MCP, NetPilot MCP, NetBrain Change Agent (roadmap Q4 2026) | The "bounded autonomy plus sealed evidence" problem AEGIS solves is now mainstream. The window to own the *independent verification layer* is roughly 12–18 months (Inferred). |
| **Consolidation and vendor-viability risk** | HPE closed Juniper (2025-07-02). Skybox shut down overnight (2025-02-24) and Tufin bought assets. PeerSpot shows NSPM mindshare falling. | Favour open formats (OSCAL, signed JSON) and an open-source core, so evidence outlives any vendor |
| **Regulators specify change control** | DORA RTS (EU) 2024/1774 Art. 17: documented change procedures, **approval segregated** from request and implementation, adequate testing, fall-back procedures | AEGIS maps 1:1 to these. One Call is US-based, so DORA is **not directly applicable** (Inferred). Use it as a benchmark for where HITRUST and PCI assessors are heading. |
| **Open-source verification is healthy** | Batfish is AWS-managed under Apache-2.0. A third party reports a v2026.08.27 release (Unverified). | Batfish is safe to embed for G1. Pin a release and vendor the container for air-gap. |

### 3.7 Recommendation and RFP questions

| Option | What | Cost | Coverage | Risk |
|---|---|---|---|---|
| **A (recommended for the pilot)** | AEGIS + Batfish (both Apache-2.0) as the pre-change evidence gate for the DC fabric | Engineering time only | BGP/EVPN + reachability/ACL (after G1) + governance and evidence | Single maintainer. Twin fidelity still to prove (G4). |
| **B** | A commercial assurance platform (Forward or IP Fabric) for depth, **with AEGIS on top** as the evidence and approval layer | Licence (Unknown; get quotes) + integration | Broadest | Two systems to run. Vendor lock-in for the model. |
| **C** | A commercial platform only | Licence | Broad assurance | Evidence and AI accountability stay vendor-controlled and unverifiable offline (§3.4 unknowns) |

**Questions to put to every vendor.** These fill the "?" cells honestly.

1. Can an auditor verify a change record **offline** with only a public key? What is the signature format?
2. Does the AI agent run on a **self-hosted model** with zero outbound calls? Which model is used, and is that recorded per change?
3. Does approval enforce **separation of duties**, and is an approval **single-use** and bound to the exact config?
4. Is there an **OSCAL** (or other open-format) export of change assessments?
5. Does Predict / pre-change analysis run in an **on-prem, air-gapped** deployment, and with what feature parity?
6. Is there a NetBox and ServiceNow integration, and are Junos and PAN-OS supported for ACL and firewall analysis?

### 3.8 Sources

- Forward: [Forward Predict GA (PR Newswire, 2026-09-29)](https://www.prnewswire.com/news-releases/forward-predict-is-now-generally-available-advancing-safer-agentic-netops-and-autonomous-networking-302892408.html) · [Predict launch (SiliconANGLE, 2026-05-20)](https://siliconangle.com/2026/05/20/forward-launches-predict-verify-network-changes-reach-production/) · [Network World on Predict](https://www.networkworld.com/article/4175696/forward-launches-predict-to-take-the-guesswork-out-of-network-changes.html) · [Forward agentic AI (Network World)](https://www.networkworld.com/article/4125111/forward-networks-launches-agentic-ai-system-built-on-network-digital-twin.html) · [Forward AI press release](https://www.forwardnetworks.com/blog/press-release/forward-networks-introduces-forward-ai-to-accelerate-network-operations-with-mathematical-certainty/) · [Datasheet: on-prem or SaaS](https://forwardnetworks.com/wp-content/uploads/2021/11/TwoPagerDatasheet-2021UpdateA-V03.pdf) · [Community FAQ: OVA and Forward Cluster](https://community.forwardnetworks.com/product-discussions-38/got-a-question-answers-to-forward-networks-faqs-250) · [fwd-netbox](https://github.com/forwardnetworks/fwd-netbox)
- IP Fabric: [v8.1, application-aware (GlobeNewswire, 2026-09-23)](https://www.globenewswire.com/news-release/2026/09/23/3367541/0/en/ip-fabric-expands-its-network-digital-twin-with-application-awareness-and-a-cloud-native-model.html) · [NetBox continuous validation (2026-05-13)](https://www.globenewswire.com/news-release/2026/05/13/3294068/0/en/ip-fabric-expands-netbox-integration-to-deliver-continuous-network-validation-for-enterprise-operations.html) · [MCP server in appliances](https://www.automateyournetwork.ca/uncategorized/netclaw-ip-fabric-network-assurance-meets-ai-powered-automation/)
- NetBrain: [Network change management](https://www.netbrain.com/solution/network-change-management/) · [Intent-based automation](https://www.netbrain.com/features/preventive-automation-intent-based/) · [Jira integration](https://www.netbrain.com/platform/network-automation-integrations/jira/)
- Batfish: [batfish.org](https://batfish.org/) · [GitHub](https://github.com/batfish/batfish) · [AWS–Intentionet deal (GeekWire)](https://www.geekwire.com/2022/amazon-web-services-inks-licensing-deal-with-seattle-startup-intentionet-developers-of-batfish/) · [rConfig guide (release dates; Unverified)](https://www.rconfig.com/batfish)
- Juniper / HPE: [HPE closes Juniper (2025-07)](https://www.hpe.com/us/en/newsroom/press-release/2025/07/hewlett-packard-enterprise-closes-acquisition-of-juniper-networks-to-offer-industry-leading-comprehensive-cloud-native-ai-driven-portfolio.html) · [Apstra Data Center Director](https://www.juniper.net/us/en/products/network-automation/apstra-data-center-director.html)
- Cisco: [NDI white paper 6.0.1 (pre-change origin in NAE)](https://www.cisco.com/c/en/us/td/docs/dcn/whitepapers/cisco-nexus-dashboard-insights-white-paper-601.html) · [Analysis Hub 6.4.1 (ACI)](https://www.cisco.com/c/en/us/td/docs/dcn/ndi/6x/articles-641/ndi-analysis-hub-aci.html) · [Delta analysis API](https://developer.cisco.com/docs/nexus-dashboard/latest/create-delta-analysis-job/)
- Arista: [ANTA](https://anta.arista.com/) · [GitHub](https://github.com/aristanetworks/anta)
- Nokia: [EDA introduction (Digital Sandbox)](https://documentation.nokia.com/eda/24-12/books/user/introduction.html) · [EDA product page](https://www.nokia.com/data-center-networks/data-center-fabric/event-driven-automation/)
- NetPilot: [Change validation](https://www.netpilot.io/network-change-validation) · [Self-hosted, air-gapped](https://www.netpilot.io/blog/self-hosted-containerlab-ai) · [Pricing](https://www.netpilot.io/pricing)
- NSPM: [Skybox shuts down (SecurityWeek)](https://www.securityweek.com/skybox-security-shuts-down-lays-off-entire-workforce/) · [Tufin acquires Skybox assets (Ctech)](https://www.calcalistech.com/ctechnews/article/s1wi4rc5yl) · [FireMon vs AlgoSec vs Tufin (FireMon)](https://www.firemon.com/firemon-vs-algosec-vs-tufin/) · [Tufin vs FireMon (Tufin)](https://www.tufin.com/why-tufin/tufin-vs-firemon) · [PeerSpot comparison](https://www.peerspot.com/products/comparisons/algosec_vs_firemon-security-manager_vs_tufin-orchestration-suite)
- Automation: [Itential configuration validation](https://www.itential.com/cloud-platform/configuration-validation/) · [Gartner Peer Insights, network automation](https://www.gartner.com/reviews/market/network-automation-platforms)
- NetBox Labs: [NetBox Assurance](https://netboxlabs.com/products/netbox-assurance/) · [Assurance docs](https://netboxlabs.com/docs/assurance/) · [Infrastructure Intelligence platform (2026-06-11)](https://www.globenewswire.com/news-release/2026/06/11/3310275/0/en/netbox-labs-announces-infrastructure-intelligence-platform-with-new-capabilities-spanning-entire-network-and-infrastructure-lifecycle.html)
- Regulation: [DORA RTS on ICT risk management, C(2024) 1532, published as Reg. (EU) 2024/1774 (European Commission)](https://ec.europa.eu/finance/docs/level-2-measures/dora-regulation-rts--2024-1532_en.pdf) · [Art. 17 summary (Springlex)](https://www.springlex.eu/en/packages/dora/rts-rmf-regulation/article-17/) · [BaFin DORA guidance](https://www.bafin.de/SharedDocs/Downloads/EN/Anlage/dl_2024_07_08_Aufsichtsmitteilung_Umsetzungshinweise_DORA_en.pdf?__blob=publicationFile&v=3)

---

## 4. Using AEGIS as a network-team security control

### 4.1 What it can measure today

The status column says how strong each piece of evidence is.

| Control objective | What AEGIS produces | Evidence strength |
|---|---|---|
| Change is tested before production (NIST CM-3(2), CM-4; PCI DSS 6.5.1/6.5.2; HITRUST 09.b) | Twin run with BGP before/after counts, convergence and verdict, sealed | **Confirmed** for BGP session health only |
| Security impact analysis (CM-4) | Static analysis findings, compliance rows, authority class (ASN/RD/RT/underlay/spine) | **Partial.** No reachability or ACL impact yet. |
| Separation of duties (CM-5, AC-5) | Approver ≠ operator, per-person approver credential, token bound to config and inventory | **Confirmed** (bridge until SSO) |
| Approval is attributable and single-use | HMAC v2 token hash in the promotion record, ledger `approval_consumed` | **Confirmed** |
| Audit trail integrity (AU-9, AU-10) | Hash-chained ledger, Ed25519 seal, offline verifier, SIEM syslog anchor | **Tamper-evident.** Becomes tamper-resistant once the SIEM copy has WORM retention. |
| Secure configuration baseline (CM-6, CIS 4, DISA) | 11 framework crosswalks, Junos and Cisco aware | **Confirmed** for the checks implemented. Not full STIG coverage. |
| AI governance (internal AI-use policy; emerging AI-assurance expectations) | Model identity (provider, model, weights hash) sealed per change, autonomy ceiling | **Differentiator.** Confirmed in code. |
| Rollback readiness | Vendor-aware plan | **Plan only.** Not executed (P1). |

### 4.2 KPIs and KRIs for Grafana

These come from `/metrics` on the existing Prometheus stack.

| Metric | Type | Use |
|---|---|---|
| `aegis_preflight_runs_total{decision}` | KPI | Share of changes preflighted; block rate (a rising block rate is a quality signal, not a failure) |
| `aegis_promotions_total{status="denied"}` | KRI | Attempts to promote outside policy. Alert on any denial with "seal verification failed" or "single-use". |
| `aegis_seal_verify_total{result="invalid"}` | KRI | **Should be 0.** Any non-zero value is a forgery or tamper attempt. Page on it. |
| `aegis_approval_mint_total{result="sod_denied"}` | KRI | Self-approval attempts |
| `aegis_ledger_entries` + `/api/ledger/verify` | Integrity | Scheduled job: alert if `valid=false` or the head regresses |
| **Coverage, to build** | KPI | % of ServiceNow normal network changes carrying an AEGIS `change_ref`. This is the number leadership will ask for. |

### 4.3 Operating model (proposed RACI)

| Activity | Network Eng | NetOps lead (approver) | InfoSec | CAB |
|---|---|---|---|---|
| Run preflight, attach bundle to CHG | **R** | I | | I |
| Approve (mint v2 token) | | **R/A** | | C |
| Own keys (seal / approve / approver registry) and rotation | | C | **R/A** | |
| Review weekly KRIs, ledger verify | | **R** | A | I |
| Policy: ceiling tier, D1–D4 decisions below | C | R | **A** | C |

---

## 5. Performance

| Measure (sim tier, this container) | Before | After |
|---|---|---|
| Pipeline, 11 frameworks | 0.80 ms/run (1,256/s) | **0.43 ms/run (2,344/s)** |
| PDF render | 24.8 ms | ~same (ReportLab bound) |

The real bottleneck in live mode is **twin spawn and convergence** (seconds to minutes per
run), not the Python engine. The levers that matter there, in order:

1. **Warm twin pool.** Keep N pre-converged twins per topology and reset by config rollback
   instead of `clab destroy/deploy`. Expect a 5–10× reduction in wall time per run
   (**Inferred** from containerlab boot costs; measure in the pilot).
2. **Topology slicing.** Spawn only the devices in the blast radius, plus their neighbors.
3. **Batfish first, twin second.** Skip the twin on a static `blocked`. This is already
   ordered correctly in the pipeline, so it saves twin minutes on bad changes.
4. **Parallel post-checks.** Run Nornir with `workers` sized to the slice, not a fixed 50.
5. **Cache static analysis** by config sha256 when the same candidate is re-run after a
   wording-only intent change.

---

## 6. Roadmap

Each phase has an owner, an exit criterion and an effort estimate in engineer-weeks.

| Phase | Work | Closes | Owner | Effort | Exit criterion |
|---|---|---|---|---|---|
| **P0 (this branch)** | G0 seal gate, SoD, approver registry, single-use tokens, ledger, production mode, Junos compliance, honest rollback, container + CI hardening, offline verifier, metrics, change_ref | A1–A7, A9, N1–N8, N10 | Georgi + Claude | done | CI green on all jobs |
| **P1 (2–4 wks): pilot-ready** | Validate OSCAL against the NIST schema in CI. Point `AEGIS_LEDGER_SYSLOG` at the SIEM (**sink shipped**; configure it and add a SIEM-side WORM retention rule). Scheduled `ledger/verify` alert. Decide D1–D4. | N8, A5 anchor | Georgi + 1 dev | 2–3 | Pilot runbook signed off by InfoSec |
| **P2 (1–2 mo): enterprise identity and keys** | Entra ID OIDC with operator/approver/auditor roles, replacing `AEGIS_APPROVER_KEYS`. Seal and approve keys in KMS/HSM with an annual rotation ceremony (IS-022P). Build the PIV signer. Threat model (STRIDE), with SAST feeding SonarQube per ITS-025P. | A2 (full), A8 | InfoSec + Network Ops | 4–6 | IS-022P / ITS-025P review passed |
| **P3 (2–3 mo): close the coverage gap** | **Batfish reachability and ACL intent checks** as YAML assertions in git, with differential before/after, cited config lines, and parse-fidelity reported as a finding. **ServiceNow**: create or attach to the CHG, post the verdict and PDF, block CAB on `blocked`. **NetBox**: inventory and roles for `classify_change` (replacing the spine/underlay name heuristic) and `inventory_rev` in v2 tokens. | Biggest market gaps | Network Ops | 6–8 | 80% of DC fabric normal changes carry an AEGIS bundle |
| **P4 (quarter): close the loop** | **Post-change verification**: after the human push, snapshot production and diff it against the twin's expected state. **Rollback executed in the twin** (`verification: executed-in-twin`). Warm twin pool. Firewall/F5 policy checks (PAN-OS, F5 tmsh) as a second domain. | N1 (fully), perf | Network Ops | 8–10 | Mean preflight under 5 min; post-change drift reported per change |

---

## 7. Decisions needed

| # | Decision | Options | Recommendation |
|---|---|---|---|
| **D1** | Is a BGP neighbor add (`remote-as` / `peer-as`) fabric identity (BLOCK)? (N9) | (a) keep BLOCK; (b) treat peer AS as a *peering* change, HITL minimum, with only `router bgp N` / `local-as` / `autonomous-system` / RD / RT as BLOCK | **(b)**. Today the tool can never promote its most common change, so teams will route around it. **Shipped as a switch:** `AEGIS_PEER_AS_POLICY=hitl` (the default stays `block`). Flip it after InfoSec agrees. |
| **D2** | Should Cisco type 7 and Junos `$9$` fail PCI 8.3.2? | (a) report only (current); (b) fail | **(b) for PCI-scoped devices.** Both are reversible obfuscation, not strong crypto. Needs InfoSec sign-off. |
| **D3** | Secrets in the bundle JSON (the push artifact) | (a) keep (promotion pushes from the bundle); (b) replace with vault references resolved only by the connector | **(b) in P2.** Until then, treat bundles as Confidential. |
| **D4** | Which standard governs? | IS-022P / ITS-025P / HITRUST (2020–21) or a newer set | Confirm the current version. This doc maps to the 2020–21 set found by the earlier session. |
| **D5** | Pilot domain | DC fabric (Junos BGP/EVPN) vs WAN edge vs firewalls | **DC fabric.** Best twin fidelity (containerlab cRPD/vJunos), and the authority model already understands ASN/RD/RT/underlay. |

---

## 8. Unknowns requiring validation

| Item | Status | How to validate |
|---|---|---|
| CI result on real Flask / Docker / Bandit / pip-audit | **Confirmed green** (runs #71–#73); merged as `ff886ea` | Done |
| Live-tier behavior (`HttpBackend` against DCN_Network_Tool :5757) | **Unverified.** Contract tests only. | Pilot run against the lab stack |
| Whether Junos GTSM evidence (`ttl-except 255` filter term) matches your standard | **Inferred** from Junos firewall-filter syntax | InfoSec/STIG owner review |
| DISA rows use Cisco `CISC-RT-*` ids for Junos checks; the Juniper Router STIG ids are not mapped | **Known gap** | Map JUNOS STIG rule ids (do not guess them) |
| OSCAL output validity against the official NIST JSON schema | **Unverified** | P1: add schema validation in CI (needs the schema vendored for air-gap) |
| Competitor pricing, air-gap feature parity, evidence formats | **Unknown** for most vendors (see the "?" cells in §3.3–3.4) | RFP questions in §3.7 |
| Older marketing copy still says competitors are "cloud-by-architecture" (`docs/launch_posts.md`, `docs/blog_why_airgap.md`, `docs/LAUNCH_PLAN.md`, `docs/overview_narration.md`, `docs/overview_video.html`, `docs/PHASES.md` research log, and the videos) | **Conflicting** with the 2026 evidence (§3.1). README and Pages are corrected. | Revise before any re-post. The PHASES.md entry is a dated historical log, so annotate it rather than rewrite it. |

---

## 9. Argus (separate repository: not verified in this session)

The earlier session's findings R1–R8 (console without auth or Host/Origin check, `sshpass -p`
in argv, shared HMAC key for audit and approval, policy/registry drift, thin redaction,
symmetric-only audit chain, CI holes) are **Unverified here**, because the repository is
not attached to this session.

Several AEGIS fixes are directly reusable there:

- the hash-chained ledger;
- single-use tokens;
- a production-mode start guard;
- vendor-aware secret redaction.

Attach the repo to continue.
