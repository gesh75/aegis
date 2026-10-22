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

**Where AEGIS stands against the market.** Forward Networks, IP Fabric and NetBrain
are mature, model-based network assurance platforms. AEGIS cannot out-model them, and it
should not try. AEGIS has a defensible niche that the incumbents structurally underserve:
signed, offline-verifiable change evidence, produced entirely inside the perimeter, that
records which AI model proposed a change and that its autonomy was bounded. That evidence
maps to the change-control clauses auditors actually test (NIST CM-3/CM-4,
PCI DSS 6.5.1–6.5.2, HITRUST 09.b).

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
  101 compliance checks, 53 hardening checks, and the rest.
- **GitHub Actions run #71** (`workflow_dispatch` on this branch, commit `be97089`) was
  **green on all three jobs**:
  - `test` ran all 15 suites against real Flask 3 and Python 3.11.
  - `security`: Bandit found **0 high**, 1 medium (B310 `urlopen`, since fixed with an
    http(s) scheme pin) and 4 low. pip-audit reported **"No known vulnerabilities found"**.
  - `container`: the image built, gunicorn 23 listens on `0.0.0.0:8088` inside the
    container, it runs as UID 10001, and `/healthz`, `/api/preflight/run` and `/metrics`
    all returned 200.
- CI notice: `actions/checkout` and `setup-python` pins target the deprecated Node 20, and
  Dependabot will propose bumps.

---

## 3. Competitive landscape

<!-- COMPETITIVE -->

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
| Audit trail integrity (AU-9, AU-10) | Hash-chained ledger, Ed25519 seal, offline verifier | **Tamper-evident**, not WORM. Anchor in SIEM/WORM (P1). |
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
| **P1 (2–4 wks): pilot-ready** | Validate OSCAL against the NIST schema in CI. Ship ledger entries to the SIEM (syslog/HTTP) for a WORM anchor. Scheduled `ledger/verify` alert. Decide D1–D4. | N8, A5 anchor | Georgi + 1 dev | 2–3 | Pilot runbook signed off by InfoSec |
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
| CI result for this branch on real Flask / Docker / Bandit / pip-audit | Pending at writing | GitHub Actions run on this branch |
| Live-tier behavior (`HttpBackend` against DCN_Network_Tool :5757) | **Unverified.** Contract tests only. | Pilot run against the lab stack |
| Whether Junos GTSM evidence (`ttl-except 255` filter term) matches your standard | **Inferred** from Junos firewall-filter syntax | InfoSec/STIG owner review |
| DISA rows use Cisco `CISC-RT-*` ids for Junos checks; the Juniper Router STIG ids are not mapped | **Known gap** | Map JUNOS STIG rule ids (do not guess them) |
| OSCAL output validity against the official NIST JSON schema | **Unverified** | P1: add schema validation in CI (needs the schema vendored for air-gap) |
| Competitor pricing and air-gap support | See the §3 confidence labels | Vendor calls during evaluation |

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
