# AEGIS Improvement Plan — June 2026

Synthesized from 3 research briefs (Batfish, digital-twin verification, compliance-evidence automation) and a 3-lens verified code review (security, quality, compliance).

---

## 1. Prioritized Fix List (quick wins first)

### Tier 0 — Quick wins (<1 hour each, ship this week)

1. **PCI control ID fix: 8.3.1 → 8.3.2** — `evidence/frameworks/pci_dss_v4.py:24` (+ SELF_TEST string at :42). One-line change; wrong requirement number in an auditor-facing artifact is a defensibility killer. *(HIGH, compliance)*
2. **Verify bundles before PDF render** — `serve.py:130`: call `bundler.verify(bundle)` (one existing line) and `verify_seal()` when present; return 422 or watermark "UNVERIFIED" on failure. Closes the forged-evidence-PDF hole. *(HIGH, security + quality)*
3. **Fail closed on invalid AEGIS_SEAL_KEY** — `serve.py:54`: `SystemExit` instead of silent ephemeral-key fallback. The pinned key IS the product; misconfig must be fatal. *(MEDIUM)*
4. **Guard empty promote** — `promote.py:38`: raise `PromoteDenied("nothing to promote")` when `generated_configs` is empty. *(LOW)*
5. **Fail closed in `parse_nornir_bgp` on missing keys** — `http_backend.py:76`: missing `error`/`results` → not converged. *(LOW)*
6. **Move `jsonschema` to requirements-dev.txt, relax to >=4; add `httpx` to runtime requirements.** *(LOW)*

### Tier 1 — High-severity correctness (this sprint)

7. **Fix the BGP session-count regex** — `http_backend.py:81`. Empirically confirmed to count 4 "Established" in output with 1 real peer (any digit-terminated line matches). This feeds the blocked/ship_ready verdict — a core safety decision on a broken parser. Parse peer rows only (lines starting with a neighbor IP; State/PfxRcd column numeric or `Estab*`); add fixture tests with real FRR/EOS `show bgp summary` output. *(HIGH, quality)*
8. **Gate twin-evidence claims on `sig.twin_tested()/twin_converged()`** in three frameworks:
   - `nist_800_53.py:18` (CM-3) — claims twin verification unconditionally
   - `soc2.py:14` (CC8.1) — same
   - `nerc_cip.py:44` (CIP-010-R1.2) — same
   Mirror the correct pattern already in `hipaa.py` (164.308(a)(8)) and `cis_v8.py` (12.2). Note verified trigger: a *non-converged* twin still produces a sealed bundle containing PASS "validated in digital twin" — internally contradictory sealed evidence. *(HIGH, compliance)*
9. **Real approval verification** — `core/promote/gate.py:31`, `pipeline.py:86`, `serve.py:113`. Any non-empty approver/token string passes G2/G3 and the Ed25519 seal then attests to an approval nobody verified. Implement HMAC-signed approval tokens bound to bundle sha256 + approver identity + expiry; derive approver from an authenticated session, not the request body. Interim: record approvals as `asserted, unverified` in the bundle. Also store verification method + token hash in the promotion record (`promote.py:55`). *(HIGH, security)*
10. **API auth + CSRF** — `serve.py:88`: API-key header minimum (custom header also breaks cross-site POSTs); refuse to load `AEGIS_SEAL_KEY` when no auth is configured so unauthenticated deployments can never mint pinned-key seals. *(HIGH, security)*

### Tier 2 — Hardening (next sprint)

11. **Central `_esc()` helper for all bundle strings entering ReportLab Paragraphs** — `evidence/pdf.py` (lines 71-74, 82, 111, 136, 141, 157; line 143 misses `>`). Legit configs with `<...>` currently 500 the PDF endpoint; crafted device names inject markup into evidence PDFs. *(MEDIUM x2)*
12. **Fail loudly on unparseable LLM output** — `http_backend.py:118`: raise `PreflightError("generation_failed")` instead of synthesizing a passing stub config. A no-op stub trivially produces a sealed `ship_ready` bundle — violates AEGIS's own fail-closed principle. *(MEDIUM)*
13. **Make all 13 test files pytest-collectible** — `tests/api_test.py` etc.: 8 of 13 files use a bespoke `check()/main()` harness invisible to `pytest tests` (only 76 tests from 5 files collected). Add `def test_<name>(): assert main() == 0` wrappers; one CI command runs everything. This is how the BGP regex bug survived. *(MEDIUM)*
14. **Real secret detection** — `_base.py:71`: replace the `'abc123'`/4-token demo predicate (drives verdicts in 8+ frameworks) with regex patterns for actual vendor syntaxes (Cisco type-0/7, `neighbor X password`, SNMP communities), and soften evidence text to match what's actually checked. *(MEDIUM)*
15. **Drop `'unsafe-inline'` from CSP** — `serve.py:34`: externalize the inline script, use addEventListener. *(LOW)*

---

## 2. Product Roadmap Gaps vs Competitors

What Batfish / Forward Networks / NetPilot do that AEGIS doesn't yet:

| Gap | Competitor pattern | AEGIS move |
|---|---|---|
| **Differential (before/after) reporting as the default** | Batfish snapshot vs reference-snapshot diff (`differentialReachability`) sold change review | Make every preflight report a pre/post diff: sessions down, reachability changed, new undefined refs — not just a verdict |
| **Snapshot abstraction with stable IDs** | Batfish snapshots; Forward "time machine" diffs | Content-addressed snapshot IDs; every run pinned to one; drift detection between runs |
| **Real simulation depth** | Batfish data-plane verification (traceroute, ACL analysis, loop detection) | Embed `batfish/allinone` as an offline sidecar instead of rebuilding reachability math; layer AEGIS compliance checks on pybatfish DataFrames |
| **Declarative intent checks in git** | Forward intent checks re-run per snapshot; Batfish `assert_*` gating CI | YAML assertion DSL versioned next to configs; exit codes + JUnit output for pipelines |
| **Model-fidelity reporting** | Batfish `initIssues`/parse-warning transparency — its biggest trust win | Report parse %, unsupported lines per snapshot; treat low fidelity as a finding, never silently drop config |
| **Evidence-cited findings** | Forward cites "the path, policy, or config line that proves it" | Every pass/fail row links to config file + line + computed path (AEGIS partially does; make universal) |
| **OSCAL Assessment Results export** | FedRAMP-mandated; Vanta/Drata converging via OSCAL-COMPASS | Emit OSCAL AR JSON alongside HTML/PDF — strong differentiator for the 11-framework story |
| **Hash-chained run log + RFC 3161** | Chain-of-custody best practice (FRE 901/902) | Append-only hash-chained collection log; observation-window stamps (SOC 2 Type II provability) |
| **Cross-framework control-mapping matrix as artifact** | Vanta/Drata 80-90% effort reduction claims | Emit the one-check→N-controls matrix in every bundle (AEGIS has the mapping; surface it) |
| **Emulation tier for convergence/failover** | NetPilot ~2-min sandbox on real NOS images | Optional containerlab tier (cEOS/cRPD/SR Linux) when static analysis isn't enough |
| **CAB-ready change report** | NetPilot pre/post + rollback-verified report | One-page CAB export: what changed, which intents still hold, rollback plan verified |

Strategic note: AEGIS's defensible position is **compliance-evidence + air-gap**, not simulation. Embed Batfish for depth; invest original engineering in evidence integrity (after Tier 0/1 fixes — the evidence layer must actually be trustworthy first).

---

## 3. LinkedIn Content Brief — Tuesday Post

**Product framing:** AEGIS — air-gapped digital-twin preflight for network changes; 11 compliance frameworks; sealed evidence bundles.

### Angle A (strongest): "Your auditor doesn't want screenshots."
- Hook: PCI QSAs and SOC 2 examiners now prefer raw, timestamped, hash-verified exports over screenshots — yet most network teams still screenshot `show run`.
- Body: AEGIS runs the change in an offline digital twin, then seals the evidence — SHA-256 manifest, Ed25519 signature, stable evidence IDs PCI-ROC style — so one preflight run produces SOC 2 + PCI + HIPAA + NERC CIP evidence simultaneously (11 frameworks, one control-mapping matrix).
- CTA: "What does your CAB evidence look like today — screenshots or signed artifacts?"
- Why it wins: speaks to a pain every regulated network engineer recognizes; quantifiable (11 frameworks, 1 run); positions Georgi at the network+compliance+AI intersection.

### Angle B: "Test the change where it can't hurt anyone."
- Hook: The safest network is one where the change already failed — in the twin, not in production.
- Body: Batfish proved config-only offline analysis works; Forward proved enterprises pay for intent verification. AEGIS brings that pattern to air-gapped environments: no live device access, no credentials, no egress — preflight verdict (ship_ready/blocked) + rollback plan before anything touches a router.
- Why it works: digital-twin is the hot enterprise networking topic; air-gap angle differentiates from Forward/NetPilot (both assume connectivity).

### Angle C: "Evidence over assertion — the CAB pattern that ends 'trust me'."
- Hook: CAB approvals shouldn't be "the engineer says it's fine." They should be "here's the signed pre/post diff proving it."
- Body: Walk the workflow: intent → twin run → differential report → framework-mapped evidence rows → sealed bundle → examiner-ready PDF. Every verdict cites the config line that proves it.
- Why it works: process-story format performs well with director/manager audience (Georgi's target roles); subtly demonstrates leadership thinking, not just tooling.

**Recommendation:** Lead with Angle A; reserve B for a follow-up post; fold C's workflow walk-through into A's body as a 5-step list. Format: hook line → 3-4 short paragraphs → quantified bullet block (11 frameworks · 0 egress · 1 sealed bundle per run) → question CTA. No links in post body (comment-link pattern).
**Honesty guardrail:** do not post claims about seal/approval integrity until Tier 0 items 1-3 and Tier 1 item 8 ship — the post's claims should survive a reader cloning the repo.

---
*Generated 2026-06-12 from multi-agent research + verified 3-lens review.*
