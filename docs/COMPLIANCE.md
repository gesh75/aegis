# AEGIS Compliance-Mapping Engine

AEGIS turns a single verified network change into a deterministic crosswalk of compliance
control results. The engine lives in `evidence/compliance.py` (`map_controls`) plus an
auto-discovering registry of per-framework modules under `evidence/frameworks/`. Each
framework is one self-contained file that exposes `FRAMEWORK = "<id>"` and
`evaluate(sig) -> list[dict]`; the registry (`frameworks/__init__.py`) walks the package
with `pkgutil`, imports every sibling module that defines both symbols, and registers it in
`REGISTRY` — a module that fails to import is skipped so one broken framework can never take
down the rest. `map_controls` builds a single read-only **`ComplianceSignal`** (the proposed
`configs`, the `batfish` static-analysis result, and the optional `twin`, `diff`, `intent`,
and `source`) and dispatches it through each requested framework in the caller's order. The
`ComplianceSignal` exposes cheap, reusable predicates (`has_bgp`, `has_plaintext_secret`,
`missing_export_policy`, `batfish_clean`, `twin_converged`, `sessions_dropped`, …) so every
per-framework check stays pure and deterministic. Each control result is a row
`{framework, control, status, evidence, kind}` where `status` is `pass | fail | not_applicable`
and `kind` is one of two honesty tiers: **`config-checked`** controls assert something
actually visible in the proposed config or static analysis (a plaintext secret, a missing
export policy, a Batfish error), while **`process-mapped`** controls claim only what the
AEGIS pipeline structurally guarantees for *this* run (twin-tested, deterministically
verified, sealed evidence, human-gated promotion).

## Frameworks

Eleven frameworks are live (`from aegis.evidence.frameworks import REGISTRY`). Tiers:
PCI/SOC2/NIST-800-53 are the original set; DISA STIG / CIS v8 / NIST CSF 2.0 = Tier 1;
NERC CIP / HIPAA = Tier 2; ISO 27001 / IEC 62443 / NIST 800-171 = Tier 4.

| id | Full name | Tier | Controls covered | Config-checked |
|---|---|---|---|---|
| `pci_dss_v4` | PCI DSS v4.0 — Payment Card Industry Data Security Standard | Original | 1.2.1 (network security controls), 8.3.1 (strong crypto for auth) | 2 of 2 |
| `soc2` | SOC 2 (AICPA Trust Services Criteria) | Original | CC8.1 (change management) | 0 of 1 |
| `nist_800-53` | NIST SP 800-53 — Security and Privacy Controls (Config Management) | Original | CM-3 (change control), CM-6 (config settings) | 1 of 2 |
| `disa_stig` | DISA STIG — Cisco Router/Switch RTR (CISC-RT-*) | Tier 1 | CISC-RT-000480 (unique per-AS BGP key), CISC-RT-000560 (BGP max-prefix), CISC-RT-000470 (eBGP GTSM/ttl-security), CISC-RT-000050 (FIPS 198-1 routing-proto auth) | 4 of 4 |
| `cis_v8` | CIS Critical Security Controls v8 | Tier 1 | 4.2 (secure-config process), 12.3 (securely manage network infra), 12.2 (secure network architecture) | 1 of 3 |
| `nist_csf_2.0` | NIST Cybersecurity Framework 2.0 | Tier 1 | PR.PS-01 (config-mgmt practices), PR.IR-01 (protect from unauthorized logical access), DE.CM-01 (network monitoring) | 2 of 3 |
| `nerc_cip` | NERC CIP-010 — Configuration Change Management & Vulnerability Assessments | Tier 2 | CIP-010-R1.1 (baseline), CIP-010-R1.2 (authorize/document deviation), CIP-010-R1.4 (CIP-005/007 not adversely affected) | 1 of 3 |
| `hipaa` | HIPAA Security Rule — 45 CFR Part 164, Subpart C | Tier 2 | 164.312(e)(1) (transmission security), 164.308(a)(8) (evaluation), 164.312(b) (audit controls) | 1 of 3 |
| `iso_27001` | ISO/IEC 27001:2022 — Annex A | Tier 4 | A.8.9 (configuration management), A.8.32 (change management), A.8.20 (networks security) | 2 of 3 |
| `iec_62443` | IEC/ISA 62443-3-3 — System security requirements & security levels (OT/ICS) | Tier 4 | SR 1.1 (human user ID/auth), SR 1.2 (device/process ID/auth), SR 3.1 (communication integrity), SR 7.6 (network/security config settings) | 4 of 4 |
| `nist_800-171` | NIST SP 800-171 Rev. 2 — Protecting CUI (Config Management 3.4.x; CMMC L2) | Tier 4 | 3.4.1 (baseline configs & inventory), 3.4.2 (enforce secure settings), 3.4.3 (track/review/approve/log changes) | 1 of 3 |

**Totals:** 11 frameworks, 30 mapped controls, 19 of which are actively config-checked off
the proposed change (the remaining 11 are process-mapped to the pipeline).

### What each module actually inspects

- **Config-checked controls** derive `pass/fail/not_applicable` from real predicates on the
  change. Common triggers: `has_plaintext_secret()` (matches `plaintext`, `abc123`,
  `password 0 `, `key 0 `), `missing_export_policy()` (a Batfish "without export policy"
  finding), `batfish_clean()` (zero errors), and protocol-surface detection (`has_bgp`,
  `has_routing_proto`). Several modules return `not_applicable` honestly when the change has
  no relevant surface — e.g. DISA STIG, NIST CSF PR.IR-01, HIPAA transmission security,
  ISO A.8.20, and all IEC 62443 SRs return NA on a clean VLAN-only change rather than
  fabricating a pass. DISA STIG and IEC 62443 are wholly config-checked, so on the
  simulator's minimal configs a BGP change without the required hardening directive
  (max-prefix, GTSM, FIPS key-chain) legitimately returns **FAIL** — AEGIS catching a real
  gap in *this* change, not a certification verdict.
- **Process-mapped controls** assert what the pipeline guarantees: change validated in a
  digital twin (`twin_converged`), no sessions dropped (`sessions_dropped`), sealed
  content-hashed evidence bundle, and human-gated promotion. Examples: SOC2 CC8.1,
  NIST 800-53 CM-3, CIS 4.2, NERC CIP-010 R1.1/R1.2, HIPAA 164.308(a)(8)/164.312(b),
  ISO A.8.32, and NIST 800-171 3.4.1/3.4.3.

## Honesty note

The bundle AEGIS emits is **control-mapped evidence for THIS change**, not a certification.
A `config-checked` row asserts only what is visible in the proposed config / static analysis
for this run; a `process-mapped` row asserts only what the pipeline structurally guaranteed
for this run (it was twin-validated and gated before deployment). No row claims the
organization is "PCI/SOC2/NIST/ISO/HIPAA/NERC/CMMC certified." Evidence strings stay specific
and truthful, and modules return `not_applicable` rather than inventing a pass when a change
does not exercise the relevant surface. This is the HONESTY RULE encoded in
`frameworks/_base.py` and enforced by each module's evidence text.

## How to add a framework

Adding a framework is a single new file in `evidence/frameworks/` — no central edit, no merge
conflict. The registry auto-discovers any module that defines `FRAMEWORK` plus `evaluate`.

1. Create `evidence/frameworks/<your_framework>.py`.
2. Import the shared contract and define the two required symbols:

   ```python
   from ._base import ComplianceSignal, control, PASS, FAIL, NA, CONFIG_CHECKED, PROCESS_MAPPED

   FRAMEWORK = "my_framework"   # the id used in the bundle + UI

   def evaluate(sig: ComplianceSignal) -> list[dict]:
       out: list[dict] = []
       # config-checked: decide from what's actually in the change
       bad = not sig.batfish_clean() or sig.has_plaintext_secret()
       out.append(control(
           FRAMEWORK, "CTRL-1",
           FAIL if bad else PASS,
           "insecure directive flagged" if bad else "config baseline clean",
           CONFIG_CHECKED))
       # process-mapped: assert only what the pipeline guarantees for THIS run
       out.append(control(
           FRAMEWORK, "CTRL-2", PASS,
           "change validated in digital twin and gated on human approval",
           PROCESS_MAPPED))
       return out
   ```

3. (Recommended) add a `SELF_TEST` list of `(signal_kwargs, control_id, expected_status)`
   tuples mirroring the existing modules, so the framework's pass/fail logic is exercised.
4. Keep the honesty rule: only mark a control `CONFIG_CHECKED` if `evaluate` actually
   inspects the config/Batfish to decide; otherwise mark it `PROCESS_MAPPED`. Use `NA` when
   the change does not exercise the control's surface. Never imply certification.

The module is live the moment the file lands — `map_controls(..., frameworks=["my_framework"])`
will dispatch through it, and `from aegis.evidence.frameworks import REGISTRY` will list it.
Module-level names beginning with `_` (e.g. `_base.py`) are skipped by the registry.
