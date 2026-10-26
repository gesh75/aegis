# D3: secret references in the evidence bundle (design note)

**Status:** Planned for P2 and not implemented. Decision D3 in `docs/STRATEGY_2026-10.md`
§7. Until it ships, **treat every bundle JSON as Confidential**.

## Problem

The bundle is the push artifact. Promotion pushes `change.configs[].config` exactly as it
was sealed, so any credential in the candidate config is inside the JSON:

- a BGP key, a Junos `$9$` string, a type 7 password or a hash;
- every copy of the bundle: the browser download, the CAB attachment, and the SIEM, if
  someone forwards it.

The PDF, CAB and OSCAL exports redact through `evidence/secrets.py`. The JSON cannot be
redacted, because the seal covers it and the connector needs the real value.

## Design

| Step | Where | What |
|---|---|---|
| 1. Tokenize at ingest | `run_preflight`, before Batfish, the twin and the bundle | Each match of `secrets.PLAINTEXT_PATTERNS`, `REVERSIBLE_PATTERNS` or `_HASH_PATTERNS` is replaced by `{{vault:<path>#<sha256-8>}}`. The value goes to the vault, and only the reference is kept. |
| 2. Seal references | `build_bundle` | The bundle and seal contain only references. `integrity.sha256` is stable, and auditors never see a secret. |
| 3. Validate with placeholders | Batfish, twin | The engines see a syntactically valid dummy of the same type (for example a `$9$` placeholder). The secret's value has no effect on reachability or BGP state. |
| 4. Resolve only at push | `core/promote/connectors.py` | The live connector resolves the references inside the push session, in memory, right before the commit, and never logs them. The ledger records the reference and its sha256-8, never the value. |
| 5. Verify after push | post-change verification | The device's running hash or fingerprint is compared with the sha256-8 in the sealed reference. |

## Vault options (in-perimeter only, air-gap preserved)

| Option | Fit | Note |
|---|---|---|
| HashiCorp Vault / OpenBao (self-hosted) | Best | KV v2 plus transit. A short-lived AppRole token for the connector only. |
| CyberArk Conjur / PAM | Good if it is already the corporate PAM | Check IS-022P key-custody wording (D4). |
| Azure Key Vault / AWS Secrets Manager | Only if reachable over a private endpoint | Breaks the strict air-gap profile, so it needs a separate risk acceptance. |

## Acceptance criteria

1. No bundle, PDF, CAB, OSCAL or ledger entry contains a credential value. A property test
   seeds secrets and greps every artifact.
2. A tampered reference fails G1 (it is covered by the hash).
3. Push fails closed when the vault is unreachable or a reference does not resolve.
4. The twin and Batfish results are identical with placeholders and with real values. A
   regression test proves it.

## Interim controls (now)

- Exports redact secrets. The bundle JSON must be stored as Confidential, and its
  download needs `AEGIS_API_KEY` (production).
- Hardening H8 proves the PDF is redacted.
