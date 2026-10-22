# AEGIS — Evidence, seals, and examiner PDFs

Two different artifacts ride on a PreFlight response. Operators and auditors
must not treat them as the same control.

| Layer | What it proves | Who can mint it | Where it is checked |
|---|---|---|---|
| **Bundle integrity** (`integrity.sha256`) | The JSON is self-consistent: fields still hash to the recorded digest. | Anyone who can compute the public algorithm. | `evidence.bundler.verify` · PDF/OSCAL/CAB endpoints · promote G1 · seal G6 |
| **Detached seal** (`bundle.seal`) | A pinned key signed *this* digest plus model identity plus the autonomy ceiling. | Only a process that holds `AEGIS_SEAL_KEY` (or the ephemeral demo key). | `POST /api/seal/verify` · `core.seal.verify_seal` (G0–G6) · **promote G0** · **PDF/OSCAL/CAB exports** · `python -m aegis.verify` |

The examiner PDF is a **rendering** of a self-consistent bundle. It is not an
origin proof.

Companion pages: [ARCHITECTURE.md](ARCHITECTURE.md) · [GO_LIVE.md](GO_LIVE.md) ·
[COMPLIANCE.md](COMPLIANCE.md).

---

## 1. Bundle integrity (`evidence/bundler.py`)

`build_bundle` writes `integrity.sha256` over canonical JSON
(`sort_keys=True`, compact separators) with two exclusions:

1. `integrity.sha256` itself is blanked while hashing.
2. `seal` is popped — the CROSS-3 receipt signs that digest; it must not be
   inside it.

`integrity.egress` is hard-pinned to `"none"`. Re-hashing after the fact is
`bundler.verify(bundle)` / `compute_sha256(bundle)`.

A 422 from `POST /api/preflight/evidence/pdf` means only: the body no longer
matches its own `integrity.sha256`. It does **not** mean the bundle came from
AEGIS, or that `bundle.seal` is authentic.

---

## 2. Detached Ed25519 seal (`core/seal/seal.py`)

`serve.preflight_run` calls `seal_response` after the pipeline. The receipt is
attached at `bundle["seal"]` and is `null` when the change is unbounded
(`authority.allowed` is false or `effective == "block"`). The signer refuses
to certify a self-escalation (`SealError`).

Claims bound into the signature (`build_claims`):

- `bundle_sha256` — the integrity digest above
- model identity — `provider`, `model`, `model_hash`, `model_hash_kind`
- authority — `required`, `max_authorized`, `allowed`, `effective`
- `sealed_at_utc`

`verify_seal(bundle, seal, pinned_verifier)` is offline and uses **only** the
public key. First failure wins:

| Gate | Rejects |
|---|---|
| G0 | Missing `claims` / `signature` fields |
| G1 | `alg` or `key_id` is not the pinned verifier |
| G2 | Signature does not verify (including a swapped or truncated `value`) |
| G3 | `claims.bundle_sha256` ≠ `bundle.integrity.sha256` |
| G4 | Sealed model identity ≠ `change.model_identity`, or an `identity-claim` carries a weight hash |
| G5 | Sealed authority ≠ `change.authority`, or the change exceeds the ceiling |
| G6 | `bundler.verify` fails |

Schema: `core/seal/schema/seal.schema.json` (`seal_version: "1.0"`). Production
swap is a YubiKey-PIV signer on the same `Signer` protocol
([PIV_HARDWARE_SIGNER_PLAN.md](PIV_HARDWARE_SIGNER_PLAN.md)).

---

## 3. Examiner PDF (`serve.evidence_pdf` → `evidence.pdf.render_pdf`)

```
POST /api/preflight/evidence/pdf
```

| Check | Result |
|---|---|
| No `integrity.sha256` | **400** `valid evidence bundle required` |
| `bundler.verify` is false | **422** content ≠ recorded digest |
| `seal` present but `verify_seal` fails | **422** `seal verification failed at G<n>` (since 2026-10) |
| `seal` absent | community: renders, **Authenticity: UNSEALED** printed under the verdict · production: **422** unless the verdict is `blocked` |
| Render succeeds | **200** `application/pdf`, filename `aegis-evidence-<12 hex of run_id>.pdf` |

Since 2026-10 the endpoint verifies the seal against the server's pinned key
*before* rendering. A swapped or garbage `seal` is a 422, never a printed
"receipt". Every PDF carries an **Authenticity** line. Config secrets are redacted
and all bundle text is markup-escaped.

The PDF is still a *rendering*. The examiner's proof of origin is the
`{bundle, seal}` pair verified offline against the pinned public key
(`python -m aegis.verify --bundle run.json --pubkey pubkey.json`, §6).

---

## 4. OSCAL Assessment Results (`evidence/oscal.py`)

```
POST /api/preflight/evidence/oscal
```

Same 400 / 422 integrity gate as the PDF. Returns AEGIS-shaped Assessment Results
JSON (`oscal-version: 1.1.2`). `metadata.remarks` states this is **not** a FedRAMP
authorization package. Control rows (`validation.compliance`) become observations;
`fail` rows become findings. `kind` is `aegis-oscal-ar-v1`.

## 5. CAB one-pager (`evidence/cab.py`)

```
POST /api/preflight/evidence/cab
```

Same integrity gate. Payload `kind: aegis-cab-v1`: what changed, which intents still
hold, rollback steps. `rollback.verified_in_twin` is **always false** — the reverse
was not applied in the twin. Do not tell a CAB the rollback was proven if this flag
is false.

---

## 6. Auditor runbook (community sim tier)

Community server: `python -m aegis.serve` → `http://127.0.0.1:8088`
(`AEGIS_HOST` / `AEGIS_PORT`). Live twin mode is **501** here; this runbook
still applies to any bundle the same `serve.py` process sealed.

### Pin the public key

```bash
curl -s http://127.0.0.1:8088/api/seal/pubkey
# {"alg":"ed25519","key_id":"…","public_key_b64":"…"}
```

Store `key_id` + `public_key_b64`. After a restart, compare them. If
`AEGIS_SEAL_KEY` was unset, the process minted an **ephemeral** demo key and
receipts from the previous process will fail G1.

To pin a stable key: 64 hex characters (Ed25519 private seed).

```bash
export AEGIS_SEAL_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
```

An invalid value is `SystemExit` at import — the server will not start.

### Seal a run, then verify the pair

```bash
curl -s -X POST http://127.0.0.1:8088/api/preflight/run \
  -H "Content-Type: application/json" \
  -d '{"intent":"add vlan 10 to leaf-1","lab":"single","frameworks":["pci_dss_v4"]}' \
  > /tmp/aegis-bundle.json

# Layer 2 — this is the authenticity check
jq '{bundle: ., seal: .seal}' /tmp/aegis-bundle.json \
  | curl -s -X POST http://127.0.0.1:8088/api/seal/verify \
      -H "Content-Type: application/json" -d @-
# 200 {"valid":true,"gate":"OK","reason":"…"}
# 422 {"valid":false,"gate":"G2","reason":"signature does not verify…"}
```

Body must be `{bundle, seal}`. A missing or non-object either side is **400**.

Offline, against a pinned verifier (no HTTP):

```python
from aegis.core.seal import Ed25519Verifier, verify_seal
from aegis.evidence.bundler import verify as verify_bundle

assert verify_bundle(bundle)                       # layer 1
verdict = verify_seal(bundle, bundle["seal"], pinned_verifier)
assert verdict.valid, (verdict.gate, verdict.reason)  # layer 2
```

### When the PDF is allowed

Only after `verify_seal` returns `valid: true` against **your** pinned key.
Then `POST /api/preflight/evidence/pdf` is a convenience printer, not a second
root of trust.

---

## 7. Pitfalls

- **Client-computed hash.** Invent a bundle, set `integrity.sha256` to
  `compute_sha256(bundle)`, POST it to the PDF route → **200**. That is the
  public algorithm working as designed. It is not a forgery of the Ed25519
  receipt.
- **Swapped `seal`.** `seal` is excluded from the digest, so replacing it does not
  trip the integrity check. Since 2026-10 the export and promote routes run
  `verify_seal`, so it trips there (G1/G2/G3/G4/G5, depending on what changed) → 422/403.
- **`seal: null`.** Unbounded changes (AS / RD / RT → BLOCK; ceiling exceeded)
  produce no receipt. A PDF of that bundle cannot claim "within bound."
- **Ephemeral demo key.** Receipts do not survive a restart unless
  `AEGIS_SEAL_KEY` is pinned. `GET /api/seal/pubkey` after restart is the
  check.
- **Promotion G0 = seal verification.** Since 2026-10 the server's promote route
  calls `evaluate(..., require_seal=True)`. G0 runs `verify_seal` against the
  pinned key, so a hash-valid but unsigned (or forged) bundle is denied before
  G1–G5. Library callers of `gate.evaluate` get the same behavior by passing
  `seal=` and `verifier=`.
- **Community `mode=live`.** `POST /api/preflight/run` with `mode=live` is
  **501**. The live twin path is the integrated `:5757` product
  ([GO_LIVE.md](GO_LIVE.md)).
