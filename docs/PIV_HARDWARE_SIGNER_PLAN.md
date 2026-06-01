# AEGIS — PIV Hardware-Signer Plan (CROSS-3, final pass)

> **Status:** plan / ready to execute when a YubiKey is in hand.
> **Scope:** swap the CROSS-3 seal's *software* Ed25519 signer for a *hardware* YubiKey-PIV
> signer (ECDSA-P256) whose origin is provable via the YubiKey attestation chain, and bind the
> `max_authorized` ceiling to the same hardware root. The Ed25519 path stays as the dev/CI
> fallback. No bundle/seal **format** change — the `signature.alg` enum already reserves
> `piv-ecdsa-p256`.

This is the one piece deliberately *not* built in the seal PRs, because it needs the physical
token to provision, sign, and verify against. Everything it plugs into already ships and is
property-tested: the `Signer`/`Verifier` protocol (`core/seal/signing.py`), the detached
receipt + offline gates **G0–G6** (`core/seal/seal.py`), and the live `/api/seal/*` endpoints.

---

## 0. What already exists (the swap point)

- **`core/seal/signing.py`** — `Signer`/`Verifier` `Protocol`s (`alg() / key_id() /
  public_key_bytes() / sign()`), plus the software `Ed25519Signer` / `Ed25519Verifier`.
  **The PIV signer implements the same `Signer` protocol — nothing above it changes.**
- **`core/seal/seal.py`** — `seal_bundle()` / `verify_seal()` run gates G0–G6; the seal format
  is `{seal_version, claims, signature:{alg, key_id, value}}`. `value` is base64.
- **`evidence/schema/.../seal.schema.json`** — `signature.alg ∈ {ed25519, piv-ecdsa-p256}`.
- **The operator already runs YubiKey PIV/PKCS#11** in the DCN tool (`DCN_SSH_MODE=pkcs11`,
  `libykcs11.dylib`, a working PIN flow). Reuse that operational knowledge — the plumbing is proven.

---

## 1. Goal

A `PivSigner` backed by a YubiKey PIV slot that:
1. signs the seal's canonical claim bytes with **ECDSA-P256** via PKCS#11 `C_Sign`,
2. carries an **attestation chain** (leaf ← slot-`f9` attestation cert ← **Yubico PIV Root CA**)
   that proves the key is **hardware-resident and non-exportable** — so a software key can't
   forge a valid seal (this is what makes "hardware-rooted" *structural*, not asserted), and
3. is selected by config (`AEGIS_SEAL_BACKEND=piv`), with `ed25519` as the default fallback.

Plus: bind **`max_authorized`** (the #5 ceiling) to a PIV-signed policy object so the ceiling
**cannot be raised by editing the environment** — the explicit `#5-ceiling` follow-up.

---

## 2. Decide up front (hardware + crypto facts)

| Decision | Recommendation | Why |
|---|---|---|
| **Slot** | **`9c` (Digital Signature)** for the seal key — *distinct* from the `9a` SSH-auth key | 9c is the PIV signature slot; PIN-per-signature; avoids colliding with the existing SSH key |
| **Key origin** | **Generate ON-DEVICE** (`ykman piv keys generate`) — never import | Only on-device keys are **attestable**; an imported key has no attestation → defeats the wedge |
| **Algorithm** | **ECCP256** (NIST P-256 / secp256r1), sign SHA-256 of the canonical claims | PIV-standard ECC; `cryptography` verifies it. (Classic PIV has **no Ed25519** — hence ECDSA here) |
| **Signature encoding** | `C_Sign`(CKM_ECDSA) returns **raw `r‖s` (64 bytes)** → convert to **DER** for `cryptography` | A real gotcha — `cryptography.verify()` wants DER `(r,s)` via `encode_dss_signature` |
| **Touch policy** | `never` for unattended sealing; `always` for high-assurance (each seal needs a physical touch) | Tradeoff: `always` blocks automated sealing |
| **PIN** | `C_Login` before `C_Sign`; source the PIN from a **secrets manager**, never env in prod | PIV locks out after N wrong PINs — never brute-force in tests |
| **Pinning posture** | **CA + serial allowlist** for regulated fabrics (CA-only survives token swap) | Document the choice; default to CA+serial |

---

## 3. New code (additive — `core/seal/`)

- **`core/seal/piv.py`** — `PivSigner` (PKCS#11 `C_Login` + `C_Sign` on the slot; `alg() ->
  "piv-ecdsa-p256"`; `key_id()` from the SHA-256 of the attested EC public key; raw→DER sig
  conversion) and `PivVerifier` (ECDSA-P256 verify against the attested EC public key). Both
  satisfy the existing `Signer`/`Verifier` protocols verbatim.
- **`core/seal/attestation.py`** — parse + validate the attestation chain with
  `cryptography.x509`: leaf ← slot-`f9` intermediate ← **pinned** Yubico PIV Root CA; assert
  the attested leaf public key **equals** the signing key; optional device-serial allowlist
  (the serial is an X.509 extension in the attestation cert).
- **`core/seal/pins.py`** — **compiled-in** constants (NOT file-loaded): the Yubico PIV Root CA
  fingerprint (SHA-256 of its DER), the pinned seal verification public key + `key_id`, and the
  serial allowlist. Editing a file must not be able to loosen trust.
- **`core/seal/seal.py` `verify_seal()`** — when `signature.alg == "piv-ecdsa-p256"`, run the
  attestation gates **before/with** G1/G2:
  - **G1a** — attestation chain validates to the pinned Yubico Root CA (+ serial in allowlist);
  - **G1b** — the attested leaf public key matches `verifier.key_id()` (the pinned key);
  - **G2** — ECDSA-P256 signature verifies over the canonical claims.
  The `ed25519` path is unchanged (software/dev/CI).
- **`core/risk` ceiling** — `load_max_authorized()` verifies a **PIV-signed ceiling policy**
  `{max_authorized, not_after_utc, key_id, signature}` against the compiled-in pinned key,
  instead of trusting raw `AEGIS_MAX_AUTHORIZED_TIER`. Env stays as the dev fallback.

---

## 4. Sequencing (the critic's D6–D7 spike). ⚡ = needs the physical token

| Step | Work | HW |
|---|---|---|
| **0** | Add the PKCS#11 dep (`PyKCS11`); the EC sign/verify + **raw→DER** helpers; `x509` chain-validation logic — all testable with **software P-256 keys + a self-signed test chain** | — |
| **1** | Provision the token: generate the seal key on-device in **slot 9c** (ECCP256, PIN policy, touch policy); capture the attestation chain (`ykman piv keys attest 9c` + the `f9` intermediate); export the leaf pubkey | ⚡ |
| **2** | `PivSigner` against `libykcs11` (`C_Login` w/ PIN, `C_Sign`); first end-to-end **sign → raw→DER → `cryptography` verify** roundtrip | ⚡ |
| **3** | `attestation.py` chain validation; obtain the **current Yubico PIV Root CA cert from developers.yubico.com**, pin its DER SHA-256, add a checked-in test asserting the pinned bytes match the reference | — |
| **4** | Capture a **real attestation-chain fixture** once (from the token) → check it into `tests/` so CI validates the chain logic **without** the token | ⚡ (once) |
| **5** | Extend `verify_seal` with G1a/G1b; **re-run the full G0–G6 + the 0-violation property against the REAL hardware verifier** (the critic's "re-run against the real verify, not the stub") | ⚡ |
| **6** | Ceiling-policy signing: sign `{max_authorized, not_after_utc, …}` with the PIV key; `load_max_authorized()` verifies it; CI test with a software-signed policy + a one-time hardware one | ⚡ |
| **7** | `serve.py`: `AEGIS_SEAL_BACKEND=piv` selects `PivSigner`; `/api/seal/pubkey` also publishes the **attestation chain** so a remote verifier validates fully offline | — |
| **8** | Rotation runbook + CA-only-vs-CA+serial decision documented | — |

---

## 5. Tests — hardware-free vs hardware-gated

**HW-free (run in CI):**
- ECDSA-P256 sign/verify roundtrip with **software** P-256 keys.
- **raw `r‖s` → DER** conversion vectors (the easy-to-get-wrong bit).
- `x509` chain validation against the **checked-in attestation fixture** + negatives: wrong root
  → fail G1a; a **software-signed leaf must fail G1a** (this is the T6 test); serial not in
  allowlist → fail.
- The full **G0–G6** suite with a software-EC verifier (mirrors `seal_test.py`).
- Ceiling-policy verify with a software key (valid / expired `not_after` / wrong-key / raised-tier).

**HW-gated (run once on the token; `@needs_yubikey`, skipped in CI):**
- Real `C_Sign` roundtrip; real attestation matches the pinned root; PIN + touch behavior.

---

## 6. Threat-model deltas (what hardware buys — and what it doesn't)

- **Closes T6 (software-key impersonation):** the attestation chain proves the key is
  hardware-resident + non-exportable; a software signer cannot produce a valid attestation to the
  pinned Yubico root. *This* makes the "hardware-rooted" claim structural rather than asserted.
- **Ceiling tamper-proofing:** `max_authorized` becomes PIV-signed → can't be raised by editing
  env (closes the `#5-ceiling` residual).
- **Residual (document, do not over-claim):** PIN compromise / coerced operator → mitigated by
  touch policy + ceiling `not_after` expiry + dual-control (HOTL/BLOCK), **not** eliminated.
  Supply-chain trust bottoms out at the **pinned Yubico Root CA fingerprint** — which is exactly
  why Step 3 verifies it against a known-good reference with a checked-in test.

---

## 7. Rotation runbook

- **Seal key rotation:** generate a new on-device key (re-gen `9c` or a new slot), re-capture
  attestation, update the compiled-in verification pubkey/`key_id`, rebuild + redeploy. Keep a
  `key_id → pubkey` map so seals from the rotation window still verify (multi-key verifier).
- **Pinned Root CA fingerprint:** changes only if Yubico rotates the PIV root (rare) — update the
  compiled-in constant + the checked-in fixture test, rebuild.
- **Serial allowlist (CA+serial posture):** add/remove device serials, rebuild.

---

## 8. Dependencies / config

- **`PyKCS11`** (or `python-pkcs11`) for the token; **`cryptography`** (already a dep) for EC
  verify + `x509`; **`ykman`** for provisioning. `libykcs11` module path = the DCN tool's
  working path.
- Env: `AEGIS_SEAL_BACKEND=piv|ed25519` · `AEGIS_PIV_MODULE=/path/libykcs11.dylib` ·
  `AEGIS_PIV_SLOT=9c` · PIN via a secrets manager (not env in prod).

---

## 9. Gotchas (PIV specifics + the DCN tool's experience)

1. **Key must be GENERATED on-device** to be attestable — an imported key has no attestation.
2. **`C_Sign`(CKM_ECDSA) returns raw `r‖s`, not DER** — convert before `cryptography.verify()`.
3. macOS `libykcs11.dylib` vs Linux `.so`; the PKCS#11 module must match arch.
4. **Slot 9c requires the PIN on every signature** (PIV spec) — fine for assurance, but automated
   sealing needs the PIN available via a secrets manager + an active `C_Login` session.
5. **Touch policy `always` blocks unattended sealing** — choose per deployment.
6. PIN lockout after N failures — never brute-force in tests; use a dedicated test token.

---

## 10. Acceptance criteria (done = )

- `AEGIS_SEAL_BACKEND=piv` produces seals whose `signature.alg == "piv-ecdsa-p256"`, carrying an
  attestation chain that validates to the pinned Yubico Root CA.
- `verify_seal` accepts a genuine hardware seal and **rejects a software-EC seal at G1a** (the
  attestation test) — with the **0-violation property re-run against the real verifier**.
- `load_max_authorized()` rejects a ceiling raised in env when a PIV-signed policy is configured.
- CI stays green with **no token** (software fallback + checked-in attestation fixture); the
  hardware path is exercised once, on the token, behind `@needs_yubikey`.

_PIV_HARDWARE_SIGNER_PLAN.md — the final CROSS-3 pass; everything it plugs into already ships._
