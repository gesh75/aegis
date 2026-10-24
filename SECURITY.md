# Security policy

## Reporting a vulnerability

Please **do not open a public issue** for a security problem. Use GitHub's private
vulnerability reporting (repo → *Security* → *Report a vulnerability*). Include the
affected commit, a reproduction, and the impact you observed. We aim to acknowledge
within 3 business days.

## What AEGIS claims — and what it does not

| Claim | Backed by | Not claimed |
|---|---|---|
| Nothing leaves the perimeter | `integrity.egress: "none"`, air-gap overlay (`network_mode: none`), **air-gap on by default** (no cloud backend, loopback-only model URLs unless `AEGIS_AIRGAP=0`) | That *your* host has no other egress path; or that an operator who sets `AEGIS_AIRGAP=0` stays inside the perimeter |
| Bundle content is self-consistent | `integrity.sha256` (`evidence/bundler.py`) | Origin — anyone can recompute a sha256 |
| Bundle came from **this** AEGIS and was bounded | detached Ed25519 seal, `verify_seal` G0–G6, offline `python -m aegis.verify` | Hardware-backed key (PIV signer is planned, `docs/PIV_HARDWARE_SIGNER_PLAN.md`) |
| A second person approved | HMAC v2 token + `AEGIS_APPROVER_KEYS` identity + SoD (approver ≠ operator) | SSO/MFA identity (planned: Entra ID / OIDC) |
| Approval used once | single-use token claim in the hash-chained ledger | — |
| Audit trail is tamper-evident | `evidence/ledger.py` hash chain, `/api/ledger/verify`, off-box anchor via `AEGIS_LEDGER_SYSLOG` (RFC 5424 to your SIEM) | Tamper-proof on the AEGIS host — the SIEM/WORM copy is the anchor |
| Rollback | a vendor-aware *plan* (`verification: plan-only`) | That the reversal was executed in the twin |
| Compliance rows | deterministic config checks + process mapping for THIS change | Certification of the organization |

## Production deployment checklist

Set `AEGIS_MODE=production`. The server then **refuses to start** unless all of these are set,
and it enforces the stricter request-time rules listed below.

| Variable | Purpose | Generate |
|---|---|---|
| `AEGIS_API_KEY` | `X-Aegis-Key` on every mutating route | `python -c "import secrets;print(secrets.token_urlsafe(32))"` |
| `AEGIS_APPROVE_KEY` | HMAC key for approval tokens (≥16 bytes) | `python -c "import secrets;print(secrets.token_hex(32))"` |
| `AEGIS_SEAL_KEY` | Ed25519 seed (64 hex), pinned seal key | `python -c "import secrets;print(secrets.token_hex(32))"` |
| `AEGIS_LEDGER_PATH` | append-only audit ledger on a persistent volume | e.g. `/var/lib/aegis/ledger.jsonl` |
| `AEGIS_APPROVER_KEYS` | `name:sha256(credential)` per approver | `python -m aegis.core.promote.approvers alice@corp` |
| `AEGIS_CHANGE_REF_PATTERN` *(optional)* | pin your ITSM numbering | e.g. `^CHG[0-9]{7}$` |
| `AEGIS_LEDGER_SYSLOG` *(recommended)* | send every ledger entry to the SIEM (`host:port[/tcp\|/udp]`) | e.g. `127.0.0.1:514/tcp` to a local rsyslog relay that forwards over TLS. The sink itself sends plain TCP/UDP, not RFC 5425 TLS. |
| `AEGIS_PEER_AS_POLICY` *(optional)* | `block` (default) or `hitl` for BGP neighbor adds | decision D1 in the strategy doc |

Production request-time rules:

- Every run needs a `change_ref`.
- A run-time `approver` is rejected, because approval only happens at promotion.
- `asserted-unverified` approvals are denied.
- Only v2 (bundle-bound) tokens can be minted.
- Exports and promotion require a valid seal. Blocked-verdict evidence is the one exception: it stays exportable and is labelled UNSEALED.
- Internal errors are never returned to clients.

Keys belong in your secrets manager / KMS (One Call IS-022P: RBAC on key access, rotation
at least every 3 years, annual preferred) — inject them at runtime, never bake them into the
image or commit them. Rotating `AEGIS_SEAL_KEY` changes the `key_id`; publish the new public
key (`GET /api/seal/pubkey`) to auditors through the key-ceremony record before switching.

Network: publish on loopback only (compose default) behind a TLS-terminating reverse proxy
with your SSO in front. The container runs as UID 10001, read-only root FS, all
capabilities dropped, `no-new-privileges`.

## Supply chain

- Every GitHub Action is pinned to a commit SHA, and the workflow token is `contents: read`.
- CI runs 15 test suites, Bandit SAST (high severity gates the build), pip-audit (any known CVE in a runtime dependency gates the build), and a container smoke test that also asserts the server runs as a non-root user.
- Dependabot watches pip, GitHub Actions and the base image.
- Runtime and dev dependencies are split (`requirements.txt` / `requirements-dev.txt`). No test tooling ships in the image.
