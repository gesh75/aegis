# AEGIS — Go-Live Runbook

How to run a **real** PreFlight (real LLM config-gen + a real containerlab twin), and how to
read the result. Sim mode needs none of this; this is only for `mode: live`.

> **Where live is easy:** on **Linux**, `containerlab` is a native binary, so twin spawn is
> a plain subprocess and "just works". On **macOS** there is no host clab binary — it runs
> as a Docker image, which AEGIS supports but with Docker-Desktop caveats (below). AEGIS's
> real deployment target is Linux; treat macOS live as a dev convenience.

---

## 0. Prerequisites

| Need | Linux target (recommended) | macOS dev laptop |
|---|---|---|
| Docker | running | Docker Desktop running |
| containerlab | native binary on PATH (`containerlab version`) | none — uses `ghcr.io/srl-labs/clab` image |
| LLM | an OpenAI-compatible endpoint (Ollama / Qwen3 runner) | same (Ollama `:11434`, gemma4 works) |
| RAM | enough for the lab (`minimal` ≈5 GB, `clos-evpn` ≈15 GB) | same |

Confirm the LLM first — this is the most common live failure:
```bash
curl -s localhost:11434/v1/chat/completions -H "Content-Type: application/json" \
  -d '{"model":"gemma4:latest","messages":[{"role":"user","content":"hi"}],"stream":false}'
```
A JSON completion = good. Anything else → fix the LLM before going further.

---

## 1. Environment

AEGIS live mode is fully env-driven. Set what applies, then (re)start the server.

```bash
# LLM (defaults already match a stock Ollama + gemma4)
export AEGIS_LLM_URL=http://localhost:11434       # OpenAI-compat /v1
export AEGIS_LLM_MODEL=gemma4:latest
# Air-gap: refuse cloud + any non-loopback URL (including host.local / mDNS)
# export AEGIS_AIRGAP=1
# Optional: sha256 the served weights into change.model_identity
# export AEGIS_LLM_WEIGHTS=/path/to/model.gguf

# Autonomy ceiling (default HOTL). Invalid values refuse to load; BLOCK is rejected.
# export AEGIS_MAX_AUTHORIZED_TIER=HOTL

# Seal: 64 hex chars pins a stable Ed25519 seed. Invalid key = process exits.
# Missing key = ephemeral demo key (receipts do not survive restart).
# export AEGIS_SEAL_KEY=<64-hex-private-seed>

# containerlab — Linux native binary:
export AEGIS_CLAB_MODE=binary
export AEGIS_CLAB_BIN=$(which containerlab)
export AEGIS_CLAB_SUDO=1                           # if clab needs root (set up sudoers, below)

# containerlab — macOS Docker image (auto-detected when no host binary):
export AEGIS_CLAB_MODE=docker
export AEGIS_CLAB_IMAGE=ghcr.io/srl-labs/clab:latest
export AEGIS_DOCKER_SOCK=$HOME/.docker/run/docker.sock   # from `docker context ls`
```

Passwordless sudo for clab (Linux, if it needs root):
```bash
echo "$(whoami) ALL=(root) NOPASSWD: $(which containerlab)" | sudo tee /etc/sudoers.d/aegis-clab
```

Restart the server so it picks up the env + any code change (background it):
```bash
lsof -ti tcp:5757 | xargs kill -9 2>/dev/null
nohup python3 app.py > /tmp/dcn5757.log 2>&1 &
```
Confirm: `grep AEGIS /tmp/dcn5757.log` shows `Preflight registered`.

---

## 2. Pre-flight the prerequisites (isolate before the full run)

Run these three in order — each isolates one dependency so a failure is unambiguous:

```bash
# A) twin spawn (isolates containerlab + Docker). Start with the cheap lab.
curl -s -X POST localhost:5757/api/preflight/twin/spawn \
  -H "Content-Type: application/json" -d '{"lab":"minimal"}'
#   {"twin_id":"twin-minimal-…","nodes":[…],"status":"deployed"}  -> good
#   {"error":"FileNotFoundError: …containerlab"}                  -> set AEGIS_CLAB_BIN / mode
#   {"error":"clab deploy failed: …"}                             -> the … is the exact cause

# clean it up
curl -s -X POST localhost:5757/api/preflight/twin/destroy \
  -H "Content-Type: application/json" -d '{"twin_id":"twin-minimal-…"}'

# B) LLM (isolates config-gen) — see §0.
```

Only when A returns a `twin_id` and B returns a completion should you run the full loop.

---

## 3. Full live run

UI: open `http://localhost:5757/preflight`, set **mode = live**, **lab = minimal**, run.
Or curl:
```bash
curl -s -X POST localhost:5757/api/preflight/run \
  -H "Content-Type: application/json" \
  -d '{"intent":"add vlan 40 to leaf1","lab":"minimal","mode":"live","frameworks":["pci_dss_v4"]}' \
  | jq '{verdict,twin}'
```

A throwaway twin (`clab-twin-minimal-…`) spawns alongside your prod lab — isolated by a
unique name + mgmt network + `10.x` subnet, so it never collides. It is destroyed in a
`finally`, even on error.

### What good looks like
- `verdict.decision` = `ship_ready` / `needs_approval` / `blocked` (all are "working")
- `twin.converged` = true, sensible `convergence_sec`
- `twin.bgp_sessions.after >= before` (a drop → the change broke BGP in the twin → blocked)
- evidence PDF downloads and shows `egress: none`

### Failure triage (the verdict card / JSON now names the cause)
| Symptom | Cause | Fix |
|---|---|---|
| `stage: guard` | empty/oversized/injection intent, or config_import with no config | fix the input |
| `502 … URLError` | LLM endpoint unreachable | check `AEGIS_LLM_URL`, §0 curl |
| `AEGIS_AIRGAP=1: non-loopback egress forbidden` | LLM URL is not loopback | use `http://127.0.0.1:…` or `http://localhost:…` — not a LAN IP, not `*.local` |
| `generation_failed` | LLM returned non-JSON | fix the model / prompt; AEGIS will **not** synthesize a passing stub |
| `AEGIS_SEAL_KEY invalid … refusing to start` | pinned seal key is not 64 hex | unset for demo, or supply a valid seed |
| `no-self-escalation` / promote 403 | required authority > ceiling, or AS/RD/RT | expected — fabric-identity is never auto-promotable |
| `422` on evidence PDF | bundle hash does not match content | re-run PreFlight; do not edit a sealed bundle |
| `502 … clab deploy failed` | twin couldn't deploy | the message has the reason (RAM, image, sudo) |
| `exec: "deploy": not found` | wrong docker image cmd | already fixed — pull latest; clab cmd names the binary |
| twin spawns but `converged:false` | the change itself breaks convergence | that's a real BLOCKED — working as intended |
| IPv6 fabric looks down in the twin | old parser ignored v6 peer rows | current `parse_nornir_bgp` counts IPv4 and IPv6 `show bgp summary` rows |

Logs: `tail -f /tmp/dcn5757.log`. Stuck twins: `docker ps | grep clab-twin-` then
`POST /api/preflight/twin/destroy`.

---

## 4. Scaling up
Once `minimal` is green, repeat with `lab: clos-evpn` (≈15 nodes / ≈15 GB). Same loop,
bigger fabric. On a Linux host with the native binary this is the production path.
