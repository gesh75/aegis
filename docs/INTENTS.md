# Intent checks (reachability, ACL, BGP, references)

AEGIS can assert **network intents** on every change. An intent is a statement such as
"the guest VLAN can never reach the CDE" or "every ACL line is reachable". AEGIS checks
each intent against:

- the **reference** snapshot: your current device configs (before);
- the **candidate** snapshot: reference + this change (after).

The engine is [Batfish](https://batfish.org/) (Apache-2.0), running **inside your
perimeter** as the `batfish/allinone` container. AEGIS never sends configs anywhere else.

## Verdict rules (fail closed)

| Outcome | Verdict |
|---|---|
| Every intent passes | Not blocked by intents. The other gates still apply. |
| Any intent **fails** | `blocked` (risk high, severity critical, no seal) |
| Any intent **cannot be evaluated** (engine down, pybatfish missing, snapshot does not parse, vacuous header space) | `blocked`: an unchecked intent is not a pass |
| An intent passed **before** and fails **after** | `blocked`, flagged as a **regression** in the verdict, PDF, CAB and OSCAL |

The result is sealed into the bundle under `validation.intents` (bundle v1.4) and is
covered by the sha256 and the Ed25519 seal.

## Writing intents

The format is JSON, or YAML when PyYAML is installed. Unknown kinds or fields are **rejected**,
because a typo must never silently turn into "no check ran".

```json
{"intents": [
  {"id": "guest-cannot-reach-cde", "kind": "reachability",
   "start": "@enter(r1[GigabitEthernet0/1])", "src_ips": "10.50.0.0/16",
   "dst_ips": "10.10.0.0/24", "protocols": ["tcp"], "dst_ports": "22",
   "expect": "deny", "control": "PCI DSS v4.0 1.3.1"},
  {"id": "guest-can-reach-web", "kind": "reachability",
   "start": "@enter(r1[GigabitEthernet0/1])", "src_ips": "10.50.1.10",
   "dst_ips": "10.20.0.10", "protocols": ["tcp"], "dst_ports": "443", "expect": "allow"},
  {"id": "bgp-up",        "kind": "bgp_sessions",             "expect": "all_established"},
  {"id": "no-undef-refs", "kind": "undefined_references",     "expect": "none"},
  {"id": "no-dead-acl",   "kind": "filter_line_reachability", "expect": "none"}
]}
```

| Kind | `expect` | Fields | Meaning |
|---|---|---|---|
| `reachability` | `deny` | `dst_ips` (required); `start` and/or `src_ips`; optional `protocols` (tcp/udp/icmp/ip), `dst_ports` | No flow in the header space may succeed |
| `reachability` | `allow` | same | Every flow must succeed. If **no** flow matches at all, that is an `error`, never a vacuous pass. |
| `bgp_sessions` | `all_established` | optional `nodes` | Every configured BGP session is established |
| `undefined_references` | `none` | — | No reference to an undefined ACL, route-map, prefix-list and so on |
| `filter_line_reachability` | `none` | optional `nodes` | No ACL or filter line is shadowed or unreachable |

`start` is a Batfish location specifier, for example `@enter(node[interface])`. `control`
is free text that is carried into the evidence, such as a PCI requirement number.

## Supplying intents

| Source | How |
|---|---|
| Org baseline (applies to every run) | `AEGIS_INTENTS_PATH=/etc/aegis/intents.json`. Invalid at startup means the server **refuses to start**. |
| Per change | `"intents": [...]` in the `POST /api/preflight/run` body. Merged after the baseline; duplicate ids are rejected. |
| Library | `run_preflight(..., intents=parse_intents(doc))` |

## Deploying the engine (in-perimeter)

```bash
docker run -d --name batfish -p 127.0.0.1:9996:9996 batfish/allinone   # pin by digest in your mirror
pip install -r requirements-batfish.txt                                # adds pybatfish
export AEGIS_BATFISH_HOST=127.0.0.1
export AEGIS_BATFISH_SNAPSHOT_DIR=/var/lib/aegis/snapshot   # configs/<device>.cfg — nightly backup
```

| Variable | Purpose |
|---|---|
| `AEGIS_BATFISH_HOST` | Batfish service. If it's unset and intents are requested, the run is **blocked**. |
| `AEGIS_BATFISH_SNAPSHOT_DIR` | Reference snapshot that enables the before/after differential. Without it, `before` is `null`. |
| `AEGIS_BATFISH_NETWORK` | Batfish network name (default `aegis`). Snapshots are uploaded under unique names and deleted after each run. |

## How the candidate snapshot is built

| Device in change | Base file exists? | Mode | What Batfish sees |
|---|---|---|---|
| `junos`, change is `set` / `delete` lines | yes | `junos-set-merge` | The base (flattened to set form if hierarchical) plus the change lines, in order |
| any other vendor | yes | `replace` | The candidate as a **full** device config |
| any | no | `new` | The candidate as a new device file |

A partial Cisco/EOS/FRR snippet **cannot** be merged safely, because mode context is
positional. Paste the full running-config (`config_import`). If you submit a snippet anyway,
Batfish's parse-fidelity check will show a truncated config.

Fidelity gate: if any candidate file **fails** to parse, every intent becomes `error`.
Partially unrecognized lines are reported in `fidelity.issues` but do not fail the gate.
Review them, because unrecognized lines are invisible to every check.

## What this proves, and what it does not

| Proves | Does not prove |
|---|---|
| The candidate configs, as modeled by Batfish, satisfy or violate each intent | Runtime behavior (dynamic routing churn, hardware limits). The containerlab twin covers convergence. |
| Regression vs the reference snapshot | That the reference snapshot matches production (use drift detection: IP Fabric, NetBox Assurance, or AEGIS P4) |
| Results are tamper-evident and sealed | Vendor features Batfish does not model. Check `fidelity.issues`. |

## Tests

- `tests/intents_test.py` (fixture oracle, runs everywhere) covers:
  - the spec rejects unknown kinds and fields;
  - deny/allow semantics, including that a vacuous allow is an `error`;
  - the fidelity gate;
  - regressions and fail-closed behavior;
  - snapshot materialization;
  - pipeline blocking;
  - HTTP.
- `tests/batfish_live_test.py` runs in the CI `batfish` job against a **real**
  `batfish/allinone`. A Cisco ACL change that opens guest→CDE SSH, adds a shadowed line and
  references an undefined ACL must produce three regressions, while the allowed web flow
  stays a pass. Locally it skips unless `AEGIS_REQUIRE_BATFISH=1`.
