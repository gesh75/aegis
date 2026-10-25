# Intent checks (reachability, ACL, BGP, references, firewall zones, NAT)

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
| `firewall_policy` | `deny` / `allow` | `node`, `from_zone`, `to_zone`, `dst_ips` (required); optional `src_ips`, `protocols`, `dst_ports` | Zone-to-zone policy on one firewall (Juniper SRX, Palo Alto, any zone-based config Batfish models). The flows start on **every** interface of `from_zone`. Deny and allow semantics are the same as for `reachability`. A zone with no interfaces on the node is an `error`, never a pass. |
| `nat` | `translated` / `untranslated` | `start`, `src_ip`, `dst_ip` (single IPs); `protocol` (tcp/udp/icmp, default tcp); `dst_port` (required for tcp/udp); for `translated`, at least one of `translated_src_ip`, `translated_dst_ip`, `translated_dst_port` | One concrete flow is traced through the snapshot. It must be **delivered** (ACCEPTED, DELIVERED_TO_SUBNET or EXITS_NETWORK), and its post-NAT header must match. Every ECMP trace must agree. `untranslated` means no header field may change, for example east-west traffic that must keep its real source for logging. |

### Firewall and NAT example

```json
{"intents": [
  {"id": "untrust-cannot-reach-trust", "kind": "firewall_policy", "node": "fw1",
   "from_zone": "untrust", "to_zone": "trust", "dst_ips": "10.1.0.0/24",
   "protocols": ["tcp"], "expect": "deny", "control": "PCI DSS v4.0 1.3.2"},
  {"id": "web-vip-dnat", "kind": "nat", "start": "@enter(fw1[ge-0/0/1.0])",
   "src_ip": "198.51.100.7", "dst_ip": "203.0.113.10", "protocol": "tcp", "dst_port": 443,
   "expect": "translated", "translated_dst_ip": "10.2.0.10"}
]}
```

`firewall_policy` judges **transit** traffic: a flow counts as succeeding only if it is
DELIVERED_TO_SUBNET or EXITS_NETWORK. Traffic addressed to the firewall's own interface IPs
(management/control plane) is accepted by the device and never crosses a zone policy. To
assert that exposure, write a `reachability` intent with `dst_ips` = the firewall's
addresses. This was found against real Batfish: SRX and PAN-OS both deny untrust→trust
transit, but accept a SYN to their own trust-side IP.

`to_zone` must exist on the node, otherwise the intent is an error. The egress path itself
is decided by routing toward `dst_ips`, so a deny intent fails on a leak through **any**
path, which is the conservative reading. Palo Alto zone names match with or without
Batfish's `vsys1~` prefix.

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
  - firewall zone resolution and NAT translation checks (I12, I13);
  - HTTP.
- `tests/batfish_live_test.py` runs in the CI `batfish` job against a **real**
  `batfish/allinone`. A Cisco ACL change that opens guest→CDE SSH, adds a shadowed line and
  references an undefined ACL must produce three regressions, while the allowed web flow
  stays a pass. A second fixture (`tests/fixtures/batfish/firewall`) does the same for an
  SRX set-delta and a PAN-OS full config. A temporary vendor permit (both vendors) and a
  retargeted DNAT pool must be three regressions, while trust→untrust HTTPS and both
  source-NAT intents stay a pass. Locally it skips unless `AEGIS_REQUIRE_BATFISH=1`.
