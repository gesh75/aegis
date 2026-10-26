# Firewall / NAT live fixture

These files are used by `tests/batfish_live_test.py` (F1–F4) against a real `batfish/allinone`.

| Device | Vendor | Reference | Change |
|---|---|---|---|
| `fw1` | Juniper SRX (set format) | trust/untrust/dmz zones; trust→untrust permit with interface source NAT; web VIP `203.0.113.10` destination-NAT to `10.2.0.10`; untrust→dmz HTTPS only | `candidate_fw1.set` is a **set delta** (junos-set-merge). It adds an untrust→trust `permit any`, and the web pool moves to `10.2.0.99`. |
| `fw2` | Palo Alto PAN-OS (set format) | trust/untrust/dmz zones; trust→untrust allow with dynamic-ip-and-port source NAT to `198.51.100.1` | `candidate_fw2.cfg` is the **full config** (replace). It adds an untrust→trust `allow any` rule. |

Expected results:

- **Regressions (3):** both untrust→trust deny intents, and the SRX web VIP destination NAT
  (it now lands on `10.2.0.99`).
- **Still pass:** the SRX trust→untrust HTTPS allow, and both source-NAT intents.

All addresses are RFC 5737 / RFC 1918 documentation ranges.
