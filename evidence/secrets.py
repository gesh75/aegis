"""Vendor-aware secret detection + redaction for network configs.

One pattern table drives two jobs:

  * ``plaintext_hits(text)``  -> labels of CLEARTEXT credentials (compliance FAIL input:
    PCI 8.3.2, DISA CISC-RT-000480/000050, HIPAA, ...). Never returns secret values.
  * ``redact(text)``          -> the same config with every secret value — cleartext,
    reversible (Cisco type 7, Junos $9$) or hashed (type 5/8/9, $1$/$6$) — replaced by
    ``<redacted>``. Used for anything that leaves the engine as an artifact (PDF / CAB /
    OSCAL), so an examiner packet never carries a usable or crackable credential.

Coverage (case-insensitive):
  Cisco IOS/XE/NX-OS/FRR : password/secret/key type 0 or bare, key-string, OSPF
                           authentication-key / message-digest-key, tacacs/radius key,
                           snmp-server community (v1/v2c communities are cleartext on
                           the wire)
  Junos (set or {} form) : authentication-key / hello-authentication-key / secret /
                           pre-shared-key ascii-text / md5 N key NOT in $9$ form,
                           snmp community
  Simulator demo markers : "plaintext", "abc123" (kept so the sim tier stays honest)

Type 7 and Junos $9$ are reversible obfuscation, NOT encryption. They are reported by
``reversible_hits`` (a separate, softer signal) and always redacted — whether they
should fail PCI 8.3.2 is a policy decision recorded in docs/STRATEGY_2026-10.md.
"""
from __future__ import annotations

import re

_F = re.IGNORECASE | re.MULTILINE
_NOT_TYPED = r"(?![0-9]\s)"                  # Cisco "<kw> 5 <hash>" / "<kw> 7 <obf>"
_NOT_J9 = r'(?!"?\$[0-9a-z]{1,2}\$)'         # Junos "$9$..." / "$1$..." / "$6$..."
_VAL = r'"?(?P<s>[^\s";]+)"?'

PLAINTEXT_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("cisco-type0-secret",
     # Junos key-chains use "key 0 secret ..." (0 = key id, not Cisco type 0)
     re.compile(r"(?<![\w-])(?:password|secret|key)\s+0\s+"
                r"(?!secret\b|start-time\b|algorithm\b|options\b)(?P<s>\S+)", _F)),
    ("cleartext-password",
     re.compile(r"(?<![\w-])password\s+" + _NOT_TYPED
                + r"(?!encryption\b|policy\b|encrypted\b|hash\b)" + _NOT_J9 + _VAL, _F)),
    ("cleartext-key-string",
     re.compile(r"(?<![\w-])key-string\s+" + _NOT_TYPED + _VAL, _F)),
    ("cleartext-ospf-key",
     re.compile(r"(?<![\w-])(?:ip\s+ospf\s+authentication-key|message-digest-key\s+\d+\s+md5)\s+"
                + _NOT_TYPED + _VAL, _F)),
    ("cleartext-aaa-server-key",
     re.compile(r"(?<![\w-])(?:tacacs-server|radius-server)\s+(?:host\s+\S+\s+)?key\s+"
                + _NOT_TYPED + _VAL, _F)),
    ("snmp-v1v2c-community",
     re.compile(r"(?<![\w-])(?:snmp-server|snmp)\s+community\s+" + _VAL, _F)),
    ("cleartext-authentication-key",
     re.compile(r"(?<![\w-])(?:hello-)?authentication-key\s+(?!encrypted\b)" + _NOT_J9 + _VAL, _F)),
    ("cleartext-secret",
     re.compile(r"(?<![\w-])secret\s+" + _NOT_TYPED + _NOT_J9 + _VAL, _F)),
    ("cleartext-psk",
     re.compile(r"(?<![\w-])ascii-text\s+" + _NOT_J9 + _VAL, _F)),
    ("cleartext-md5-key",
     re.compile(r"(?<![\w-])md5\s+\d+\s+key\s+" + _NOT_J9 + _VAL, _F)),
    ("demo-plaintext-marker", re.compile(r"(?P<s>\bplaintext\b|\babc123\b)", _F)),
]

REVERSIBLE_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("cisco-type7",
     re.compile(r"(?<![\w-])(?:password|key|key-string|md5|authentication-key)\s+7\s+(?P<s>\S+)", _F)),
    ("junos-$9$", re.compile(r'(?P<s>\$9\$[^\s";]+)', _F)),
]

# Hashes are not reversible but are crackable offline — redact, never report as a fail.
_HASH_PATTERNS: list[re.Pattern] = [
    re.compile(r"(?<![\w-])(?:password|secret)\s+[0-9]\s+(?P<s>\S+)", _F),
    re.compile(r'(?<![\w-])encrypted-password\s+' + _VAL, _F),
    re.compile(r'(?P<s>\$[0-9a-z]{1,2}\$[^\s";]+)', _F),
]

REDACTED = "<redacted>"


def plaintext_hits(text: str) -> list[str]:
    """Labels (sorted, unique) of cleartext credentials present. Values never returned."""
    t = text or ""
    return sorted({label for label, rx in PLAINTEXT_PATTERNS if rx.search(t)})


def reversible_hits(text: str) -> list[str]:
    t = text or ""
    return sorted({label for label, rx in REVERSIBLE_PATTERNS if rx.search(t)})


def _sub_group(rx: re.Pattern, text: str) -> str:
    def repl(m: re.Match) -> str:
        if m.group("s") == REDACTED:
            return m.group(0)
        a, b = m.span("s")
        base = m.start(0)
        whole = m.group(0)
        return whole[:a - base] + REDACTED + whole[b - base:]
    return rx.sub(repl, text)


def redact(text: str) -> str:
    """Replace every secret value with <redacted>. Idempotent; keeps the keyword so the
    examiner can still see THAT a credential is configured and of WHICH kind."""
    out = text or ""
    for _label, rx in REVERSIBLE_PATTERNS + PLAINTEXT_PATTERNS:
        out = _sub_group(rx, out)
    for rx in _HASH_PATTERNS:
        out = _sub_group(rx, out)
    return out
