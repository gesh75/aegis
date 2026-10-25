"""core/intents/ — declarative network intent checks (reachability, ACL, BGP, references).

Intents are versioned next to the configs (JSON, or YAML when PyYAML is installed) and are
evaluated against the REFERENCE snapshot (before) and the CANDIDATE snapshot (after) by an
oracle — Batfish in production (`batfish_oracle.py`), a fixture oracle in tests. Results are
differential (pass→fail is a regression) and fail closed: an intent that cannot be evaluated
blocks the change. See docs/INTENTS.md.
"""
from __future__ import annotations

from .engine import IntentOracle, OracleError, check_intents, evaluate
from .spec import IntentSpecError, load_intents, parse_intents

__all__ = ["IntentOracle", "OracleError", "IntentSpecError", "check_intents", "evaluate",
           "load_intents", "parse_intents"]
