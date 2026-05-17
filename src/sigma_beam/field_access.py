"""Nested-field access into event dicts.

Sigma field names may be dotted (`a.b.c`) or include numeric segments for
array indices (`logs.0.message`). Missing keys must be distinguishable
from explicit `None`, so we return a `MISSING` sentinel rather than `None`.
Predicates check identity against `MISSING` and return False without
raising.
"""

from typing import Any


class _Missing:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __repr__(self) -> str:
        return "MISSING"

    def __bool__(self) -> bool:
        return False


MISSING = _Missing()


def get_field(event: Any, path: str) -> Any:
    """Walk `path` (dot-separated) into `event`. Return MISSING on any miss.

    Numeric segments index into lists. Anything else indexes into dicts.
    Case-sensitive by design — Sigma rules specify field names exactly.
    """
    if not path:
        return MISSING
    cur: Any = event
    for segment in path.split("."):
        if isinstance(cur, dict):
            if segment not in cur:
                return MISSING
            cur = cur[segment]
        elif isinstance(cur, list):
            try:
                idx = int(segment)
            except ValueError:
                return MISSING
            if idx < 0 or idx >= len(cur):
                return MISSING
            cur = cur[idx]
        else:
            return MISSING
    return cur
