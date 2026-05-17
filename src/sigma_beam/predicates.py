"""Primitive value predicates.

Each predicate is a `Callable[[Any], bool]` over an extracted field value.
Predicates MUST return False (never raise) when given `MISSING`, the wrong
type, or a value that doesn't make sense for the comparison. This keeps
evaluation total — a malformed event drops out of a rule without killing
the pipeline.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any, Callable, Iterable

from .field_access import MISSING

Predicate = Callable[[Any], bool]


def _stringify(v: Any) -> str | None:
    if v is MISSING or v is None:
        return None
    return v if isinstance(v, str) else str(v)


def equals(target: Any) -> Predicate:
    def p(v: Any) -> bool:
        if v is MISSING:
            return False
        return v == target
    return p


def contains(needle: str) -> Predicate:
    def p(v: Any) -> bool:
        s = _stringify(v)
        return s is not None and needle in s
    return p


def startswith(prefix: str) -> Predicate:
    def p(v: Any) -> bool:
        s = _stringify(v)
        return s is not None and s.startswith(prefix)
    return p


def endswith(suffix: str) -> Predicate:
    def p(v: Any) -> bool:
        s = _stringify(v)
        return s is not None and s.endswith(suffix)
    return p


def re_match(pattern: str, flags: int = 0) -> Predicate:
    compiled = re.compile(pattern, flags)
    def p(v: Any) -> bool:
        s = _stringify(v)
        return s is not None and bool(compiled.search(s))
    return p


def cidr_contains(cidr: str) -> Predicate:
    net = ipaddress.ip_network(cidr, strict=False)
    def p(v: Any) -> bool:
        s = _stringify(v)
        if s is None:
            return False
        try:
            return ipaddress.ip_address(s) in net
        except ValueError:
            return False
    return p


def _numeric(v: Any) -> float | None:
    if v is MISSING or v is None or isinstance(v, bool):
        return None
    if isinstance(v, (int, float)):
        return float(v)
    if isinstance(v, str):
        try:
            return float(v)
        except ValueError:
            return None
    return None


def gt(target: float) -> Predicate:
    def p(v: Any) -> bool:
        n = _numeric(v)
        return n is not None and n > target
    return p


def gte(target: float) -> Predicate:
    def p(v: Any) -> bool:
        n = _numeric(v)
        return n is not None and n >= target
    return p


def lt(target: float) -> Predicate:
    def p(v: Any) -> bool:
        n = _numeric(v)
        return n is not None and n < target
    return p


def lte(target: float) -> Predicate:
    def p(v: Any) -> bool:
        n = _numeric(v)
        return n is not None and n <= target
    return p


def in_list(targets: Iterable[Any]) -> Predicate:
    s = set(targets)
    def p(v: Any) -> bool:
        if v is MISSING:
            return False
        try:
            return v in s
        except TypeError:
            return False
    return p


def any_of(preds: Iterable[Predicate]) -> Predicate:
    preds = list(preds)
    def p(v: Any) -> bool:
        return any(pr(v) for pr in preds)
    return p


def all_of(preds: Iterable[Predicate]) -> Predicate:
    preds = list(preds)
    def p(v: Any) -> bool:
        return all(pr(v) for pr in preds)
    return p
