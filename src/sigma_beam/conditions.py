"""Walk a pySigma condition AST → `Callable[[dict], bool]`.

pySigma's `rule.detection.parsed_condition[0].parse()` returns a fully
resolved tree of `ConditionAND` / `ConditionOR` / `ConditionNOT` /
`ConditionFieldEqualsValueExpression` / `ConditionValueExpression`
(keyword search). Modifiers are pre-applied — `|endswith`, `|contains`,
etc. are expressed as wildcards in a `SigmaString`; `|re` becomes a
`SigmaRegularExpression`; `|cidr` becomes a `SigmaCIDRExpression`. So
this module dispatches purely on value *type*, not on modifier names.

Output predicates are total: any structural surprise (missing field,
type mismatch) yields False rather than raising. Errors during compile
do raise — we want to fail rule loading fast, not at runtime.
"""

from __future__ import annotations

import re
from typing import Any, Callable

from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionNOT,
    ConditionOR,
    ConditionValueExpression,
)
from sigma.rule import SigmaRule
from sigma.types import (
    SigmaBool,
    SigmaCasedString,
    SigmaCIDRExpression,
    SigmaCompareExpression,
    SigmaExists,
    SigmaExpansion,
    SigmaFieldReference,
    SigmaNull,
    SigmaNumber,
    SigmaRegularExpression,
    SigmaString,
    SpecialChars,
)

from .field_access import MISSING, get_field

Predicate = Callable[[dict], bool]


class UnsupportedCondition(Exception):
    """Raised when the condition AST contains a node we don't handle yet."""


# --- value matching -----------------------------------------------------

def _sigma_string_to_regex(s: SigmaString, case_insensitive: bool = True) -> re.Pattern[str]:
    """Translate a SigmaString (literal + wildcards) into an anchored regex."""
    parts = []
    for part in s.iter_parts():
        if part == SpecialChars.WILDCARD_MULTI:
            parts.append(".*")
        elif part == SpecialChars.WILDCARD_SINGLE:
            parts.append(".")
        else:
            parts.append(re.escape(part))
    flags = re.DOTALL | (re.IGNORECASE if case_insensitive else 0)
    return re.compile("^" + "".join(parts) + "$", flags)


def _stringify(v: Any) -> str | None:
    if v is MISSING or v is None:
        return None
    return v if isinstance(v, str) else str(v)


def _match_value(value: Any, field_val: Any, *, event: dict | None = None) -> bool:
    """Match a single Sigma value against an extracted field value."""
    # SigmaExists / SigmaFieldReference need to see the raw MISSING; everything
    # else takes the simple "missing == miss" shortcut, with SigmaNull as
    # the one exception (null can match absence).
    if field_val is MISSING:
        if isinstance(value, SigmaNull):
            return True
        if isinstance(value, SigmaExists):
            return value.exists is False
        if isinstance(value, SigmaExpansion):
            return any(_match_value(v, field_val, event=event) for v in value.values)
        return False

    if isinstance(value, SigmaNull):
        return field_val is None

    if isinstance(value, SigmaExists):
        return value.exists is (field_val is not MISSING)

    if isinstance(value, SigmaExpansion):
        # |windash, |base64offset|contains etc. expand into a list of values
        # that are OR-combined.
        return any(_match_value(v, field_val, event=event) for v in value.values)

    if isinstance(value, SigmaCasedString):
        return _stringify(field_val) == value.to_plain()

    if isinstance(value, SigmaString):
        if value.contains_special():
            pat = _sigma_string_to_regex(value, case_insensitive=True)
            s = _stringify(field_val)
            return s is not None and pat.match(s) is not None
        # Sigma 2 default: case-insensitive equality.
        plain = value.to_plain()
        s = _stringify(field_val)
        return s is not None and s.lower() == plain.lower()

    if isinstance(value, SigmaNumber):
        # SigmaNumber compares equal to its underlying int/float.
        try:
            return float(field_val) == float(value.number)
        except (TypeError, ValueError):
            return False

    if isinstance(value, SigmaBool):
        return field_val == value.boolean

    if isinstance(value, SigmaRegularExpression):
        flags = 0
        # pySigma exposes flags as a set of SigmaRegularExpressionFlag enums;
        # treat them defensively in case the API shifts.
        for f in getattr(value, "flags", set()) or set():
            name = getattr(f, "name", "").lower()
            if "ignorecase" in name or name == "i":
                flags |= re.IGNORECASE
            elif "multiline" in name or name == "m":
                flags |= re.MULTILINE
            elif "dotall" in name or name == "s":
                flags |= re.DOTALL
        try:
            pat = re.compile(str(value.regexp), flags)
        except re.error:
            return False
        s = _stringify(field_val)
        return s is not None and pat.search(s) is not None

    if isinstance(value, SigmaCIDRExpression):
        import ipaddress
        s = _stringify(field_val)
        if s is None:
            return False
        try:
            return ipaddress.ip_address(s) in value.network
        except ValueError:
            return False

    if isinstance(value, SigmaCompareExpression):
        target = float(value.number.number)
        try:
            n = float(field_val) if not isinstance(field_val, bool) else None
        except (TypeError, ValueError):
            return False
        if n is None:
            return False
        op = value.op.name
        return {
            "GTE": n >= target, "GT": n > target,
            "LTE": n <= target, "LT": n < target,
            "EQ":  n == target, "NEQ": n != target,
        }.get(op, False)

    if isinstance(value, SigmaFieldReference):
        if event is None:
            return False
        other = get_field(event, value.field)
        if other is MISSING:
            return False
        a, b = _stringify(field_val), _stringify(other)
        if a is None or b is None:
            return False
        # Sigma 2 fieldref default: case-insensitive.
        a, b = a.lower(), b.lower()
        if value.starts_with and value.ends_with:
            return a == b
        if value.starts_with:
            return a.startswith(b)
        if value.ends_with:
            return a.endswith(b)
        return a == b

    raise UnsupportedCondition(f"unsupported Sigma value type: {type(value).__name__}")


# --- keyword (field-less) search ---------------------------------------

def _iter_strings(obj: Any):
    """Yield every string-like leaf inside a nested event structure."""
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, (int, float, bool)):
        yield str(obj)
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from _iter_strings(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _iter_strings(v)


def _compile_keyword(value: Any) -> Predicate:
    # Real-world Sigma rules occasionally put numeric literals or booleans in
    # keyword position. Coerce to string for the equality check; only reject
    # genuinely exotic value types.
    if isinstance(value, SigmaString):
        if value.contains_special():
            pat = _sigma_string_to_regex(value)
            def p(event: dict) -> bool:
                return any(pat.match(s) for s in _iter_strings(event))
        else:
            needle = value.to_plain()
            def p(event: dict) -> bool:
                return any(needle == s for s in _iter_strings(event))
        return p
    if isinstance(value, (SigmaNumber, SigmaBool)):
        needle = str(getattr(value, "number", getattr(value, "boolean", value)))
        def p(event: dict) -> bool:
            return any(needle == s for s in _iter_strings(event))
        return p
    raise UnsupportedCondition(
        f"keyword search requires SigmaString/Number/Bool, got {type(value).__name__}"
    )


# --- AST walker --------------------------------------------------------

def _compile_node(node: Any) -> Predicate:
    if isinstance(node, ConditionAND):
        children = [_compile_node(a) for a in node.args]
        def p(e: dict) -> bool:
            return all(c(e) for c in children)
        return p

    if isinstance(node, ConditionOR):
        children = [_compile_node(a) for a in node.args]
        def p(e: dict) -> bool:
            return any(c(e) for c in children)
        return p

    if isinstance(node, ConditionNOT):
        # ConditionNOT.args is a list of one element.
        child = _compile_node(node.args[0])
        def p(e: dict) -> bool:
            return not child(e)
        return p

    if isinstance(node, ConditionFieldEqualsValueExpression):
        field = node.field
        value = node.value
        def p(e: dict) -> bool:
            fv = get_field(e, field)
            try:
                return _match_value(value, fv, event=e)
            except UnsupportedCondition:
                raise
            except Exception:
                return False
        return p

    if isinstance(node, ConditionValueExpression):
        return _compile_keyword(node.value)

    raise UnsupportedCondition(f"unsupported condition node: {type(node).__name__}")


def compile_rule(rule: SigmaRule) -> Predicate:
    """Compile a parsed `SigmaRule` into a single boolean predicate."""
    if not rule.detection.parsed_condition:
        raise UnsupportedCondition(f"rule {rule.id!r} has no parsed condition")
    if len(rule.detection.parsed_condition) > 1:
        # Multiple condition strings → OR them together.
        parts = [c.parse() for c in rule.detection.parsed_condition]
        compiled = [_compile_node(p) for p in parts]
        def p(e: dict) -> bool:
            return any(c(e) for c in compiled)
        return p
    return _compile_node(rule.detection.parsed_condition[0].parse())
