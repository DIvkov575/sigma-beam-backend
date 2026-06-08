"""Shared helpers for correlation transforms."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import apache_beam as beam
from apache_beam.transforms.window import TimestampedValue
from apache_beam.utils.timestamp import Timestamp

from ..field_access import get_field, MISSING
from ..ruleset import CompiledCorrelation, CompiledRule, Ruleset

TIMESTAMP_FIELD_DEFAULT = "timestamp"


def parse_event_time(event: dict, field: str = TIMESTAMP_FIELD_DEFAULT) -> Timestamp:
    """Extract an event-time Timestamp. Falls back to 'now' if unparseable."""
    raw = get_field(event, field)
    if raw is MISSING or raw is None:
        return Timestamp.now()
    if isinstance(raw, (int, float)):
        return Timestamp(seconds=float(raw))
    if isinstance(raw, str):
        try:
            # Accept either ISO or `Z`-suffix UTC.
            s = raw.replace("Z", "+00:00")
            dt = datetime.fromisoformat(s)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return Timestamp.from_utc_datetime(dt.astimezone(timezone.utc))
        except ValueError:
            return Timestamp.now()
    return Timestamp.now()


def make_group_key(event: dict, group_by: tuple[str, ...]) -> str:
    """Stringified, ordered key for a group-by tuple. Returns 'MISSING' for absent fields."""
    parts = []
    for g in group_by:
        v = get_field(event, g)
        parts.append("MISSING" if v is MISSING else str(v))
    return "|".join(parts)


def passes_any_referenced_rule(event: dict, refs: list[CompiledRule]) -> bool:
    for r in refs:
        try:
            if r.predicate(event):
                return True
        except Exception:
            continue
    return False


def referenced_rules(c: CompiledCorrelation, rs: Ruleset) -> list[CompiledRule]:
    by_id = rs.rules_by_id()
    return [by_id[rid] for rid in c.referenced_rule_ids if rid in by_id]


def cmp_threshold(count: int, c: CompiledCorrelation) -> bool:
    if c.threshold_range is not None:
        lo, hi = c.threshold_range
        return lo <= count <= hi
    t = c.threshold or 0
    return {
        "gte": count >= t,
        "gt":  count >  t,
        "lte": count <= t,
        "lt":  count <  t,
        "eq":  count == t,
        "neq": count != t,
    }.get(c.threshold_op, count >= t)


def attach_event_time(event: dict, field: str = TIMESTAMP_FIELD_DEFAULT) -> TimestampedValue:
    return TimestampedValue(event, parse_event_time(event, field))
