"""Compiled rule + correlation dataclasses + Ruleset container."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from .conditions import Predicate

CorrelationKind = str  # one of: event_count, value_count, temporal, temporal_ordered, percentile


@dataclass(frozen=True)
class CompiledRule:
    id: str
    title: str
    severity: str
    predicate: Predicate
    source_path: str | None = None


@dataclass(frozen=True)
class CompiledCorrelation:
    id: str
    title: str
    severity: str
    kind: CorrelationKind
    referenced_rule_ids: tuple[str, ...]
    group_by: tuple[str, ...]
    window_seconds: int
    # event_count / value_count only:
    threshold: int | None = None
    threshold_op: str = "gte"   # gte | gt | lt | lte | eq
    # value_count only:
    value_field: str | None = None
    # percentile only:
    percentile: float | None = None
    percentile_field: str | None = None
    # temporal_ordered only (sequence of rule ids):
    ordered_sequence: tuple[str, ...] = ()
    # Nested correlation flag:
    is_nested: bool = False
    # Annotations:
    allowed_lateness_seconds: int = 300
    allow_high_cardinality: bool = False
    source_path: str | None = None


@dataclass
class Ruleset:
    single_event: list[CompiledRule] = field(default_factory=list)
    correlation: list[CompiledCorrelation] = field(default_factory=list)
    nested_correlation: list[CompiledCorrelation] = field(default_factory=list)

    def rules_by_id(self) -> dict[str, CompiledRule]:
        return {r.id: r for r in self.single_event}

    def correlations_by_id(self) -> dict[str, CompiledCorrelation]:
        return {c.id: c for c in self.correlation + self.nested_correlation}
