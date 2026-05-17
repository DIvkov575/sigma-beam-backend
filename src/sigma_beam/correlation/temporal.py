"""temporal (unordered): fire when at least one event matching EACH
referenced rule occurs within a fixed window, grouped by `group_by`.

Implementation: tag each event with the set of referenced rule ids it
matches, key by group, window into FixedWindows, combine sets per key.
Fire when the combined set covers all referenced rule ids.
"""

from __future__ import annotations

import apache_beam as beam
from apache_beam.transforms.trigger import (
    AccumulationMode, AfterWatermark, Repeatedly,
)
from apache_beam.transforms.window import FixedWindows

from ..alerts import Alert
from ..ruleset import CompiledCorrelation, CompiledRule
from ._common import attach_event_time, make_group_key


def _safe_match(pred, event) -> bool:
    try:
        return bool(pred(event))
    except Exception:
        return False


class _UnionRuleIds(beam.CombineFn):
    def create_accumulator(self):
        return frozenset()

    def add_input(self, acc, val):
        return acc | val

    def merge_accumulators(self, accs):
        out = frozenset()
        for a in accs:
            out = out | a
        return out

    def extract_output(self, acc):
        return acc


class _ToAlertIfComplete(beam.DoFn):
    def __init__(self, c: CompiledCorrelation) -> None:
        self._c = c
        self._required = frozenset(c.referenced_rule_ids)

    def process(self, element, window=beam.DoFn.WindowParam):
        key, seen = element
        if not self._required.issubset(seen):
            return
        c = self._c
        yield Alert(
            rule_id=c.id,
            rule_title=c.title,
            severity=c.severity,
            window_start=window.start.to_utc_datetime().isoformat(),
            window_end=window.end.to_utc_datetime().isoformat(),
            correlation_key=key,
        )


class TemporalCorrelation(beam.PTransform):
    def __init__(self, c: CompiledCorrelation, refs: list[CompiledRule]) -> None:
        super().__init__()
        self._c = c
        self._refs = refs

    def expand(self, pcoll):
        c = self._c
        refs = self._refs

        def to_kv(e):
            matched = frozenset(r.id for r in refs if _safe_match(r.predicate, e))
            return (make_group_key(e, c.group_by), matched) if matched else None

        return (
            pcoll
            | "AttachTs" >> beam.Map(attach_event_time)
            | "Tag" >> beam.Map(to_kv)
            | "DropEmpty" >> beam.Filter(lambda x: x is not None)
            | "Window" >> beam.WindowInto(
                FixedWindows(c.window_seconds),
                allowed_lateness=c.allowed_lateness_seconds,
                trigger=Repeatedly(AfterWatermark()),
                accumulation_mode=AccumulationMode.DISCARDING,
            )
            | "Union" >> beam.CombinePerKey(_UnionRuleIds())
            | "AlertIfComplete" >> beam.ParDo(_ToAlertIfComplete(c))
        )
