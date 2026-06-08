"""value_count: fire when ≥N distinct values of `value_field` occur within
a window, grouped by `group_by`. Caps tracked distinct values per key per
window at MAX_DISTINCT to prevent state blowup."""

from __future__ import annotations

import logging

import apache_beam as beam
from apache_beam.transforms.window import FixedWindows
from apache_beam.transforms.trigger import (
    AccumulationMode, AfterWatermark, Repeatedly,
)

from ..alerts import Alert
from ..field_access import MISSING, get_field
from ..ruleset import CompiledCorrelation, CompiledRule
from ._common import (
    attach_event_time, cmp_threshold, make_group_key,
    passes_any_referenced_rule,
)

log = logging.getLogger(__name__)
MAX_DISTINCT = 10_000


class _DistinctSet(beam.CombineFn):
    def create_accumulator(self):
        return set()

    def add_input(self, acc, val):
        if len(acc) < MAX_DISTINCT:
            acc.add(val)
        return acc

    def merge_accumulators(self, accs):
        out = set()
        for a in accs:
            out |= a
            if len(out) >= MAX_DISTINCT:
                break
        return out

    def extract_output(self, acc):
        return len(acc)


class _ToWindowedAlert(beam.DoFn):
    def __init__(self, c: CompiledCorrelation) -> None:
        self._c = c

    def process(self, element, window=beam.DoFn.WindowParam):
        key, count = element
        c = self._c
        if not cmp_threshold(count, c):
            return
        yield Alert(
            rule_id=c.id,
            rule_title=c.title,
            severity=c.severity,
            window_start=window.start.to_utc_datetime().isoformat(),
            window_end=window.end.to_utc_datetime().isoformat(),
            correlation_key=key,
            tags=list(c.tags),
        )


class ValueCountCorrelation(beam.PTransform):
    def __init__(self, c: CompiledCorrelation, refs: list[CompiledRule]) -> None:
        super().__init__()
        if not c.value_field:
            raise ValueError(f"value_count rule {c.id!r} missing value_field")
        self._c = c
        self._refs = refs

    def expand(self, pcoll):
        c = self._c
        refs = self._refs
        vf = c.value_field

        def key_and_value(e: dict):
            v = get_field(e, vf)
            return (make_group_key(e, c.group_by), v)

        return (
            pcoll
            | "Filter" >> beam.Filter(lambda e: passes_any_referenced_rule(e, refs))
            | "DropMissingValue" >> beam.Filter(lambda e: get_field(e, vf) is not MISSING)
            | "AttachTs" >> beam.Map(attach_event_time)
            | "Key" >> beam.Map(key_and_value)
            | "Window" >> beam.WindowInto(
                FixedWindows(c.window_seconds),
                allowed_lateness=c.allowed_lateness_seconds,
                trigger=Repeatedly(AfterWatermark()),
                accumulation_mode=AccumulationMode.DISCARDING,
            )
            | "DistinctCount" >> beam.CombinePerKey(_DistinctSet())
            | "Threshold" >> beam.ParDo(_ToWindowedAlert(c))
        )
