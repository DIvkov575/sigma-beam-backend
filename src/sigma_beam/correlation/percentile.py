"""percentile correlation: fire when the Nth percentile of a field's values
exceeds a threshold within a window, grouped by `group_by`.

Uses a sorted-list accumulator capped at MAX_SAMPLES per key per window.
"""

from __future__ import annotations

import math

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

MAX_SAMPLES = 50_000


class _PercentileCombineFn(beam.CombineFn):
    def __init__(self, percentile: float) -> None:
        self._percentile = percentile

    def create_accumulator(self):
        return []

    def add_input(self, acc: list, val: float):
        if len(acc) < MAX_SAMPLES:
            acc.append(val)
        return acc

    def merge_accumulators(self, accs):
        out: list = []
        for a in accs:
            out.extend(a)
            if len(out) >= MAX_SAMPLES:
                return out[:MAX_SAMPLES]
        return out

    def extract_output(self, acc: list) -> float:
        if not acc:
            return 0.0
        acc.sort()
        k = (self._percentile / 100.0) * (len(acc) - 1)
        f = math.floor(k)
        c = math.ceil(k)
        if f == c:
            return acc[int(k)]
        return acc[f] * (c - k) + acc[c] * (k - f)


class _ToWindowedAlert(beam.DoFn):
    def __init__(self, c: CompiledCorrelation) -> None:
        self._c = c

    def process(self, element, window=beam.DoFn.WindowParam):
        key, pval = element
        c = self._c
        if not cmp_threshold(pval, c.threshold_op, c.threshold or 0):
            return
        yield Alert(
            rule_id=c.id,
            rule_title=c.title,
            severity=c.severity,
            window_start=window.start.to_utc_datetime().isoformat(),
            window_end=window.end.to_utc_datetime().isoformat(),
            correlation_key=key,
            matched_events=[],
        )


class PercentileCorrelation(beam.PTransform):
    def __init__(self, c: CompiledCorrelation, refs: list[CompiledRule]) -> None:
        super().__init__()
        if not c.percentile_field:
            raise ValueError(f"percentile rule {c.id!r} missing percentile_field")
        if c.percentile is None:
            raise ValueError(f"percentile rule {c.id!r} missing percentile value")
        self._c = c
        self._refs = refs

    def expand(self, pcoll):
        c = self._c
        refs = self._refs
        pf = c.percentile_field

        def extract_value(e: dict) -> float:
            return float(get_field(e, pf))

        return (
            pcoll
            | "Filter" >> beam.Filter(lambda e: passes_any_referenced_rule(e, refs))
            | "DropMissing" >> beam.Filter(lambda e: get_field(e, pf) is not MISSING)
            | "AttachTs" >> beam.Map(attach_event_time)
            | "Key" >> beam.Map(lambda e: (make_group_key(e, c.group_by), extract_value(e)))
            | "Window" >> beam.WindowInto(
                FixedWindows(c.window_seconds),
                allowed_lateness=c.allowed_lateness_seconds,
                trigger=Repeatedly(AfterWatermark()),
                accumulation_mode=AccumulationMode.DISCARDING,
            )
            | "Percentile" >> beam.CombinePerKey(_PercentileCombineFn(c.percentile))
            | "Threshold" >> beam.ParDo(_ToWindowedAlert(c))
        )
