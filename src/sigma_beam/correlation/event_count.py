"""event_count correlation: fire when N events of the referenced rule(s)
occur within a fixed window, grouped by `group_by`."""

from __future__ import annotations

import apache_beam as beam
from apache_beam.transforms.window import FixedWindows
from apache_beam.transforms.trigger import (
    AccumulationMode, AfterWatermark, Repeatedly,
)

from ..alerts import Alert
from ..ruleset import CompiledCorrelation, CompiledRule
from ._common import (
    attach_event_time, cmp_threshold, make_group_key,
    passes_any_referenced_rule,
)


class _ToWindowedAlert(beam.DoFn):
    def __init__(self, c: CompiledCorrelation) -> None:
        self._c = c

    def process(self, element, window=beam.DoFn.WindowParam):
        key, count = element
        c = self._c
        if not cmp_threshold(count, c.threshold_op, c.threshold or 0):
            return
        yield Alert(
            rule_id=c.id,
            rule_title=c.title,
            severity=c.severity,
            window_start=window.start.to_utc_datetime().isoformat(),
            window_end=window.end.to_utc_datetime().isoformat(),
            correlation_key=key,
            matched_events=[],  # individual events not retained for count rules
        )


class EventCountCorrelation(beam.PTransform):
    def __init__(self, c: CompiledCorrelation, refs: list[CompiledRule]) -> None:
        super().__init__()
        self._c = c
        self._refs = refs

    def expand(self, pcoll):
        c = self._c
        refs = self._refs
        return (
            pcoll
            | "Filter" >> beam.Filter(lambda e: passes_any_referenced_rule(e, refs))
            | "AttachTs" >> beam.Map(attach_event_time)
            | "Key" >> beam.Map(lambda e: (make_group_key(e, c.group_by), 1))
            | "Window" >> beam.WindowInto(
                FixedWindows(c.window_seconds),
                allowed_lateness=c.allowed_lateness_seconds,
                trigger=Repeatedly(AfterWatermark()),
                accumulation_mode=AccumulationMode.DISCARDING,
            )
            | "Sum" >> beam.CombinePerKey(sum)
            | "Threshold" >> beam.ParDo(_ToWindowedAlert(c))
        )
