"""temporal_ordered: events matching the referenced rules must occur in
the order given in `referenced_rule_ids` (= `ordered_sequence`), all
within the same window, grouped by `group_by`.

The sequence is satisfied as a *subsequence* of the windowed events
sorted by event-time — interleaved unrelated events are fine.

Memory: per (key, window) we keep at most MAX_EVENTS_PER_KEY tagged
events. Beyond that we DROP further events for that key+window (no
alert escalation; we'd rather miss a match than OOM the worker).
"""

from __future__ import annotations

import apache_beam as beam
from apache_beam.transforms.trigger import (
    AccumulationMode, AfterWatermark, Repeatedly,
)
from apache_beam.transforms.window import FixedWindows

from ..alerts import Alert
from ..ruleset import CompiledCorrelation, CompiledRule
from ._common import attach_event_time, make_group_key, parse_event_time

MAX_EVENTS_PER_KEY = 10_000


def _safe_match(pred, event) -> bool:
    try:
        return bool(pred(event))
    except Exception:
        return False


def _is_subsequence(needle: tuple[str, ...], haystack: list[str]) -> bool:
    i = 0
    for h in haystack:
        if i < len(needle) and h == needle[i]:
            i += 1
    return i == len(needle)


class _AccumTagged(beam.CombineFn):
    """Accumulate `(event_time_seconds: float, rule_id: str)` tuples."""

    def create_accumulator(self):
        return []

    def add_input(self, acc, val):
        if len(acc) < MAX_EVENTS_PER_KEY:
            acc.append(val)
        return acc

    def merge_accumulators(self, accs):
        out = []
        for a in accs:
            out.extend(a)
            if len(out) >= MAX_EVENTS_PER_KEY:
                return out[:MAX_EVENTS_PER_KEY]
        return out

    def extract_output(self, acc):
        return acc


class _CheckSequence(beam.DoFn):
    def __init__(self, c: CompiledCorrelation) -> None:
        self._c = c

    def process(self, element, window=beam.DoFn.WindowParam):
        key, tagged = element
        tagged.sort(key=lambda t: t[0])
        ids = [t[1] for t in tagged]
        if not _is_subsequence(self._c.ordered_sequence, ids):
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


class TemporalOrderedCorrelation(beam.PTransform):
    def __init__(self, c: CompiledCorrelation, refs: list[CompiledRule]) -> None:
        super().__init__()
        if not c.ordered_sequence:
            raise ValueError(
                f"temporal_ordered rule {c.id!r} missing ordered_sequence"
            )
        self._c = c
        self._refs = refs

    def expand(self, pcoll):
        c = self._c
        refs = self._refs

        def tag_kvs(e):
            for r in refs:
                if _safe_match(r.predicate, e):
                    et = parse_event_time(e).micros / 1_000_000
                    yield (make_group_key(e, c.group_by), (et, r.id))
                    return

        return (
            pcoll
            | "AttachTs" >> beam.Map(attach_event_time)
            | "Tag" >> beam.FlatMap(tag_kvs)
            | "Window" >> beam.WindowInto(
                FixedWindows(c.window_seconds),
                allowed_lateness=c.allowed_lateness_seconds,
                trigger=Repeatedly(AfterWatermark()),
                accumulation_mode=AccumulationMode.DISCARDING,
            )
            | "Accumulate" >> beam.CombinePerKey(_AccumTagged())
            | "CheckSeq" >> beam.ParDo(_CheckSequence(c))
        )
