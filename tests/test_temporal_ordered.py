from datetime import datetime, timedelta, timezone

import apache_beam as beam
from apache_beam.testing.test_pipeline import TestPipeline
from apache_beam.testing.util import assert_that, equal_to

from sigma_beam.correlation.temporal_ordered import TemporalOrderedCorrelation
from sigma_beam.ruleset import CompiledCorrelation, CompiledRule


def _ts(s):
    return (datetime(2026, 5, 16, tzinfo=timezone.utc) + timedelta(seconds=s)).isoformat()


_REFS = [
    CompiledRule(id="A", title="a", severity="m", predicate=lambda e: e.get("k") == "a"),
    CompiledRule(id="B", title="b", severity="m", predicate=lambda e: e.get("k") == "b"),
    CompiledRule(id="C", title="c", severity="m", predicate=lambda e: e.get("k") == "c"),
]


def _corr(seq=("A", "B", "C"), window=60):
    return CompiledCorrelation(
        id="K", title="kill chain", severity="high", kind="temporal_ordered",
        referenced_rule_ids=seq, ordered_sequence=seq,
        group_by=("u",), window_seconds=window,
    )


def test_temporal_ordered_in_order_fires():
    events = [
        {"u": "x", "k": "a", "timestamp": _ts(1)},
        {"u": "x", "k": "b", "timestamp": _ts(5)},
        {"u": "x", "k": "c", "timestamp": _ts(10)},
    ]
    with TestPipeline() as p:
        out = p | beam.Create(events) | TemporalOrderedCorrelation(_corr(), _REFS)
        assert_that(out | beam.Map(lambda a: a.correlation_key), equal_to(["x"]))


def test_temporal_ordered_wrong_order_no_alert():
    events = [
        {"u": "x", "k": "a", "timestamp": _ts(1)},
        {"u": "x", "k": "c", "timestamp": _ts(5)},
        {"u": "x", "k": "b", "timestamp": _ts(10)},
    ]
    with TestPipeline() as p:
        out = p | beam.Create(events) | TemporalOrderedCorrelation(_corr(), _REFS)
        assert_that(out | beam.Map(lambda a: a.rule_id), equal_to([]))


def test_temporal_ordered_interleaving_ok():
    # A then noise then B then noise then C → still matches.
    events = [
        {"u": "x", "k": "a", "timestamp": _ts(1)},
        {"u": "x", "k": "a", "timestamp": _ts(2)},  # extra A
        {"u": "x", "k": "b", "timestamp": _ts(3)},
        {"u": "x", "k": "a", "timestamp": _ts(4)},  # extra A
        {"u": "x", "k": "c", "timestamp": _ts(5)},
    ]
    with TestPipeline() as p:
        out = p | beam.Create(events) | TemporalOrderedCorrelation(_corr(), _REFS)
        assert_that(out | beam.Map(lambda a: a.correlation_key), equal_to(["x"]))


def test_temporal_ordered_missing_middle_no_alert():
    events = [
        {"u": "x", "k": "a", "timestamp": _ts(1)},
        {"u": "x", "k": "c", "timestamp": _ts(5)},
    ]
    with TestPipeline() as p:
        out = p | beam.Create(events) | TemporalOrderedCorrelation(_corr(), _REFS)
        assert_that(out | beam.Map(lambda a: a.rule_id), equal_to([]))


def test_temporal_ordered_across_window_no_alert():
    events = [
        {"u": "x", "k": "a", "timestamp": _ts(1)},
        {"u": "x", "k": "b", "timestamp": _ts(2)},
        {"u": "x", "k": "c", "timestamp": _ts(70)},  # next window
    ]
    with TestPipeline() as p:
        out = p | beam.Create(events) | TemporalOrderedCorrelation(_corr(window=60), _REFS)
        assert_that(out | beam.Map(lambda a: a.rule_id), equal_to([]))
