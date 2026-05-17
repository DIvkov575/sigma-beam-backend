from datetime import datetime, timedelta, timezone

import apache_beam as beam
from apache_beam.testing.test_pipeline import TestPipeline
from apache_beam.testing.util import assert_that, equal_to

from sigma_beam.correlation.temporal import TemporalCorrelation
from sigma_beam.ruleset import CompiledCorrelation, CompiledRule


def _ts(s):
    return (datetime(2026, 5, 16, tzinfo=timezone.utc) + timedelta(seconds=s)).isoformat()


_REFS = [
    CompiledRule(id="A", title="a", severity="m", predicate=lambda e: e.get("k") == "a"),
    CompiledRule(id="B", title="b", severity="m", predicate=lambda e: e.get("k") == "b"),
]


def _corr(window: int = 60):
    return CompiledCorrelation(
        id="C", title="ab", severity="high", kind="temporal",
        referenced_rule_ids=("A", "B"),
        group_by=("u",), window_seconds=window,
    )


def test_temporal_both_within_window_fires():
    events = [
        {"u": "alice", "k": "a", "timestamp": _ts(1)},
        {"u": "alice", "k": "b", "timestamp": _ts(5)},
    ]
    with TestPipeline() as p:
        out = p | beam.Create(events) | TemporalCorrelation(_corr(60), _REFS)
        assert_that(out | beam.Map(lambda a: a.correlation_key), equal_to(["alice"]))


def test_temporal_only_one_rule_does_not_fire():
    events = [{"u": "alice", "k": "a", "timestamp": _ts(1)}]
    with TestPipeline() as p:
        out = p | beam.Create(events) | TemporalCorrelation(_corr(60), _REFS)
        assert_that(out | beam.Map(lambda a: a.rule_id), equal_to([]))


def test_temporal_across_window_boundary_does_not_fire():
    # A at t=1 (window 0-60), B at t=65 (window 60-120) → neither window has both.
    events = [
        {"u": "alice", "k": "a", "timestamp": _ts(1)},
        {"u": "alice", "k": "b", "timestamp": _ts(65)},
    ]
    with TestPipeline() as p:
        out = p | beam.Create(events) | TemporalCorrelation(_corr(60), _REFS)
        assert_that(out | beam.Map(lambda a: a.rule_id), equal_to([]))


def test_temporal_groups_independently():
    events = [
        {"u": "alice", "k": "a", "timestamp": _ts(1)},
        {"u": "alice", "k": "b", "timestamp": _ts(2)},
        {"u": "bob",   "k": "a", "timestamp": _ts(3)},
    ]
    with TestPipeline() as p:
        out = p | beam.Create(events) | TemporalCorrelation(_corr(60), _REFS)
        assert_that(out | beam.Map(lambda a: a.correlation_key), equal_to(["alice"]))
