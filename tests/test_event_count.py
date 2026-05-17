from datetime import datetime, timezone

import apache_beam as beam
from apache_beam.testing.test_pipeline import TestPipeline
from apache_beam.testing.util import assert_that, equal_to

from sigma_beam.correlation.event_count import EventCountCorrelation
from sigma_beam.ruleset import CompiledCorrelation, CompiledRule


def _ts(s: int) -> str:
    base = datetime(2026, 5, 16, 0, 0, 0, tzinfo=timezone.utc)
    from datetime import timedelta
    return (base + timedelta(seconds=s)).isoformat()


def _ref_rule():
    return CompiledRule(id="R", title="failed", severity="medium",
                        predicate=lambda e: e.get("type") == "failed_login")


def _corr(threshold: int = 5, window: int = 60):
    return CompiledCorrelation(
        id="C", title="brute force", severity="high", kind="event_count",
        referenced_rule_ids=("R",), group_by=("user",), window_seconds=window,
        threshold=threshold, threshold_op="gte",
    )


def test_event_count_fires_when_threshold_met():
    events = [
        {"type": "failed_login", "user": "alice", "timestamp": _ts(i)}
        for i in range(5)
    ] + [{"type": "noise", "user": "alice", "timestamp": _ts(10)}]

    with TestPipeline() as p:
        out = (
            p
            | beam.Create(events)
            | EventCountCorrelation(_corr(threshold=5, window=60), [_ref_rule()])
        )
        assert_that(
            out | beam.Map(lambda a: (a.rule_id, a.correlation_key)),
            equal_to([("C", "alice")]),
        )


def test_event_count_below_threshold_does_not_fire():
    events = [
        {"type": "failed_login", "user": "alice", "timestamp": _ts(i)}
        for i in range(4)
    ]
    with TestPipeline() as p:
        out = (
            p
            | beam.Create(events)
            | EventCountCorrelation(_corr(threshold=5, window=60), [_ref_rule()])
        )
        assert_that(out | beam.Map(lambda a: a.rule_id), equal_to([]))


def test_event_count_groups_independently_per_key():
    events = (
        [{"type": "failed_login", "user": "alice", "timestamp": _ts(i)} for i in range(5)]
        + [{"type": "failed_login", "user": "bob",   "timestamp": _ts(i)} for i in range(3)]
    )
    with TestPipeline() as p:
        out = (
            p
            | beam.Create(events)
            | EventCountCorrelation(_corr(threshold=5, window=60), [_ref_rule()])
        )
        assert_that(
            out | beam.Map(lambda a: a.correlation_key),
            equal_to(["alice"]),
        )


def test_event_count_window_boundary():
    # 4 events in window 0-60, 4 events in window 60-120 → neither hits 5.
    events = (
        [{"type": "failed_login", "user": "alice", "timestamp": _ts(i)} for i in (1, 2, 3, 4)]
        + [{"type": "failed_login", "user": "alice", "timestamp": _ts(i)} for i in (61, 62, 63, 64)]
    )
    with TestPipeline() as p:
        out = (
            p
            | beam.Create(events)
            | EventCountCorrelation(_corr(threshold=5, window=60), [_ref_rule()])
        )
        assert_that(out | beam.Map(lambda a: a.rule_id), equal_to([]))
