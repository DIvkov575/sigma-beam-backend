from datetime import datetime, timedelta, timezone

import apache_beam as beam
from apache_beam.testing.test_pipeline import TestPipeline
from apache_beam.testing.util import assert_that, equal_to

from sigma_beam.correlation.fanout import CorrelationFanout
from sigma_beam.ruleset import CompiledCorrelation, CompiledRule, Ruleset


def _ts(s):
    return (datetime(2026, 5, 16, tzinfo=timezone.utc) + timedelta(seconds=s)).isoformat()


def test_fanout_dispatches_per_kind():
    rs = Ruleset(
        single_event=[
            CompiledRule(id="A", title="a", severity="m", predicate=lambda e: e.get("k") == "a"),
            CompiledRule(id="B", title="b", severity="m", predicate=lambda e: e.get("k") == "b"),
        ],
        correlation=[
            CompiledCorrelation(
                id="count_a", title="many a", severity="h", kind="event_count",
                referenced_rule_ids=("A",), group_by=("u",), window_seconds=60,
                threshold=3, threshold_op="gte",
            ),
            CompiledCorrelation(
                id="ab_temporal", title="a&b", severity="h", kind="temporal",
                referenced_rule_ids=("A", "B"), group_by=("u",), window_seconds=60,
            ),
        ],
    )
    events = [
        {"u": "x", "k": "a", "timestamp": _ts(1)},
        {"u": "x", "k": "a", "timestamp": _ts(2)},
        {"u": "x", "k": "a", "timestamp": _ts(3)},   # ↑ trips event_count
        {"u": "x", "k": "b", "timestamp": _ts(4)},   # together with A trips temporal
    ]
    with TestPipeline() as p:
        out = p | beam.Create(events) | CorrelationFanout(rs)
        assert_that(
            out | beam.Map(lambda a: a.rule_id),
            equal_to(["count_a", "ab_temporal"]),
        )
