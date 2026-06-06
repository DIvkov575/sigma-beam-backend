"""Windowed correlation tests using TestStream for real event-time semantics."""
import apache_beam as beam
from apache_beam.testing.test_pipeline import TestPipeline
from apache_beam.testing.test_stream import TestStream
from apache_beam.testing.util import assert_that, equal_to, is_not_empty
from apache_beam.transforms.window import TimestampedValue
from apache_beam.utils.timestamp import Timestamp

from sigma_beam.correlation.event_count import EventCountCorrelation
from sigma_beam.correlation.temporal import TemporalCorrelation
from sigma_beam.ruleset import CompiledCorrelation, CompiledRule


def _ts(epoch_s: int) -> Timestamp:
    return Timestamp(seconds=epoch_s)


def _always_true(e: dict) -> bool:
    return True


def _matches_k(k: str):
    def pred(e: dict) -> bool:
        return e.get("k") == k
    return pred


def test_event_count_fires_within_window():
    """3 events in a 60s window with threshold=3 fires."""
    corr = CompiledCorrelation(
        id="c1", title="count", severity="high", kind="event_count",
        referenced_rule_ids=("r1",), group_by=("user",),
        window_seconds=60, threshold=3, threshold_op="gte",
    )
    refs = [CompiledRule(id="r1", title="r", severity="low", predicate=_always_true)]

    ts = (
        TestStream()
        .add_elements([
            TimestampedValue({"user": "alice", "timestamp": 10}, _ts(10)),
            TimestampedValue({"user": "alice", "timestamp": 20}, _ts(20)),
            TimestampedValue({"user": "alice", "timestamp": 30}, _ts(30)),
        ])
        .advance_watermark_to_infinity()
    )

    with TestPipeline() as p:
        events = p | ts
        alerts = events | EventCountCorrelation(corr, refs)
        assert_that(alerts, is_not_empty())


def test_event_count_does_not_fire_across_windows():
    """2 events in window [0,60) + 1 in [60,120) with threshold=3 → 0 alerts."""
    corr = CompiledCorrelation(
        id="c1", title="count", severity="high", kind="event_count",
        referenced_rule_ids=("r1",), group_by=("user",),
        window_seconds=60, threshold=3, threshold_op="gte",
    )
    refs = [CompiledRule(id="r1", title="r", severity="low", predicate=_always_true)]

    ts = (
        TestStream()
        .add_elements([
            TimestampedValue({"user": "alice", "timestamp": 10}, _ts(10)),
            TimestampedValue({"user": "alice", "timestamp": 20}, _ts(20)),
        ])
        .advance_watermark_to(_ts(60))
        .add_elements([
            TimestampedValue({"user": "alice", "timestamp": 70}, _ts(70)),
        ])
        .advance_watermark_to_infinity()
    )

    with TestPipeline() as p:
        events = p | ts
        alerts = events | EventCountCorrelation(corr, refs)
        assert_that(alerts, equal_to([]))


def test_temporal_fires_when_both_rules_in_window():
    """Events matching rule A and rule B in same window → alert."""
    corr = CompiledCorrelation(
        id="c1", title="ab", severity="high", kind="temporal",
        referenced_rule_ids=("A", "B"), group_by=("user",),
        window_seconds=60,
    )
    refs = [
        CompiledRule(id="A", title="a", severity="low", predicate=_matches_k("a")),
        CompiledRule(id="B", title="b", severity="low", predicate=_matches_k("b")),
    ]

    ts = (
        TestStream()
        .add_elements([
            TimestampedValue({"user": "alice", "k": "a", "timestamp": 5}, _ts(5)),
            TimestampedValue({"user": "alice", "k": "b", "timestamp": 15}, _ts(15)),
        ])
        .advance_watermark_to_infinity()
    )

    with TestPipeline() as p:
        events = p | ts
        alerts = events | TemporalCorrelation(corr, refs)
        assert_that(alerts, is_not_empty())


def test_temporal_does_not_fire_across_window_boundary():
    """Rule A in window [0,60) and rule B in [60,120) → no alert."""
    corr = CompiledCorrelation(
        id="c1", title="ab", severity="high", kind="temporal",
        referenced_rule_ids=("A", "B"), group_by=("user",),
        window_seconds=60,
    )
    refs = [
        CompiledRule(id="A", title="a", severity="low", predicate=_matches_k("a")),
        CompiledRule(id="B", title="b", severity="low", predicate=_matches_k("b")),
    ]

    ts = (
        TestStream()
        .add_elements([
            TimestampedValue({"user": "alice", "k": "a", "timestamp": 5}, _ts(5)),
        ])
        .advance_watermark_to(_ts(60))
        .add_elements([
            TimestampedValue({"user": "alice", "k": "b", "timestamp": 65}, _ts(65)),
        ])
        .advance_watermark_to_infinity()
    )

    with TestPipeline() as p:
        events = p | ts
        alerts = events | TemporalCorrelation(corr, refs)
        assert_that(alerts, equal_to([]))
