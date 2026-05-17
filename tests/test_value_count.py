from datetime import datetime, timedelta, timezone

import apache_beam as beam
from apache_beam.testing.test_pipeline import TestPipeline
from apache_beam.testing.util import assert_that, equal_to

from sigma_beam.correlation.value_count import ValueCountCorrelation
from sigma_beam.ruleset import CompiledCorrelation, CompiledRule


def _ts(s):
    return (datetime(2026, 5, 16, tzinfo=timezone.utc) + timedelta(seconds=s)).isoformat()


_REF = CompiledRule(id="R", title="x", severity="medium",
                    predicate=lambda e: e.get("type") == "conn")


def _corr(threshold, window=60):
    return CompiledCorrelation(
        id="C", title="port scan", severity="high", kind="value_count",
        referenced_rule_ids=("R",), group_by=("src",), window_seconds=window,
        threshold=threshold, threshold_op="gte", value_field="dst_port",
    )


def test_value_count_distinct_above_threshold():
    events = [
        {"type": "conn", "src": "10.0.0.1", "dst_port": p, "timestamp": _ts(i)}
        for i, p in enumerate(range(1000, 1010))   # 10 distinct ports
    ]
    with TestPipeline() as p:
        out = p | beam.Create(events) | ValueCountCorrelation(_corr(threshold=10), [_REF])
        assert_that(out | beam.Map(lambda a: a.correlation_key),
                    equal_to(["10.0.0.1"]))


def test_value_count_repeated_values_dont_count():
    # 100 events but only 3 distinct destination ports → no alert.
    events = [
        {"type": "conn", "src": "10.0.0.1", "dst_port": (i % 3), "timestamp": _ts(i % 50)}
        for i in range(100)
    ]
    with TestPipeline() as p:
        out = p | beam.Create(events) | ValueCountCorrelation(_corr(threshold=10), [_REF])
        assert_that(out | beam.Map(lambda a: a.rule_id), equal_to([]))


def test_value_count_skips_missing_value_field():
    events = [{"type": "conn", "src": "10.0.0.1", "timestamp": _ts(i)} for i in range(20)]
    with TestPipeline() as p:
        out = p | beam.Create(events) | ValueCountCorrelation(_corr(threshold=1), [_REF])
        assert_that(out | beam.Map(lambda a: a.rule_id), equal_to([]))
