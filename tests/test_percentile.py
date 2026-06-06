import pytest
import apache_beam as beam
from apache_beam.testing.test_pipeline import TestPipeline
from apache_beam.testing.util import assert_that, is_not_empty, equal_to

from sigma_beam.correlation.percentile import PercentileCorrelation, _PercentileCombineFn
from sigma_beam.ruleset import CompiledCorrelation, CompiledRule


def _always_true(e: dict) -> bool:
    return True


def test_percentile_combine_fn():
    fn = _PercentileCombineFn(percentile=95.0)
    acc = fn.create_accumulator()
    for v in range(100):
        acc = fn.add_input(acc, float(v))
    result = fn.extract_output(acc)
    assert 93.0 <= result <= 96.0


def test_percentile_combine_fn_empty():
    fn = _PercentileCombineFn(percentile=50.0)
    assert fn.extract_output(fn.create_accumulator()) == 0.0


def test_percentile_combine_fn_merge():
    fn = _PercentileCombineFn(percentile=50.0)
    a1 = [1.0, 2.0, 3.0]
    a2 = [4.0, 5.0, 6.0]
    merged = fn.merge_accumulators([a1, a2])
    assert sorted(merged) == [1.0, 2.0, 3.0, 4.0, 5.0, 6.0]


def test_percentile_fires_when_exceeded():
    base = CompiledRule(id="r1", title="r", severity="low", predicate=_always_true)
    corr = CompiledCorrelation(
        id="corr-p95", title="high latency p95", severity="high",
        kind="percentile", referenced_rule_ids=("r1",),
        group_by=("service",), window_seconds=60,
        threshold=500, threshold_op="gte",
        percentile=95.0, percentile_field="latency_ms",
    )
    # 95 events at 100ms, 5 at 1000ms -> p95 = 1000 > 500
    events = [
        {"service": "api", "latency_ms": 100, "timestamp": 1000 + i}
        for i in range(95)
    ] + [
        {"service": "api", "latency_ms": 1000, "timestamp": 1000 + i}
        for i in range(95, 100)
    ]

    with TestPipeline() as p:
        pcoll = p | beam.Create(events)
        alerts = pcoll | PercentileCorrelation(corr, [base])
        assert_that(alerts, is_not_empty())


def test_percentile_does_not_fire_when_below():
    base = CompiledRule(id="r1", title="r", severity="low", predicate=_always_true)
    corr = CompiledCorrelation(
        id="corr-p95", title="low latency", severity="high",
        kind="percentile", referenced_rule_ids=("r1",),
        group_by=("service",), window_seconds=60,
        threshold=500, threshold_op="gte",
        percentile=95.0, percentile_field="latency_ms",
    )
    # All at 100ms -> p95 = 100 < 500
    events = [
        {"service": "api", "latency_ms": 100, "timestamp": 1000 + i}
        for i in range(100)
    ]

    with TestPipeline() as p:
        pcoll = p | beam.Create(events)
        alerts = pcoll | PercentileCorrelation(corr, [base])
        assert_that(alerts, equal_to([]))


def test_percentile_missing_field_raises():
    base = CompiledRule(id="r1", title="r", severity="low", predicate=_always_true)
    corr = CompiledCorrelation(
        id="c", title="t", severity="high",
        kind="percentile", referenced_rule_ids=("r1",),
        group_by=("x",), window_seconds=60,
        threshold=100, percentile=95.0, percentile_field=None,
    )
    with pytest.raises(ValueError, match="missing percentile_field"):
        PercentileCorrelation(corr, [base])
