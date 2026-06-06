from sigma_beam.ruleset import CompiledCorrelation, CompiledRule, Ruleset


def test_ruleset_has_nested_correlation_list():
    rs = Ruleset()
    assert hasattr(rs, "nested_correlation")
    assert rs.nested_correlation == []


def test_correlations_by_id():
    c1 = CompiledCorrelation(
        id="corr-1", title="c1", severity="high", kind="event_count",
        referenced_rule_ids=("r1",), group_by=("user",),
        window_seconds=60, threshold=5,
    )
    rs = Ruleset(correlation=[c1])
    by_id = rs.correlations_by_id()
    assert by_id["corr-1"] is c1


def test_compiled_correlation_has_percentile_fields():
    c = CompiledCorrelation(
        id="c1", title="t", severity="high", kind="percentile",
        referenced_rule_ids=("r1",), group_by=("svc",),
        window_seconds=60, threshold=500,
        percentile=95.0, percentile_field="latency_ms",
    )
    assert c.percentile == 95.0
    assert c.percentile_field == "latency_ms"


def test_compiled_correlation_has_is_nested():
    c = CompiledCorrelation(
        id="c1", title="t", severity="high", kind="event_count",
        referenced_rule_ids=("corr-x",), group_by=("user",),
        window_seconds=60, threshold=3, is_nested=True,
    )
    assert c.is_nested is True
