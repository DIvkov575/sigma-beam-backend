"""Tests for nested correlation: AlertToEvent adapter + fanout wiring."""
import pytest
import apache_beam as beam
from apache_beam.testing.test_pipeline import TestPipeline

from sigma_beam.alerts import Alert
from sigma_beam.correlation.nested import alert_to_event
from sigma_beam.correlation.fanout import CorrelationFanout
from sigma_beam.ruleset import CompiledCorrelation, CompiledRule, Ruleset


def test_alert_to_event_maps_fields():
    a = Alert(
        rule_id="corr-brute-force",
        rule_title="Brute Force",
        severity="high",
        fired_at="2026-01-01T00:00:00+00:00",
        window_start="2026-01-01T00:00:00+00:00",
        window_end="2026-01-01T00:05:00+00:00",
        correlation_key="10.0.0.1",
    )
    event = alert_to_event(a)
    assert event["rule_id"] == "corr-brute-force"
    assert event["severity"] == "high"
    assert event["timestamp"] == "2026-01-01T00:00:00+00:00"
    assert event["_sigma_beam_alert"] is True


def _always_true(e: dict) -> bool:
    return e.get("event") == "login" and e.get("status") == "failed"


def test_nested_fanout_does_not_crash():
    """Nested pipeline structure is valid — smoke test."""
    base_rule = CompiledRule(
        id="rule-failed-login", title="failed login",
        severity="low", predicate=_always_true,
    )
    child_corr = CompiledCorrelation(
        id="corr-brute-force", title="brute force", severity="high",
        kind="event_count", referenced_rule_ids=("rule-failed-login",),
        group_by=("src_ip",), window_seconds=300, threshold=2,
    )
    nested_corr = CompiledCorrelation(
        id="corr-distributed", title="distributed brute", severity="critical",
        kind="event_count", referenced_rule_ids=("corr-brute-force",),
        group_by=("correlation_key",), window_seconds=900, threshold=2,
        is_nested=True,
    )
    rs = Ruleset(
        single_event=[base_rule],
        correlation=[child_corr],
        nested_correlation=[nested_corr],
    )

    events = [
        {"event": "login", "status": "failed", "src_ip": f"10.0.0.{i}",
         "timestamp": 1000 + j}
        for i in range(3) for j in range(5)
    ]

    with TestPipeline() as p:
        pcoll = p | beam.Create(events)
        _ = pcoll | CorrelationFanout(rs)
    # No crash = success
