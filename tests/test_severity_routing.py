"""Severity routing via Pub/Sub message attributes.

Production sinks tag alerts with `severity` + `rule_id` attributes so
subscribers can filter natively (`attributes.severity = "critical"`).
"""

from __future__ import annotations

import apache_beam as beam
from apache_beam.testing.test_pipeline import TestPipeline
from apache_beam.testing.util import assert_that, equal_to

from sigma_beam.alerts import Alert
from sigma_beam.correlation_pipeline import _AlertToPubsubMessage


def test_alert_to_pubsub_message_tags_attributes():
    alerts = [
        Alert(rule_id="rA", rule_title="t1", severity="critical",
              correlation_key="alice"),
        Alert(rule_id="rB", rule_title="t2", severity="medium"),
    ]
    with TestPipeline() as p:
        out = (
            p
            | beam.Create(alerts)
            | beam.ParDo(_AlertToPubsubMessage())
            | beam.Map(lambda m: (m.attributes.get("severity"),
                                  m.attributes.get("rule_id")))
        )
        assert_that(
            out,
            equal_to([("critical", "rA"), ("medium", "rB")]),
        )


def test_alert_to_pubsub_message_data_round_trips():
    import json
    alert = Alert(rule_id="r", rule_title="t", severity="high",
                  correlation_key="alice", tags=["attack.t1059"])
    with TestPipeline() as p:
        out = (
            p
            | beam.Create([alert])
            | beam.ParDo(_AlertToPubsubMessage())
            | beam.Map(lambda m: json.loads(m.data.decode("utf-8"))["rule_id"])
        )
        assert_that(out, equal_to(["r"]))
