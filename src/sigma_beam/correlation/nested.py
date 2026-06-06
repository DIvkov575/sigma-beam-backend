"""Convert Alert PCollection into event-shaped dicts for nested correlation."""

from __future__ import annotations

import apache_beam as beam

from ..alerts import Alert


def alert_to_event(alert: Alert) -> dict:
    """Map an Alert to a flat event dict suitable for correlation processing."""
    return {
        "rule_id": alert.rule_id,
        "rule_title": alert.rule_title,
        "severity": alert.severity,
        "timestamp": alert.fired_at,
        "window_start": alert.window_start,
        "window_end": alert.window_end,
        "correlation_key": alert.correlation_key,
        "_sigma_beam_alert": True,
    }


class AlertsToEvents(beam.PTransform):
    """PCollection[Alert] → PCollection[dict] for nested correlation input."""

    def expand(self, pcoll):
        return pcoll | "AlertToEvent" >> beam.Map(alert_to_event)
