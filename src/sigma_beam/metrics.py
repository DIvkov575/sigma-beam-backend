"""Beam metrics helpers — per-rule counters land in Cloud Monitoring."""

from __future__ import annotations

from apache_beam import metrics

_NAMESPACE = "sigma_beam"


def matches(rule_id: str):
    return metrics.Metrics.counter(_NAMESPACE, f"matches_{rule_id}")


def errors(rule_id: str):
    return metrics.Metrics.counter(_NAMESPACE, f"errors_{rule_id}")


def evaluated():
    return metrics.Metrics.counter(_NAMESPACE, "evaluated")


def dlq():
    return metrics.Metrics.counter(_NAMESPACE, "dlq")
