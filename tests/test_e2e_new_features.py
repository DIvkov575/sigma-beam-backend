"""End-to-end tests for expand, nested correlation, and percentile on DirectRunner."""

from pathlib import Path
import tempfile

import apache_beam as beam
from apache_beam.testing.test_pipeline import TestPipeline
from apache_beam.testing.util import assert_that, is_not_empty

from sigma_beam.correlation.fanout import CorrelationFanout
from sigma_beam.loader import load_from_dir
from sigma_beam.single_event import SingleEventDetect, MAIN


def test_e2e_expand_placeholder():
    with tempfile.TemporaryDirectory() as td:
        (Path(td) / "rule.yml").write_text("""
title: admin action
id: 00000000-0000-0000-0000-000000000001
logsource: {product: app}
detection:
    sel:
        User|expand: '%admins%'
        action: delete
    condition: sel
level: high
""")
        rs = load_from_dir(td, placeholders={"admins": ["root", "admin"]})

    events = [
        {"User": "root", "action": "delete"},
        {"User": "nobody", "action": "delete"},
        {"User": "admin", "action": "read"},
    ]
    with TestPipeline() as p:
        pcoll = p | beam.Create(events)
        results = pcoll | SingleEventDetect(rs.single_event)
        assert_that(results[MAIN], is_not_empty())


def test_e2e_percentile_correlation():
    with tempfile.TemporaryDirectory() as td:
        (Path(td) / "rules.yml").write_text("""
---
title: any req
id: 00000000-0000-0000-0000-000000000002
logsource: {product: app}
detection:
    sel: {type: request}
    condition: sel
level: low
---
title: p99 latency
id: 00000000-0000-0000-0000-000000000003
status: test
level: critical
correlation:
    type: event_count
    rules:
        - 00000000-0000-0000-0000-000000000002
    group-by: [svc]
    timespan: 1m
    condition:
        gte: 1000
beaver:
    percentile: 99.0
    percentile_field: ms
""")
        rs = load_from_dir(td)

    # 99 events at 100ms, 1 at 5000ms -> p99 ~ 5000 > 1000
    events = [
        {"type": "request", "svc": "api", "ms": 100, "timestamp": 1000 + i}
        for i in range(99)
    ] + [{"type": "request", "svc": "api", "ms": 5000, "timestamp": 1099}]

    with TestPipeline() as p:
        pcoll = p | beam.Create(events)
        alerts = pcoll | CorrelationFanout(rs)
        assert_that(alerts, is_not_empty())
