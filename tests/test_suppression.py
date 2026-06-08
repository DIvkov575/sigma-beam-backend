"""Per-correlation alert suppression via beaver.suppress_window_seconds."""

from __future__ import annotations

import json
import textwrap
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import apache_beam as beam
from apache_beam.testing.test_pipeline import TestPipeline

from sigma_beam.alerts import Alert
from sigma_beam.correlation.suppression import Suppress
from sigma_beam.correlation_pipeline import build_pipeline
from sigma_beam.loader import load_from_dir


def _iso(off_s: int) -> str:
    return (datetime(2026, 5, 18, tzinfo=timezone.utc) + timedelta(seconds=off_s)).isoformat()


class _FileSink(beam.PTransform):
    def __init__(self, p): super().__init__(); self.p = str(p)
    def expand(self, c):
        return (c | beam.Map(lambda b: b.decode("utf-8"))
                  | beam.io.WriteToText(self.p, num_shards=1, shard_name_template=""))


def _read(path) -> list[dict]:
    p = Path(path)
    return [json.loads(l) for l in p.read_text().splitlines() if l.strip()] if p.exists() else []


# ---------------------------------------------------------------------------
# Unit-level: Suppress PTransform in isolation
# ---------------------------------------------------------------------------

def test_suppress_drops_duplicates_within_window(tmp_path):
    """Two alerts for the same key within the suppression window → one survives."""
    alerts = [
        Alert(rule_id="r", rule_title="t", severity="high", correlation_key="alice"),
        Alert(rule_id="r", rule_title="t", severity="high", correlation_key="alice"),
    ]
    out_path = tmp_path / "out.jsonl"
    with TestPipeline() as p:
        (p | beam.Create(alerts)
           | Suppress(suppress_seconds=3600)
           | beam.Map(lambda a: a.to_bytes())
           | _FileSink(out_path))
    survivors = _read(out_path)
    assert len(survivors) == 1


def test_suppress_lets_different_keys_through(tmp_path):
    alerts = [
        Alert(rule_id="r", rule_title="t", severity="high", correlation_key="alice"),
        Alert(rule_id="r", rule_title="t", severity="high", correlation_key="bob"),
        Alert(rule_id="r", rule_title="t", severity="high", correlation_key="charlie"),
    ]
    out_path = tmp_path / "out.jsonl"
    with TestPipeline() as p:
        (p | beam.Create(alerts)
           | Suppress(suppress_seconds=3600)
           | beam.Map(lambda a: a.to_bytes())
           | _FileSink(out_path))
    survivors = _read(out_path)
    assert sorted(s["correlation_key"] for s in survivors) == ["alice", "bob", "charlie"]


def test_suppress_zero_is_passthrough(tmp_path):
    alerts = [
        Alert(rule_id="r", rule_title="t", severity="high", correlation_key="alice"),
        Alert(rule_id="r", rule_title="t", severity="high", correlation_key="alice"),
    ]
    out_path = tmp_path / "out.jsonl"
    with TestPipeline() as p:
        (p | beam.Create(alerts)
           | Suppress(suppress_seconds=0)
           | beam.Map(lambda a: a.to_bytes())
           | _FileSink(out_path))
    assert len(_read(out_path)) == 2


# ---------------------------------------------------------------------------
# Integration: end-to-end with a correlation rule carrying the annotation
# ---------------------------------------------------------------------------

def test_e2e_suppression_on_event_count_correlation(tmp_path):
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "base.yml").write_text(textwrap.dedent("""
        title: failed login
        id: 11111111-1111-1111-1111-111111111111
        status: test
        logsource: {product: windows}
        detection:
            sel: {EventID: 4625}
            condition: sel
    """).strip())
    (rules / "corr.yml").write_text(textwrap.dedent("""
        title: brute force, suppress 1h
        id: 22222222-2222-2222-2222-222222222222
        status: test
        correlation:
            type: event_count
            rules: [11111111-1111-1111-1111-111111111111]
            group-by: [User]
            timespan: 1m
            condition: {gte: 3}
        beaver:
            suppress_window_seconds: 3600
    """).strip())
    rs = load_from_dir(rules)
    assert rs.correlation[0].suppress_window_seconds == 3600

    # Three windows back-to-back, each triggering the threshold for alice.
    # Without suppression: 3 correlation alerts. With suppression: 1.
    msgs = []
    for window_start in (0, 60, 120):
        for i in range(3):
            msgs.append(json.dumps({
                "EventID": 4625, "User": "alice",
                "timestamp": _iso(window_start + i),
            }).encode())

    alerts_p = tmp_path / "alerts.jsonl"
    dlq_p = tmp_path / "dlq.jsonl"
    with TestPipeline() as p:
        build_pipeline(p, rs,
                       source=beam.Create(msgs),
                       alerts_sink=_FileSink(alerts_p),
                       dlq_sink=_FileSink(dlq_p))

    alerts = _read(alerts_p)
    corr = [a for a in alerts
            if a["rule_id"] == "22222222-2222-2222-2222-222222222222"]
    assert len(corr) == 1, (
        f"expected 1 suppressed alert, got {len(corr)}: {corr}"
    )
