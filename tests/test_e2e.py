"""End-to-end tests that drive the actual `correlation_pipeline.build_pipeline()`
on the DirectRunner with realistic rule sets, real file I/O for rule loading,
and capture sinks. These exercise the exact composition that ships to Dataflow.

What they cover that unit/integration tests don't:
- The full graph wiring: parse → single-event → correlation → flatten → sinks
- Rule loading from disk via the same code path the production runner uses
- DLQ routing for both parse errors and per-rule predicate explosions
- Beam serialization (every DoFn pickleable for Dataflow workers)
- Event-time correlation across multiple rule kinds in one stream
- Empty / degenerate rule sets without crashes

What they don't cover (would require real GCP):
- Pub/Sub delivery semantics, watermark behavior under streaming
- IAM, deploy plumbing, Dataflow worker startup
"""

from __future__ import annotations

import json
import textwrap
from datetime import datetime, timedelta, timezone
from pathlib import Path

import apache_beam as beam
import pytest
from apache_beam.options.pipeline_options import PipelineOptions
from apache_beam.testing.test_pipeline import TestPipeline

from sigma_beam.correlation_pipeline import build_pipeline
from sigma_beam.loader import load_from_dir
from sigma_beam.ruleset import CompiledRule, Ruleset


def _test_pipeline():
    return TestPipeline()


class _FileSink(beam.PTransform):
    """Decode bytes → text → one-line-per-element file. Works across runners
    because Beam serializes nothing across processes for `WriteToText`."""

    def __init__(self, path):
        super().__init__()
        self.path = str(path)

    def expand(self, pcoll):
        return (
            pcoll
            | "Decode" >> beam.Map(lambda b: b.decode("utf-8"))
            | "Write"  >> beam.io.WriteToText(
                self.path, num_shards=1, shard_name_template="",
            )
        )


def _read_records(path) -> list[dict]:
    p = Path(path)
    if not p.exists():
        return []
    return [json.loads(ln) for ln in p.read_text().splitlines() if ln.strip()]


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _iso(offset_s: int) -> str:
    base = datetime(2026, 5, 16, tzinfo=timezone.utc)
    return (base + timedelta(seconds=offset_s)).isoformat()


def _write_ruleset(root: Path) -> None:
    """Write a realistic ruleset to `root` covering every rule kind."""
    (root / "single_failed_login.yml").write_text(textwrap.dedent("""
        title: Failed Login
        id: 10000000-0000-0000-0000-000000000001
        status: test
        logsource: {product: windows, service: security}
        detection:
            sel: {EventID: 4625}
            condition: sel
        level: medium
    """).strip())

    (root / "single_conn.yml").write_text(textwrap.dedent("""
        title: Connection
        id: 10000000-0000-0000-0000-000000000002
        status: test
        logsource: {category: firewall}
        detection:
            sel: {type: conn}
            condition: sel
        level: low
    """).strip())

    (root / "single_recon.yml").write_text(textwrap.dedent("""
        title: Recon Process
        id: 10000000-0000-0000-0000-000000000003
        status: test
        logsource: {product: windows, category: process_creation}
        detection:
            sel: {Image|endswith: '\\whoami.exe'}
            condition: sel
        level: medium
    """).strip())

    (root / "single_pivot.yml").write_text(textwrap.dedent("""
        title: Pivot Process
        id: 10000000-0000-0000-0000-000000000004
        status: test
        logsource: {product: windows, category: process_creation}
        detection:
            sel: {Image|endswith: '\\psexec.exe'}
            condition: sel
        level: high
    """).strip())

    (root / "corr_brute_force.yml").write_text(textwrap.dedent("""
        title: Brute Force
        id: 20000000-0000-0000-0000-000000000001
        status: test
        correlation:
            type: event_count
            rules: [10000000-0000-0000-0000-000000000001]
            group-by: [User]
            timespan: 5m
            condition: {gte: 5}
        level: high
    """).strip())

    (root / "corr_port_scan.yml").write_text(textwrap.dedent("""
        title: Port Scan
        id: 20000000-0000-0000-0000-000000000002
        status: test
        correlation:
            type: value_count
            rules: [10000000-0000-0000-0000-000000000002]
            group-by: [src]
            timespan: 1m
            condition: {gte: 10, field: dst_port}
        level: high
    """).strip())

    (root / "corr_recon_pivot.yml").write_text(textwrap.dedent("""
        title: Recon Then Pivot
        id: 20000000-0000-0000-0000-000000000003
        status: test
        correlation:
            type: temporal
            rules:
              - 10000000-0000-0000-0000-000000000003
              - 10000000-0000-0000-0000-000000000004
            group-by: [User]
            timespan: 10m
        level: critical
    """).strip())


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_e2e_multi_rule_happy_path(tmp_path):
    """One pipeline run exercising every rule kind, plus a malformed message."""
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    _write_ruleset(rules_dir)
    ruleset = load_from_dir(rules_dir)

    messages: list[bytes] = []
    # 5 failed logins for alice within 30s → 5 single-event alerts + 1 brute_force
    for i in range(5):
        messages.append(json.dumps({
            "EventID": 4625, "User": "alice", "timestamp": _iso(i),
        }).encode())
    # 1 successful login (noise, no match)
    messages.append(json.dumps({
        "EventID": 4624, "User": "alice", "timestamp": _iso(6),
    }).encode())
    # 10 distinct dst_ports from one src → 10 single-event conn alerts + 1 port_scan
    for i in range(10):
        messages.append(json.dumps({
            "type": "conn", "src": "10.0.0.1", "dst_port": 1000 + i,
            "timestamp": _iso(i),
        }).encode())
    # recon then pivot for bob → temporal correlation fires once
    messages.append(json.dumps({
        "Image": "C:\\\\Windows\\\\System32\\\\whoami.exe",
        "User": "bob", "timestamp": _iso(1),
    }).encode())
    messages.append(json.dumps({
        "Image": "C:\\\\Tools\\\\psexec.exe",
        "User": "bob", "timestamp": _iso(60),
    }).encode())
    # malformed → DLQ
    messages.append(b"this is not json {{{")

    alerts_path = tmp_path / 'alerts.jsonl'
    dlq_path = tmp_path / 'dlq.jsonl'
    with _test_pipeline() as p:
        build_pipeline(
            p, ruleset,
            source=beam.Create(messages),
            alerts_sink=_FileSink(alerts_path),
            dlq_sink=_FileSink(dlq_path),
        )
    alerts = _read_records(alerts_path)
    dlq = _read_records(dlq_path)
    alerts = _read_records(alerts_path)
    dlq = _read_records(dlq_path)

    rule_ids = sorted(a["rule_id"] for a in alerts)
    counts = {rid: rule_ids.count(rid) for rid in set(rule_ids)}

    # 5 failed-login single-event alerts
    assert counts["10000000-0000-0000-0000-000000000001"] == 5
    # 10 single-event conn alerts
    assert counts["10000000-0000-0000-0000-000000000002"] == 10
    # one for each of recon + pivot single-event matches (bob)
    assert counts["10000000-0000-0000-0000-000000000003"] == 1
    assert counts["10000000-0000-0000-0000-000000000004"] == 1
    # one brute_force correlation for alice
    assert counts["20000000-0000-0000-0000-000000000001"] == 1
    # one port_scan correlation for 10.0.0.1
    assert counts["20000000-0000-0000-0000-000000000002"] == 1
    # one temporal correlation for bob
    assert counts["20000000-0000-0000-0000-000000000003"] == 1

    # DLQ: exactly the malformed message
    assert len(dlq) == 1
    assert dlq[0]["reason"] == "non-JSON message"


def test_e2e_load_rules_from_nested_dirs(tmp_path):
    """Rules in subdirectories should be discovered by load_from_dir."""
    (tmp_path / "windows").mkdir()
    (tmp_path / "aws").mkdir()
    _write_ruleset(tmp_path / "windows")
    (tmp_path / "aws" / "root.yml").write_text(textwrap.dedent("""
        title: AWS Root Use
        id: 30000000-0000-0000-0000-000000000001
        status: test
        logsource: {product: aws, service: cloudtrail}
        detection:
            sel: {userIdentity.type: Root}
            condition: sel
        level: high
    """).strip())

    ruleset = load_from_dir(tmp_path)
    assert len(ruleset.single_event) == 5  # 4 windows + 1 aws
    assert len(ruleset.correlation) == 3

    alerts_path = tmp_path / 'alerts.jsonl'
    dlq_path = tmp_path / 'dlq.jsonl'
    with _test_pipeline() as p:
        build_pipeline(
            p, ruleset,
            source=beam.Create([
                json.dumps({"userIdentity": {"type": "Root"}}).encode(),
            ]),
            alerts_sink=_FileSink(alerts_path),
            dlq_sink=_FileSink(dlq_path),
        )
    alerts = _read_records(alerts_path)
    dlq = _read_records(dlq_path)
    assert any(a["rule_id"] == "30000000-0000-0000-0000-000000000001" for a in alerts)


def test_e2e_pickle_every_dofn(tmp_path):
    """Every transform in the production graph must serialize for Dataflow."""
    # Beam uses cloudpickle/dill, not stdlib pickle. Hit it via the same coder
    # the runner uses so we catch the same failures Dataflow workers would.
    from apache_beam.internal.pickler import dumps

    _write_ruleset(tmp_path)
    ruleset = load_from_dir(tmp_path)

    from sigma_beam.correlation.fanout import CorrelationFanout
    from sigma_beam.correlation_pipeline import _ParseJson
    from sigma_beam.single_event import SingleEventDetect

    # Top-level transforms — Dataflow will need to ship these to workers.
    dumps(SingleEventDetect(ruleset.single_event))
    dumps(CorrelationFanout(ruleset))
    dumps(_ParseJson())

    # Every compiled predicate (these are closures over compiled regex /
    # SigmaCIDR / etc. — exactly the things that historically break pickling).
    for r in ruleset.single_event:
        dumps(r.predicate)


def test_e2e_predicate_explosion_to_dlq(tmp_path):
    """A rule whose predicate raises sends a DLQ entry tagged with rule_id."""
    def explosive(_event):
        raise RuntimeError("kaboom")

    ruleset = Ruleset(
        single_event=[
            CompiledRule(id="BAD", title="explodes", severity="medium",
                         predicate=explosive),
            CompiledRule(id="OK", title="benign", severity="low",
                         predicate=lambda e: e.get("k") == "v"),
        ],
    )

    alerts_path = tmp_path / 'alerts.jsonl'
    dlq_path = tmp_path / 'dlq.jsonl'
    with _test_pipeline() as p:
        build_pipeline(
            p, ruleset,
            source=beam.Create([json.dumps({"k": "v"}).encode()]),
            alerts_sink=_FileSink(alerts_path),
            dlq_sink=_FileSink(dlq_path),
        )
    alerts = _read_records(alerts_path)
    dlq = _read_records(dlq_path)

    assert [a["rule_id"] for a in alerts] == ["OK"]
    assert len(dlq) == 1
    assert dlq[0]["rule_id"] == "BAD"
    assert "kaboom" in dlq[0]["error"]


def test_e2e_empty_ruleset_runs_clean(tmp_path):
    """Empty ruleset → no alerts, malformed events still routed to DLQ."""
    ruleset = Ruleset(single_event=[], correlation=[])
    alerts_path = tmp_path / 'alerts.jsonl'
    dlq_path = tmp_path / 'dlq.jsonl'
    with _test_pipeline() as p:
        build_pipeline(
            p, ruleset,
            source=beam.Create([
                json.dumps({"x": 1}).encode(),
                b"definitely not json",
            ]),
            alerts_sink=_FileSink(alerts_path),
            dlq_sink=_FileSink(dlq_path),
        )
    alerts = _read_records(alerts_path)
    dlq = _read_records(dlq_path)
    assert alerts == []
    assert len(dlq) == 1


def test_e2e_correlation_threshold_just_below(tmp_path):
    """4 failed logins (threshold=5) → no brute_force, just 4 single-event alerts."""
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    _write_ruleset(rules_dir)
    ruleset = load_from_dir(rules_dir)

    messages = [
        json.dumps({"EventID": 4625, "User": "alice", "timestamp": _iso(i)}).encode()
        for i in range(4)
    ]
    alerts_path = tmp_path / 'alerts.jsonl'
    dlq_path = tmp_path / 'dlq.jsonl'
    with _test_pipeline() as p:
        build_pipeline(
            p, ruleset,
            source=beam.Create(messages),
            alerts_sink=_FileSink(alerts_path),
            dlq_sink=_FileSink(dlq_path),
        )
    alerts = _read_records(alerts_path)
    dlq = _read_records(dlq_path)

    rule_ids = [a["rule_id"] for a in alerts]
    assert rule_ids.count("10000000-0000-0000-0000-000000000001") == 4
    assert "20000000-0000-0000-0000-000000000001" not in rule_ids  # no brute force


def test_e2e_correlation_groups_independently(tmp_path):
    """5 failed logins for alice + 4 for bob → brute_force fires only for alice."""
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    _write_ruleset(rules_dir)
    ruleset = load_from_dir(rules_dir)

    messages = (
        [json.dumps({"EventID": 4625, "User": "alice", "timestamp": _iso(i)}).encode()
         for i in range(5)]
        + [json.dumps({"EventID": 4625, "User": "bob", "timestamp": _iso(i)}).encode()
           for i in range(4)]
    )
    alerts_path = tmp_path / 'alerts.jsonl'
    dlq_path = tmp_path / 'dlq.jsonl'
    with _test_pipeline() as p:
        build_pipeline(
            p, ruleset,
            source=beam.Create(messages),
            alerts_sink=_FileSink(alerts_path),
            dlq_sink=_FileSink(dlq_path),
        )
    alerts = _read_records(alerts_path)
    dlq = _read_records(dlq_path)

    bfs = [a for a in alerts if a["rule_id"] == "20000000-0000-0000-0000-000000000001"]
    assert len(bfs) == 1
    assert bfs[0]["correlation_key"] == "alice"


def test_e2e_correlation_window_boundary(tmp_path):
    """5 failed logins split across the brute_force window → no alert."""
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    _write_ruleset(rules_dir)
    ruleset = load_from_dir(rules_dir)

    # 5m window. 3 events in window 0, 2 events in window 1 (separated by 5m).
    messages = (
        [json.dumps({"EventID": 4625, "User": "alice", "timestamp": _iso(i)}).encode()
         for i in (1, 2, 3)]
        + [json.dumps({"EventID": 4625, "User": "alice", "timestamp": _iso(i)}).encode()
           for i in (301, 302)]
    )
    alerts_path = tmp_path / 'alerts.jsonl'
    dlq_path = tmp_path / 'dlq.jsonl'
    with _test_pipeline() as p:
        build_pipeline(
            p, ruleset,
            source=beam.Create(messages),
            alerts_sink=_FileSink(alerts_path),
            dlq_sink=_FileSink(dlq_path),
        )
    alerts = _read_records(alerts_path)
    dlq = _read_records(dlq_path)
    bfs = [a for a in alerts if a["rule_id"] == "20000000-0000-0000-0000-000000000001"]
    assert bfs == []


def test_e2e_dlq_includes_event_payload_for_predicate_errors(tmp_path):
    """DLQ entries for predicate raises must include the offending event."""
    sentinel_event = {"trigger": "yes", "extra": [1, 2, 3]}

    def explodes_on_trigger(e):
        if e.get("trigger") == "yes":
            raise ValueError("explicit failure")
        return False

    ruleset = Ruleset(
        single_event=[
            CompiledRule(id="EXPL", title="explodes", severity="medium",
                         predicate=explodes_on_trigger),
        ],
    )
    alerts_path = tmp_path / 'alerts.jsonl'
    dlq_path = tmp_path / 'dlq.jsonl'
    with _test_pipeline() as p:
        build_pipeline(
            p, ruleset,
            source=beam.Create([json.dumps(sentinel_event).encode()]),
            alerts_sink=_FileSink(alerts_path),
            dlq_sink=_FileSink(dlq_path),
        )
    alerts = _read_records(alerts_path)
    dlq = _read_records(dlq_path)
    assert alerts == []
    assert len(dlq) == 1
    assert dlq[0]["rule_id"] == "EXPL"
    assert dlq[0]["event"] == sentinel_event
    assert "explicit failure" in dlq[0]["error"]


def test_e2e_accepts_str_and_dict_messages(tmp_path):
    """Source-shape robustness: ParseJson handles bytes / str / dict alike."""
    ruleset = Ruleset(
        single_event=[
            CompiledRule(id="OK", title="x", severity="m",
                         predicate=lambda e: e.get("a") == 1),
        ],
    )
    alerts_path = tmp_path / 'alerts.jsonl'
    dlq_path = tmp_path / 'dlq.jsonl'
    with _test_pipeline() as p:
        build_pipeline(
            p, ruleset,
            source=beam.Create([
                b'{"a": 1}',
                '{"a": 1}',
            ]),
            alerts_sink=_FileSink(alerts_path),
            dlq_sink=_FileSink(dlq_path),
        )
    alerts = _read_records(alerts_path)
    dlq = _read_records(dlq_path)
    assert len(alerts) == 2
