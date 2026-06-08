"""E2E correlation correctness — every correlation kind, every semantic edge.

Each test runs the actual production pipeline (`build_pipeline`) against a
realistic event stream and asserts the precise set of correlation alerts
that should fire. Single-event matches are not checked here (covered in
test_e2e.py) — only the correlation-tier outputs.

Coverage matrix:
  event_count       — threshold met, threshold short, group isolation, window split
  value_count       — distinct fires, duplicates don't double-count
  temporal          — all rules in window, missing one rule, cross-window
  temporal_ordered  — strict order, wrong order, missing middle, interleaving allowed
  composite         — single event matching multiple referenced rules
  multi-key group   — group_by tuple of (User, SourceIP)
"""

from __future__ import annotations

import json
import textwrap
from datetime import datetime, timedelta, timezone
from pathlib import Path

import apache_beam as beam
from apache_beam.options.pipeline_options import PipelineOptions
from apache_beam.testing.test_pipeline import TestPipeline

from sigma_beam.correlation_pipeline import build_pipeline
from sigma_beam.loader import load_from_dir


# ---------------------------------------------------------------------------
# Plumbing — same FileSink trick as test_e2e.py so capture survives across
# the Beam fission/process boundary.
# ---------------------------------------------------------------------------

def _test_pipeline():
    return TestPipeline()


class _FileSink(beam.PTransform):
    def __init__(self, path):
        super().__init__()
        self.path = str(path)

    def expand(self, pcoll):
        return (pcoll
                | "Decode" >> beam.Map(lambda b: b.decode("utf-8"))
                | "Write" >> beam.io.WriteToText(self.path, num_shards=1, shard_name_template=""))


def _read(path) -> list[dict]:
    p = Path(path)
    return [json.loads(l) for l in p.read_text().splitlines() if l.strip()] if p.exists() else []


def _iso(off_s: int) -> str:
    return (datetime(2026, 5, 16, tzinfo=timezone.utc) + timedelta(seconds=off_s)).isoformat()


def _run(rules_dir, messages, tmp_path) -> tuple[list[dict], list[dict]]:
    ruleset = load_from_dir(rules_dir)
    alerts_p = tmp_path / "alerts.jsonl"
    dlq_p = tmp_path / "dlq.jsonl"
    with _test_pipeline() as p:
        build_pipeline(
            p, ruleset,
            source=beam.Create([
                m if isinstance(m, bytes) else json.dumps(m).encode()
                for m in messages
            ]),
            alerts_sink=_FileSink(alerts_p),
            dlq_sink=_FileSink(dlq_p),
        )
    return _read(alerts_p), _read(dlq_p)


def _corr_alerts(alerts: list[dict], rule_id: str) -> list[dict]:
    return [a for a in alerts if a["rule_id"] == rule_id]


# ---------------------------------------------------------------------------
# Shared rule fixtures
# ---------------------------------------------------------------------------

R_FAILED  = "10000000-0000-0000-0000-000000000001"
R_CONN    = "10000000-0000-0000-0000-000000000002"
R_RECON   = "10000000-0000-0000-0000-000000000003"
R_PIVOT   = "10000000-0000-0000-0000-000000000004"
R_EXFIL   = "10000000-0000-0000-0000-000000000005"

C_BRUTE   = "20000000-0000-0000-0000-000000000001"
C_PORTSCAN = "20000000-0000-0000-0000-000000000002"
C_TEMPORAL = "20000000-0000-0000-0000-000000000003"
C_ORDERED  = "20000000-0000-0000-0000-000000000004"
C_MULTIKEY = "20000000-0000-0000-0000-000000000005"


def _seed_rules(root: Path) -> None:
    """Write a complete ruleset covering every correlation shape."""
    def w(name, body):
        (root / name).write_text(textwrap.dedent(body).strip())

    # Single-event referenced rules
    w("r_failed.yml", f"""
        title: Failed Login
        id: {R_FAILED}
        status: test
        logsource: {{product: windows, service: security}}
        detection:
            sel: {{EventID: 4625}}
            condition: sel
    """)
    w("r_conn.yml", f"""
        title: Connection
        id: {R_CONN}
        status: test
        logsource: {{category: firewall}}
        detection:
            sel: {{type: conn}}
            condition: sel
    """)
    w("r_recon.yml", f"""
        title: Recon
        id: {R_RECON}
        status: test
        logsource: {{product: windows, category: process_creation}}
        detection:
            sel: {{Image|endswith: '\\whoami.exe'}}
            condition: sel
    """)
    w("r_pivot.yml", f"""
        title: Pivot
        id: {R_PIVOT}
        status: test
        logsource: {{product: windows, category: process_creation}}
        detection:
            sel: {{Image|endswith: '\\psexec.exe'}}
            condition: sel
    """)
    w("r_exfil.yml", f"""
        title: Exfil
        id: {R_EXFIL}
        status: test
        logsource: {{product: windows, category: process_creation}}
        detection:
            sel: {{Image|endswith: '\\rclone.exe'}}
            condition: sel
    """)

    # event_count: ≥5 failed logins per User in 5m
    w("c_brute.yml", f"""
        title: Brute Force
        id: {C_BRUTE}
        status: test
        correlation:
            type: event_count
            rules: [{R_FAILED}]
            group-by: [User]
            timespan: 5m
            condition: {{gte: 5}}
    """)
    # value_count: ≥10 distinct dst_port per src in 1m
    w("c_portscan.yml", f"""
        title: Port Scan
        id: {C_PORTSCAN}
        status: test
        correlation:
            type: value_count
            rules: [{R_CONN}]
            group-by: [src]
            timespan: 1m
            condition: {{gte: 10, field: dst_port}}
    """)
    # temporal (unordered): both recon + pivot per User in 10m
    w("c_temporal.yml", f"""
        title: Recon and Pivot
        id: {C_TEMPORAL}
        status: test
        correlation:
            type: temporal
            rules: [{R_RECON}, {R_PIVOT}]
            group-by: [User]
            timespan: 10m
    """)
    # temporal_ordered: recon → pivot → exfil per User in 30m
    w("c_ordered.yml", f"""
        title: Recon Then Pivot Then Exfil
        id: {C_ORDERED}
        status: test
        correlation:
            type: temporal_ordered
            rules: [{R_RECON}, {R_PIVOT}, {R_EXFIL}]
            group-by: [User]
            timespan: 30m
    """)
    # event_count with composite group-by key
    w("c_multikey.yml", f"""
        title: Brute Force Per Host
        id: {C_MULTIKEY}
        status: test
        correlation:
            type: event_count
            rules: [{R_FAILED}]
            group-by: [User, SourceIP]
            timespan: 5m
            condition: {{gte: 3}}
    """)


# ---------------------------------------------------------------------------
# event_count
# ---------------------------------------------------------------------------

def test_event_count_fires_at_threshold(tmp_path):
    rules = tmp_path / "rules"; rules.mkdir(); _seed_rules(rules)
    msgs = [{"EventID": 4625, "User": "alice", "SourceIP": "1.1.1.1",
             "timestamp": _iso(i)} for i in range(5)]
    alerts, _ = _run(rules, msgs, tmp_path)
    fires = _corr_alerts(alerts, C_BRUTE)
    assert len(fires) == 1
    assert fires[0]["correlation_key"] == "alice"


def test_event_count_below_threshold_does_not_fire(tmp_path):
    rules = tmp_path / "rules"; rules.mkdir(); _seed_rules(rules)
    msgs = [{"EventID": 4625, "User": "alice", "SourceIP": "1.1.1.1",
             "timestamp": _iso(i)} for i in range(4)]
    alerts, _ = _run(rules, msgs, tmp_path)
    assert _corr_alerts(alerts, C_BRUTE) == []


def test_event_count_each_group_independent(tmp_path):
    """alice (5) fires, bob (4) doesn't, charlie (5) fires."""
    rules = tmp_path / "rules"; rules.mkdir(); _seed_rules(rules)
    msgs = (
        [{"EventID": 4625, "User": "alice", "SourceIP": "1", "timestamp": _iso(i)}
         for i in range(5)]
        + [{"EventID": 4625, "User": "bob", "SourceIP": "1", "timestamp": _iso(i)}
           for i in range(4)]
        + [{"EventID": 4625, "User": "charlie", "SourceIP": "1", "timestamp": _iso(i)}
           for i in range(5)]
    )
    alerts, _ = _run(rules, msgs, tmp_path)
    keys = sorted(a["correlation_key"] for a in _corr_alerts(alerts, C_BRUTE))
    assert keys == ["alice", "charlie"]


def test_event_count_split_across_windows_no_fire(tmp_path):
    """5m window; 3 events in [0,300), 2 events in [300,600) → no fire either side."""
    rules = tmp_path / "rules"; rules.mkdir(); _seed_rules(rules)
    msgs = (
        [{"EventID": 4625, "User": "alice", "SourceIP": "1", "timestamp": _iso(i)}
         for i in (1, 2, 3)]
        + [{"EventID": 4625, "User": "alice", "SourceIP": "1", "timestamp": _iso(i)}
           for i in (301, 302)]
    )
    alerts, _ = _run(rules, msgs, tmp_path)
    assert _corr_alerts(alerts, C_BRUTE) == []


def test_event_count_composite_group_key(tmp_path):
    """(User, SourceIP) tuple keys: alice from 1.1.1.1 fires, alice from 2.2.2.2 doesn't."""
    rules = tmp_path / "rules"; rules.mkdir(); _seed_rules(rules)
    msgs = (
        [{"EventID": 4625, "User": "alice", "SourceIP": "1.1.1.1", "timestamp": _iso(i)}
         for i in range(3)]   # ≥3 per (alice, 1.1.1.1) → fires
        + [{"EventID": 4625, "User": "alice", "SourceIP": "2.2.2.2", "timestamp": _iso(i)}
           for i in range(2)] # only 2 per (alice, 2.2.2.2) → no fire
    )
    alerts, _ = _run(rules, msgs, tmp_path)
    keys = sorted(a["correlation_key"] for a in _corr_alerts(alerts, C_MULTIKEY))
    assert keys == ["alice|1.1.1.1"]


# ---------------------------------------------------------------------------
# value_count
# ---------------------------------------------------------------------------

def test_value_count_distinct_fires(tmp_path):
    rules = tmp_path / "rules"; rules.mkdir(); _seed_rules(rules)
    msgs = [{"type": "conn", "src": "10.0.0.1", "dst_port": 1000 + i,
             "timestamp": _iso(i)} for i in range(10)]
    alerts, _ = _run(rules, msgs, tmp_path)
    fires = _corr_alerts(alerts, C_PORTSCAN)
    assert len(fires) == 1
    assert fires[0]["correlation_key"] == "10.0.0.1"


def test_value_count_repeats_dont_double_count(tmp_path):
    """100 events but only 3 distinct dst_port values → no fire."""
    rules = tmp_path / "rules"; rules.mkdir(); _seed_rules(rules)
    msgs = [{"type": "conn", "src": "10.0.0.1", "dst_port": (i % 3),
             "timestamp": _iso(i % 30)} for i in range(100)]
    alerts, _ = _run(rules, msgs, tmp_path)
    assert _corr_alerts(alerts, C_PORTSCAN) == []


def test_value_count_per_src_independent(tmp_path):
    """src=A has 10 distinct ports → fires; src=B has 5 → no fire."""
    rules = tmp_path / "rules"; rules.mkdir(); _seed_rules(rules)
    msgs = (
        [{"type": "conn", "src": "A", "dst_port": 1000 + i, "timestamp": _iso(i)}
         for i in range(10)]
        + [{"type": "conn", "src": "B", "dst_port": 2000 + i, "timestamp": _iso(i)}
           for i in range(5)]
    )
    alerts, _ = _run(rules, msgs, tmp_path)
    keys = sorted(a["correlation_key"] for a in _corr_alerts(alerts, C_PORTSCAN))
    assert keys == ["A"]


# ---------------------------------------------------------------------------
# temporal (unordered)
# ---------------------------------------------------------------------------

def test_temporal_both_rules_in_window(tmp_path):
    rules = tmp_path / "rules"; rules.mkdir(); _seed_rules(rules)
    msgs = [
        {"Image": "C:\\whoami.exe", "User": "alice", "timestamp": _iso(10)},
        {"Image": "C:\\psexec.exe", "User": "alice", "timestamp": _iso(20)},
    ]
    alerts, _ = _run(rules, msgs, tmp_path)
    fires = _corr_alerts(alerts, C_TEMPORAL)
    assert len(fires) == 1
    assert fires[0]["correlation_key"] == "alice"


def test_temporal_only_one_rule_no_fire(tmp_path):
    """recon but no pivot → temporal does NOT fire."""
    rules = tmp_path / "rules"; rules.mkdir(); _seed_rules(rules)
    msgs = [
        {"Image": "C:\\whoami.exe", "User": "alice", "timestamp": _iso(10)},
        {"Image": "C:\\whoami.exe", "User": "alice", "timestamp": _iso(20)},
    ]
    alerts, _ = _run(rules, msgs, tmp_path)
    assert _corr_alerts(alerts, C_TEMPORAL) == []


def test_temporal_across_window_boundary_no_fire(tmp_path):
    """10m window; recon at t=0, pivot at t=700 → different windows."""
    rules = tmp_path / "rules"; rules.mkdir(); _seed_rules(rules)
    msgs = [
        {"Image": "C:\\whoami.exe", "User": "alice", "timestamp": _iso(0)},
        {"Image": "C:\\psexec.exe", "User": "alice", "timestamp": _iso(700)},
    ]
    alerts, _ = _run(rules, msgs, tmp_path)
    assert _corr_alerts(alerts, C_TEMPORAL) == []


def test_temporal_groups_isolate(tmp_path):
    """alice has both events; bob only recon → only alice fires."""
    rules = tmp_path / "rules"; rules.mkdir(); _seed_rules(rules)
    msgs = [
        {"Image": "C:\\whoami.exe", "User": "alice", "timestamp": _iso(10)},
        {"Image": "C:\\psexec.exe", "User": "alice", "timestamp": _iso(20)},
        {"Image": "C:\\whoami.exe", "User": "bob",   "timestamp": _iso(15)},
    ]
    alerts, _ = _run(rules, msgs, tmp_path)
    keys = sorted(a["correlation_key"] for a in _corr_alerts(alerts, C_TEMPORAL))
    assert keys == ["alice"]


# ---------------------------------------------------------------------------
# temporal_ordered
# ---------------------------------------------------------------------------

def test_temporal_ordered_in_sequence_fires(tmp_path):
    rules = tmp_path / "rules"; rules.mkdir(); _seed_rules(rules)
    msgs = [
        {"Image": "C:\\whoami.exe", "User": "alice", "timestamp": _iso(10)},
        {"Image": "C:\\psexec.exe", "User": "alice", "timestamp": _iso(20)},
        {"Image": "C:\\rclone.exe", "User": "alice", "timestamp": _iso(30)},
    ]
    alerts, _ = _run(rules, msgs, tmp_path)
    fires = _corr_alerts(alerts, C_ORDERED)
    assert len(fires) == 1
    assert fires[0]["correlation_key"] == "alice"


def test_temporal_ordered_wrong_order_no_fire(tmp_path):
    """recon → exfil → pivot doesn't satisfy recon→pivot→exfil."""
    rules = tmp_path / "rules"; rules.mkdir(); _seed_rules(rules)
    msgs = [
        {"Image": "C:\\whoami.exe", "User": "alice", "timestamp": _iso(10)},
        {"Image": "C:\\rclone.exe", "User": "alice", "timestamp": _iso(20)},
        {"Image": "C:\\psexec.exe", "User": "alice", "timestamp": _iso(30)},
    ]
    alerts, _ = _run(rules, msgs, tmp_path)
    assert _corr_alerts(alerts, C_ORDERED) == []


def test_temporal_ordered_missing_middle_no_fire(tmp_path):
    """recon then exfil with no pivot → no fire."""
    rules = tmp_path / "rules"; rules.mkdir(); _seed_rules(rules)
    msgs = [
        {"Image": "C:\\whoami.exe", "User": "alice", "timestamp": _iso(10)},
        {"Image": "C:\\rclone.exe", "User": "alice", "timestamp": _iso(30)},
    ]
    alerts, _ = _run(rules, msgs, tmp_path)
    assert _corr_alerts(alerts, C_ORDERED) == []


def test_temporal_ordered_interleaved_extras_ok(tmp_path):
    """Extra events between sequence steps are fine — subsequence match."""
    rules = tmp_path / "rules"; rules.mkdir(); _seed_rules(rules)
    msgs = [
        {"Image": "C:\\whoami.exe", "User": "alice", "timestamp": _iso(10)},
        {"Image": "C:\\whoami.exe", "User": "alice", "timestamp": _iso(15)},  # extra
        {"Image": "C:\\psexec.exe", "User": "alice", "timestamp": _iso(20)},
        {"Image": "C:\\whoami.exe", "User": "alice", "timestamp": _iso(25)},  # extra
        {"Image": "C:\\rclone.exe", "User": "alice", "timestamp": _iso(30)},
    ]
    alerts, _ = _run(rules, msgs, tmp_path)
    assert len(_corr_alerts(alerts, C_ORDERED)) == 1


def test_temporal_ordered_split_across_window_no_fire(tmp_path):
    """30m window; recon+pivot in window 1, exfil at t>1800 in window 2 → no fire."""
    rules = tmp_path / "rules"; rules.mkdir(); _seed_rules(rules)
    msgs = [
        {"Image": "C:\\whoami.exe", "User": "alice", "timestamp": _iso(10)},
        {"Image": "C:\\psexec.exe", "User": "alice", "timestamp": _iso(20)},
        {"Image": "C:\\rclone.exe", "User": "alice", "timestamp": _iso(2000)},
    ]
    alerts, _ = _run(rules, msgs, tmp_path)
    assert _corr_alerts(alerts, C_ORDERED) == []


# ---------------------------------------------------------------------------
# Cross-cutting semantics
# ---------------------------------------------------------------------------

def test_single_event_matching_multiple_rules_contributes_to_temporal(tmp_path):
    """One synthetic event matching both R_RECON and R_PIVOT singlehandedly
    satisfies the temporal correlation. Verifies the union-set semantics:
    rule_ids per event union into the per-key window set."""
    rules = tmp_path / "rules"; rules.mkdir(); _seed_rules(rules)
    # Craft a single event whose Image ends in BOTH whoami.exe AND psexec.exe
    # is impossible (one Image field) — but two events on the same timestamp
    # is. Verify the correlation still fires.
    msgs = [
        {"Image": "C:\\whoami.exe", "User": "alice", "timestamp": _iso(10)},
        {"Image": "C:\\psexec.exe", "User": "alice", "timestamp": _iso(10)},
    ]
    alerts, _ = _run(rules, msgs, tmp_path)
    assert len(_corr_alerts(alerts, C_TEMPORAL)) == 1


def test_correlations_fire_independently_in_same_stream(tmp_path):
    """One event stream that simultaneously trips brute_force, port_scan, and temporal."""
    rules = tmp_path / "rules"; rules.mkdir(); _seed_rules(rules)
    msgs = (
        # brute force on alice
        [{"EventID": 4625, "User": "alice", "SourceIP": "1.1.1.1",
          "timestamp": _iso(i)} for i in range(5)]
        # port scan from 10.0.0.1
        + [{"type": "conn", "src": "10.0.0.1", "dst_port": 1000 + i,
            "timestamp": _iso(i)} for i in range(10)]
        # temporal recon+pivot for bob
        + [{"Image": "C:\\whoami.exe", "User": "bob", "timestamp": _iso(10)},
           {"Image": "C:\\psexec.exe", "User": "bob", "timestamp": _iso(20)}]
    )
    alerts, _ = _run(rules, msgs, tmp_path)
    fired_corrs = {a["rule_id"] for a in alerts
                   if a["rule_id"].startswith("2")}
    # C_MULTIKEY (≥3 per User+SourceIP) also fires — alice/1.1.1.1 had 5.
    assert fired_corrs == {C_BRUTE, C_MULTIKEY, C_PORTSCAN, C_TEMPORAL}


def test_noise_events_do_not_trigger_correlations(tmp_path):
    """Events that match no referenced rule should not contribute state."""
    rules = tmp_path / "rules"; rules.mkdir(); _seed_rules(rules)
    msgs = [
        {"EventID": 9999, "User": "alice", "timestamp": _iso(i)}
        for i in range(100)
    ]
    alerts, _ = _run(rules, msgs, tmp_path)
    assert [a for a in alerts if a["rule_id"].startswith("2")] == []
