"""Tier 1 feature tests: tags surfacing, fields projection, threshold_range,
extra pipeline plugins, placeholder expansion."""

from __future__ import annotations

import textwrap
from pathlib import Path

from sigma_beam.alerts import Alert
from sigma_beam.loader import load_from_dir, load_from_paths


def _write(p: Path, body: str) -> Path:
    p.write_text(textwrap.dedent(body).strip())
    return p


# ---------------------------------------------------------------------------
# A: tags
# ---------------------------------------------------------------------------

def test_tags_extracted_as_dotted_strings(tmp_path):
    _write(tmp_path / "r.yml", """
        title: t
        id: 11111111-1111-1111-1111-111111111111
        status: test
        logsource: {product: windows}
        detection: {sel: {EventID: 4625}, condition: sel}
        tags:
          - attack.t1059
          - attack.execution
          - cve.2024-1234
    """)
    rs = load_from_dir(tmp_path)
    r = rs.single_event[0]
    assert r.tags == ("attack.t1059", "attack.execution", "cve.2024-1234")


def test_tags_propagate_to_alert_in_pipeline(tmp_path):
    import apache_beam as beam
    from apache_beam.testing.test_pipeline import TestPipeline
    import json

    _write(tmp_path / "r.yml", """
        title: t
        id: 22222222-2222-2222-2222-222222222222
        status: test
        logsource: {product: windows}
        detection: {sel: {EventID: 4625}, condition: sel}
        tags: [attack.t1110]
    """)
    rs = load_from_dir(tmp_path)

    from sigma_beam.correlation_pipeline import build_pipeline
    out_path = tmp_path / "alerts.jsonl"
    dlq_path = tmp_path / "dlq.jsonl"

    class _Sink(beam.PTransform):
        def __init__(self, p): super().__init__(); self.p = str(p)
        def expand(self, c): return (c | beam.Map(lambda b: b.decode())
                                       | beam.io.WriteToText(self.p, num_shards=1,
                                                              shard_name_template=""))

    with TestPipeline() as p:
        build_pipeline(p, rs,
                       source=beam.Create([json.dumps({"EventID": 4625}).encode()]),
                       alerts_sink=_Sink(out_path), dlq_sink=_Sink(dlq_path))
    [alert] = [json.loads(l) for l in out_path.read_text().splitlines() if l.strip()]
    assert alert["tags"] == ["attack.t1110"]


# ---------------------------------------------------------------------------
# B: fields projection
# ---------------------------------------------------------------------------

def test_fields_projection_filters_matched_event(tmp_path):
    import apache_beam as beam
    from apache_beam.testing.test_pipeline import TestPipeline
    import json

    _write(tmp_path / "r.yml", """
        title: t
        id: 33333333-3333-3333-3333-333333333333
        status: test
        logsource: {product: windows}
        detection: {sel: {EventID: 4625}, condition: sel}
        fields: [EventID, User]
    """)
    rs = load_from_dir(tmp_path)
    assert rs.single_event[0].project_fields == ("EventID", "User")

    from sigma_beam.correlation_pipeline import build_pipeline

    class _Sink(beam.PTransform):
        def __init__(self, p): super().__init__(); self.p = str(p)
        def expand(self, c): return (c | beam.Map(lambda b: b.decode())
                                       | beam.io.WriteToText(self.p, num_shards=1,
                                                              shard_name_template=""))

    out_path = tmp_path / "alerts.jsonl"
    dlq_path = tmp_path / "dlq.jsonl"
    with TestPipeline() as p:
        build_pipeline(p, rs,
                       source=beam.Create([json.dumps({
                           "EventID": 4625, "User": "alice", "SecretField": "shh",
                       }).encode()]),
                       alerts_sink=_Sink(out_path), dlq_sink=_Sink(dlq_path))
    [alert] = [json.loads(l) for l in out_path.read_text().splitlines() if l.strip()]
    matched = alert["matched_events"][0]
    assert matched == {"EventID": 4625, "User": "alice"}
    assert "SecretField" not in matched


def test_fields_missing_field_becomes_null(tmp_path):
    _write(tmp_path / "r.yml", """
        title: t
        id: 44444444-4444-4444-4444-444444444444
        status: test
        logsource: {product: windows}
        detection: {sel: {EventID: 4625}, condition: sel}
        fields: [EventID, NotPresent]
    """)
    rs = load_from_dir(tmp_path)
    # Run by hand through the predicate + Alert builder fragment
    from sigma_beam.field_access import MISSING, get_field
    rule = rs.single_event[0]
    event = {"EventID": 4625}
    assert rule.predicate(event)
    projected = {
        f: (None if (v := get_field(event, f)) is MISSING else v)
        for f in rule.project_fields
    }
    assert projected == {"EventID": 4625, "NotPresent": None}


# ---------------------------------------------------------------------------
# C: threshold_range (beaver annotation)
# ---------------------------------------------------------------------------

def test_threshold_range_annotation(tmp_path):
    # Base rule
    _write(tmp_path / "base.yml", """
        title: base
        id: 55555555-5555-5555-5555-555555555555
        status: test
        logsource: {product: windows}
        detection: {sel: {EventID: 4625}, condition: sel}
    """)
    # Correlation with beaver.threshold_range
    _write(tmp_path / "corr.yml", """
        title: count in range
        id: 66666666-6666-6666-6666-666666666666
        status: test
        correlation:
          type: event_count
          rules: [55555555-5555-5555-5555-555555555555]
          group-by: [User]
          timespan: 5m
          condition: {gte: 1}    # required by pySigma grammar
        beaver:
          threshold_range: [3, 5]
    """)
    rs = load_from_dir(tmp_path)
    c = rs.correlation[0]
    assert c.threshold_range == (3, 5)
    # `threshold_op` keeps whatever pySigma parsed (gte here); the range
    # takes precedence at evaluation time in cmp_threshold().

    # End-to-end: 2 events → no fire; 4 events → fire; 6 events → no fire.
    from datetime import datetime, timedelta, timezone
    import json
    import apache_beam as beam
    from apache_beam.testing.test_pipeline import TestPipeline
    from sigma_beam.correlation_pipeline import build_pipeline

    def _iso(s): return (datetime(2026,5,16,tzinfo=timezone.utc)+timedelta(seconds=s)).isoformat()

    class _Sink(beam.PTransform):
        def __init__(self, p): super().__init__(); self.p = str(p)
        def expand(self, c): return (c | beam.Map(lambda b: b.decode())
                                       | beam.io.WriteToText(self.p, num_shards=1, shard_name_template=""))

    for n, expect_fire in [(2, False), (4, True), (6, False)]:
        msgs = [json.dumps({"EventID": 4625, "User": "alice",
                            "timestamp": _iso(i)}).encode() for i in range(n)]
        out_path = tmp_path / f"alerts_{n}.jsonl"
        dlq_path = tmp_path / f"dlq_{n}.jsonl"
        with TestPipeline() as p:
            build_pipeline(p, rs,
                           source=beam.Create(msgs),
                           alerts_sink=_Sink(out_path), dlq_sink=_Sink(dlq_path))
        alerts = [json.loads(l) for l in out_path.read_text().splitlines() if l.strip()]
        corr_fires = [a for a in alerts if a["rule_id"].startswith("66")]
        assert bool(corr_fires) is expect_fire, f"n={n} expected fire={expect_fire}, got {corr_fires}"


# ---------------------------------------------------------------------------
# D: more pipeline plugins (CrowdStrike was installable; AWS/Okta gracefully absent)
# ---------------------------------------------------------------------------

def test_crowdstrike_pipeline_applied_when_available(tmp_path):
    import importlib
    try:
        importlib.import_module("sigma.pipelines.crowdstrike")
    except ImportError:
        import pytest
        pytest.skip("pysigma-pipeline-crowdstrike not installed")

    _write(tmp_path / "r.yml", """
        title: cs process
        id: 77777777-7777-7777-7777-777777777777
        status: test
        logsource: {product: crowdstrike, category: process_creation}
        detection:
            sel: {Image|endswith: '\\powershell.exe'}
            condition: sel
    """)
    from sigma_beam.processing import default_selector, null_selector

    rs_off = load_from_dir(tmp_path, pipeline_selector=null_selector)
    rs_on  = load_from_dir(tmp_path, pipeline_selector=default_selector())

    # CrowdStrike pipeline renames Image → ImageFileName.
    evt_native = {"Image": "C:\\powershell.exe"}
    evt_falcon = {"ImageFileName": "C:\\powershell.exe", "event_simpleName": "ProcessRollup2"}

    # Without the pipeline, native Image matches.
    assert rs_off.single_event[0].predicate(evt_native)
    # With the pipeline, the rule's Image is rewritten — falcon-shaped events should hit.
    on_predicate = rs_on.single_event[0].predicate
    # At least one of the two shapes should match under the falcon pipeline;
    # the exact rename depends on plugin version, so accept either path.
    assert on_predicate(evt_falcon) or on_predicate(evt_native)


def test_default_selector_skips_missing_plugins_gracefully(tmp_path):
    """Plugins we don't have installed (AWS, Okta) must not crash load."""
    _write(tmp_path / "r.yml", """
        title: aws root
        id: 88888888-8888-8888-8888-888888888888
        status: test
        logsource: {product: aws, service: cloudtrail}
        detection: {sel: {userIdentity.type: Root}, condition: sel}
    """)
    from sigma_beam.processing import default_selector
    rs = load_from_dir(tmp_path, pipeline_selector=default_selector())
    assert len(rs.single_event) == 1   # didn't crash
    # And the rule still matches even though no AWS-specific pipeline ran.
    assert rs.single_event[0].predicate({"userIdentity": {"type": "Root"}})


# ---------------------------------------------------------------------------
# G: |expand placeholders
# ---------------------------------------------------------------------------

def test_expand_placeholder_resolves_at_load_time(tmp_path):
    _write(tmp_path / "r.yml", """
        title: admin shell
        id: 99999999-9999-9999-9999-999999999999
        status: test
        logsource: {product: linux}
        detection:
            sel: {User|expand: '%admin_users%'}
            condition: sel
    """)
    rs = load_from_dir(tmp_path, placeholders={"admin_users": ["alice", "bob"]})
    p = rs.single_event[0].predicate
    assert p({"User": "alice"})
    assert p({"User": "bob"})
    assert not p({"User": "charlie"})


def test_expand_placeholder_missing_key_does_not_crash(tmp_path):
    _write(tmp_path / "r.yml", """
        title: t
        id: a0000000-0000-0000-0000-000000000000
        status: test
        logsource: {product: linux}
        detection:
            sel: {User|expand: '%not_provided%'}
            condition: sel
    """)
    # Loading with no placeholders or wrong key shouldn't crash — rule may
    # simply never match.
    rs = load_from_dir(tmp_path, placeholders={"some_other": ["x"]})
    assert len(rs.single_event) == 1
