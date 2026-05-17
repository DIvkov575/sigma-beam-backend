from pathlib import Path

import pytest

from sigma_beam.loader import RuleLoadError, load_from_dir

FIX = Path(__file__).parent / "fixtures" / "rules"


def test_load_fixtures():
    rs = load_from_dir(FIX)
    assert len(rs.single_event) == 1
    assert len(rs.correlation) == 1

    se = rs.single_event[0]
    assert se.id == "00000000-0000-0000-0000-000000000001"
    assert se.title == "Failed Windows Logon"
    assert se.severity == "medium"
    assert se.predicate({"EventID": 4625})
    assert not se.predicate({"EventID": 4624})

    c = rs.correlation[0]
    assert c.kind == "event_count"
    assert c.window_seconds == 300
    assert c.group_by == ("User",)
    assert c.threshold == 5
    assert c.threshold_op == "gte"
    assert c.referenced_rule_ids == ("00000000-0000-0000-0000-000000000001",)


def test_rules_by_id():
    rs = load_from_dir(FIX)
    by_id = rs.rules_by_id()
    assert "00000000-0000-0000-0000-000000000001" in by_id


def test_cardinality_linter(tmp_path):
    # Write a correlation rule grouping by `user_agent` without override → reject.
    (tmp_path / "base.yml").write_text("""
title: t
id: aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
status: test
logsource: {product: web}
detection:
  sel: {status: 401}
  condition: sel
""".strip())
    (tmp_path / "bad.yml").write_text("""
title: high-card grouping
id: bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb
correlation:
  type: event_count
  rules: [aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa]
  group-by: [user_agent]
  timespan: 1m
  condition: {gte: 100}
""".strip())
    with pytest.raises(RuleLoadError, match="high-cardinality"):
        load_from_dir(tmp_path)


def test_empty_dir(tmp_path):
    rs = load_from_dir(tmp_path)
    assert rs.single_event == []
    assert rs.correlation == []
