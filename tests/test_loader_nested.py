from pathlib import Path
import pytest
from sigma_beam.loader import load_from_dir


def test_nested_correlation_from_fixture(tmp_path: Path):
    fixture = Path(__file__).parent / "fixtures" / "rules_nested" / "nested_correlation.yml"
    (tmp_path / "rules.yml").write_text(fixture.read_text())
    rs = load_from_dir(tmp_path)
    assert len(rs.single_event) == 1
    assert len(rs.correlation) == 1
    assert len(rs.nested_correlation) == 1
    nested = rs.nested_correlation[0]
    assert nested.id == "00000000-0000-0000-0000-000000000003"
    assert nested.is_nested is True
    assert nested.referenced_rule_ids == ("00000000-0000-0000-0000-000000000002",)


def test_cycle_detection_raises(tmp_path: Path):
    (tmp_path / "cycle.yml").write_text("""
---
title: rule A
id: 00000000-0000-0000-0000-00000000000a
status: test
correlation:
    type: event_count
    rules: [00000000-0000-0000-0000-00000000000b]
    group-by: [user]
    timespan: 5m
    condition: {gte: 5}
level: high
---
title: rule B
id: 00000000-0000-0000-0000-00000000000b
status: test
correlation:
    type: event_count
    rules: [00000000-0000-0000-0000-00000000000a]
    group-by: [user]
    timespan: 5m
    condition: {gte: 5}
level: high
""")
    with pytest.raises(Exception, match="[Cc]ycle"):
        load_from_dir(tmp_path)


def test_normal_correlations_not_marked_nested(tmp_path: Path):
    (tmp_path / "rule.yml").write_text("""
---
title: base
id: 00000000-0000-0000-0000-000000000010
status: test
logsource: {product: x}
detection:
    sel: {event: login}
    condition: sel
level: low
---
title: count
id: 00000000-0000-0000-0000-000000000011
status: test
correlation:
    type: event_count
    rules: [00000000-0000-0000-0000-000000000010]
    group-by: [user]
    timespan: 5m
    condition: {gte: 3}
level: high
""")
    rs = load_from_dir(tmp_path)
    assert len(rs.correlation) == 1
    assert len(rs.nested_correlation) == 0
    assert rs.correlation[0].is_nested is False
