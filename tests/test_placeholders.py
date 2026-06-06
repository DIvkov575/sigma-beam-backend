"""Tests for |expand placeholder substitution."""
import textwrap
import pytest
from sigma.rule import SigmaRule
from sigma_beam.placeholders import resolve_placeholders
from sigma_beam.conditions import compile_rule


def _rule(body: str) -> SigmaRule:
    return SigmaRule.from_yaml(textwrap.dedent(body))


def test_expand_resolves_placeholder_table():
    r = _rule("""
        title: admin login
        logsource: {product: x}
        detection:
            sel: {User|expand: '%admin_users%'}
            condition: sel
    """)
    table = {"admin_users": ["alice", "bob", "root"]}
    resolved = resolve_placeholders(r, table)
    p = compile_rule(resolved)
    assert p({"User": "alice"})
    assert p({"User": "bob"})
    assert p({"User": "root"})
    assert not p({"User": "mallory"})


def test_expand_unknown_placeholder_raises():
    r = _rule("""
        title: t
        logsource: {product: x}
        detection:
            sel: {User|expand: '%unknown_group%'}
            condition: sel
    """)
    with pytest.raises(ValueError, match="unknown_group"):
        resolve_placeholders(r, {})


def test_expand_with_empty_table_and_no_placeholders():
    r = _rule("""
        title: t
        logsource: {product: x}
        detection:
            sel: {User: alice}
            condition: sel
    """)
    # Should not raise — no placeholders in the rule
    result = resolve_placeholders(r, {})
    p = compile_rule(result)
    assert p({"User": "alice"})


from pathlib import Path
from sigma_beam.loader import load_from_dir


def test_loader_resolves_placeholders(tmp_path: Path):
    rule_file = tmp_path / "admin_rule.yml"
    rule_file.write_text("""
title: admin login
id: 00000000-0000-0000-0000-000000000002
logsource:
    product: app
    service: auth
detection:
    sel:
        User|expand: '%admin_users%'
    condition: sel
level: high
""")
    table = {"admin_users": ["alice", "bob"]}
    rs = load_from_dir(tmp_path, placeholders=table)
    assert len(rs.single_event) == 1
    p = rs.single_event[0].predicate
    assert p({"User": "alice"})
    assert p({"User": "bob"})
    assert not p({"User": "mallory"})
