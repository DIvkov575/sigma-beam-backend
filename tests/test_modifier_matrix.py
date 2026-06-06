"""Sigma 2 modifier coverage matrix.

Each test compiles a rule using one (or one combination of) modifier(s) and
asserts a positive + negative case. New modifiers we support should be added
here; modifiers we deliberately don't support should be xfail-marked so the
matrix is the explicit backlog.
"""

import textwrap

import pytest
from sigma.rule import SigmaRule

from sigma_beam.conditions import compile_rule


def _rule(body: str):
    return SigmaRule.from_yaml(textwrap.dedent(body))


def test_case_insensitive_default():
    r = _rule("""
        title: t
        logsource: {product: x}
        detection:
            sel: {User: ALICE}
            condition: sel
    """)
    p = compile_rule(r)
    assert p({"User": "alice"})       # default = case insensitive
    assert p({"User": "Alice"})
    assert not p({"User": "bob"})


def test_cased_modifier_opt_in():
    r = _rule("""
        title: t
        logsource: {product: x}
        detection:
            sel: {User|cased: Alice}
            condition: sel
    """)
    p = compile_rule(r)
    assert p({"User": "Alice"})
    assert not p({"User": "alice"})
    assert not p({"User": "ALICE"})


def test_wildcard_case_insensitive():
    r = _rule("""
        title: t
        logsource: {product: x}
        detection:
            sel: {Image|endswith: '.EXE'}
            condition: sel
    """)
    p = compile_rule(r)
    assert p({"Image": "C:\\\\foo\\\\bar.exe"})
    assert p({"Image": "x.ExE"})


def test_gte_operator_modifier():
    r = _rule("""
        title: t
        logsource: {product: x}
        detection:
            sel: {Count|gte: 5}
            condition: sel
    """)
    p = compile_rule(r)
    assert p({"Count": 5})
    assert p({"Count": 10})
    assert not p({"Count": 4})
    assert not p({"Count": "not a number"})
    assert not p({})


def test_lt_operator_modifier():
    r = _rule("""
        title: t
        logsource: {product: x}
        detection:
            sel: {Bytes|lt: 1024}
            condition: sel
    """)
    p = compile_rule(r)
    assert p({"Bytes": 100})
    assert not p({"Bytes": 1024})
    assert not p({"Bytes": 2048})


def test_exists_true():
    r = _rule("""
        title: t
        logsource: {product: x}
        detection:
            sel: {Optional|exists: true}
            condition: sel
    """)
    p = compile_rule(r)
    assert p({"Optional": "anything"})
    assert p({"Optional": None})    # present-and-None still "exists"
    assert not p({})


def test_exists_false():
    r = _rule("""
        title: t
        logsource: {product: x}
        detection:
            sel: {Optional|exists: false}
            condition: sel
    """)
    p = compile_rule(r)
    assert not p({"Optional": "x"})
    assert p({})


def test_fieldref_equality():
    r = _rule("""
        title: t
        logsource: {product: x}
        detection:
            sel: {SourceUser|fieldref: TargetUser}
            condition: sel
    """)
    p = compile_rule(r)
    assert p({"SourceUser": "alice", "TargetUser": "alice"})
    assert p({"SourceUser": "Alice", "TargetUser": "ALICE"})  # case-insensitive
    assert not p({"SourceUser": "alice", "TargetUser": "bob"})
    assert not p({"SourceUser": "alice"})


def test_windash_expansion():
    r = _rule("""
        title: t
        logsource: {product: x}
        detection:
            sel: {CommandLine|windash|contains: '-encoded'}
            condition: sel
    """)
    p = compile_rule(r)
    assert p({"CommandLine": "powershell -encoded ABC"})
    assert p({"CommandLine": "powershell /encoded ABC"})   # windash variant
    assert not p({"CommandLine": "powershell --safe"})


def test_base64_modifier():
    r = _rule("""
        title: t
        logsource: {product: x}
        detection:
            sel: {CommandLine|base64: echo}
            condition: sel
    """)
    p = compile_rule(r)
    # pySigma base64-encodes the value; we match the encoded literal.
    # "echo" → "ZWNobw==" (case-insensitive default applies).
    assert p({"CommandLine": "ZWNobw=="})
    assert p({"CommandLine": "zwnobw=="})  # case-insensitive
    assert not p({"CommandLine": "echo"})


def test_base64offset_contains_modifier():
    # |base64offset|contains expands into multiple offset-shifted base64 strings,
    # any of which substring-matches the field.
    r = _rule("""
        title: t
        logsource: {product: x}
        detection:
            sel: {CommandLine|base64offset|contains: net user}
            condition: sel
    """)
    p = compile_rule(r)
    # One of pySigma's offset encodings of "net user" → bmV0IHVzZXI=
    assert p({"CommandLine": "powershell -enc bmV0IHVzZXI="})


def test_compound_or_in_field_list():
    r = _rule("""
        title: t
        logsource: {product: x}
        detection:
            sel:
                Image|endswith:
                    - '.exe'
                    - '.dll'
                EventID: 1
            condition: sel
    """)
    p = compile_rule(r)
    assert p({"Image": "x.exe", "EventID": 1})
    assert p({"Image": "x.dll", "EventID": 1})
    assert not p({"Image": "x.txt", "EventID": 1})
    assert not p({"Image": "x.exe", "EventID": 2})


def test_wide_modifier():
    # pySigma's |wide encodes the value with null bytes between chars; our
    # SigmaString matcher then matches the resulting literal as a substring.
    r = _rule("""
        title: t
        logsource: {product: x}
        detection:
            sel: {Data|wide|contains: secret}
            condition: sel
    """)
    p = compile_rule(r)
    assert p({"Data": "s\x00e\x00c\x00r\x00e\x00t\x00"})
    assert not p({"Data": "secret"})  # plain ASCII shouldn't match wide-encoded


def test_expand_placeholder():
    """With a placeholder table supplied via the loader, |expand rules work."""
    from pathlib import Path
    from sigma_beam.loader import load_from_dir
    import tempfile

    rule_yaml = """\
title: admin detection
id: 00000000-0000-0000-0000-000000000001
logsource: {product: x}
detection:
    sel:
        User|expand: '%admin_users%'
    condition: sel
level: medium
"""
    with tempfile.TemporaryDirectory() as td:
        (Path(td) / "rule.yml").write_text(rule_yaml)
        rs = load_from_dir(td, placeholders={"admin_users": ["alice", "bob"]})
    p = rs.single_event[0].predicate
    assert p({"User": "alice"})
    assert p({"User": "bob"})
    assert not p({"User": "mallory"})
