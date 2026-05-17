"""End-to-end tests of compile_rule on hand-written Sigma YAML."""

import textwrap

import pytest
from sigma.rule import SigmaRule

from sigma_beam.conditions import compile_rule


def _rule(body: str) -> SigmaRule:
    return SigmaRule.from_yaml(textwrap.dedent(body))


def test_basic_field_equals():
    r = _rule("""
        title: t
        logsource: {product: windows}
        detection:
            sel: {EventID: 4624}
            condition: sel
    """)
    p = compile_rule(r)
    assert p({"EventID": 4624})
    assert not p({"EventID": 4625})
    assert not p({})


def test_and_of_two_selections():
    r = _rule("""
        title: t
        logsource: {product: windows}
        detection:
            sel1: {EventID: 4624}
            sel2: {User: alice}
            condition: sel1 and sel2
    """)
    p = compile_rule(r)
    assert p({"EventID": 4624, "User": "alice"})
    assert not p({"EventID": 4624, "User": "bob"})
    assert not p({"EventID": 4625, "User": "alice"})


def test_or_and_not():
    r = _rule("""
        title: t
        logsource: {product: windows}
        detection:
            sel1: {EventID: 1}
            sel2: {EventID: 2}
            sel3: {User: root}
            condition: (sel1 or sel2) and not sel3
    """)
    p = compile_rule(r)
    assert p({"EventID": 1, "User": "alice"})
    assert p({"EventID": 2, "User": "alice"})
    assert not p({"EventID": 1, "User": "root"})
    assert not p({"EventID": 3, "User": "alice"})


def test_endswith_modifier():
    r = _rule("""
        title: t
        logsource: {product: windows}
        detection:
            sel:
                Image|endswith:
                    - '.exe'
                    - '.dll'
            condition: sel
    """)
    p = compile_rule(r)
    assert p({"Image": "C:\\\\windows\\\\foo.exe"})
    assert p({"Image": "x.dll"})
    assert not p({"Image": "foo.txt"})


def test_contains_all():
    r = _rule("""
        title: t
        logsource: {product: windows}
        detection:
            sel:
                CommandLine|contains|all:
                    - foo
                    - bar
            condition: sel
    """)
    p = compile_rule(r)
    assert p({"CommandLine": "x foo y bar z"})
    assert not p({"CommandLine": "x foo y z"})


def test_re_modifier():
    r = _rule("""
        title: t
        logsource: {product: windows}
        detection:
            sel:
                Image|re: '\\.(exe|dll)$'
            condition: sel
    """)
    p = compile_rule(r)
    assert p({"Image": "foo.exe"})
    assert p({"Image": "bar.dll"})
    assert not p({"Image": "baz.txt"})


def test_cidr_modifier():
    r = _rule("""
        title: t
        logsource: {product: windows}
        detection:
            sel:
                SourceIP|cidr: '10.0.0.0/8'
            condition: sel
    """)
    p = compile_rule(r)
    assert p({"SourceIP": "10.5.6.7"})
    assert not p({"SourceIP": "11.0.0.1"})
    assert not p({"SourceIP": "not-an-ip"})


def test_keyword_search():
    r = _rule("""
        title: t
        logsource: {product: windows}
        detection:
            kw: ['hello world']
            condition: kw
    """)
    p = compile_rule(r)
    assert p({"msg": "hello world"})
    assert p({"nested": {"deep": "hello world"}})
    assert not p({"msg": "goodbye"})


def test_1_of():
    r = _rule("""
        title: t
        logsource: {product: windows}
        detection:
            sel_a: {a: 1}
            sel_b: {b: 2}
            sel_c: {c: 3}
            condition: 1 of sel_*
    """)
    p = compile_rule(r)
    assert p({"a": 1})
    assert p({"b": 2})
    assert p({"c": 3})
    assert not p({"a": 0, "b": 0, "c": 0})


def test_all_of():
    r = _rule("""
        title: t
        logsource: {product: windows}
        detection:
            sel_a: {a: 1}
            sel_b: {b: 2}
            condition: all of sel_*
    """)
    p = compile_rule(r)
    assert p({"a": 1, "b": 2})
    assert not p({"a": 1})


def test_null_match():
    r = _rule("""
        title: t
        logsource: {product: windows}
        detection:
            sel: {Field: null}
            condition: sel
    """)
    p = compile_rule(r)
    assert p({})
    assert p({"Field": None})
    assert not p({"Field": "present"})


def test_nested_field_access():
    r = _rule("""
        title: t
        logsource: {product: windows}
        detection:
            sel: {'event.user.name': alice}
            condition: sel
    """)
    p = compile_rule(r)
    assert p({"event": {"user": {"name": "alice"}}})
    assert not p({"event": {"user": {"name": "bob"}}})


def test_value_list_is_or():
    r = _rule("""
        title: t
        logsource: {product: windows}
        detection:
            sel:
                EventID:
                    - 4624
                    - 4625
            condition: sel
    """)
    p = compile_rule(r)
    assert p({"EventID": 4624})
    assert p({"EventID": 4625})
    assert not p({"EventID": 4626})


def test_bool_match():
    r = _rule("""
        title: t
        logsource: {product: windows}
        detection:
            sel: {Elevated: true}
            condition: sel
    """)
    p = compile_rule(r)
    assert p({"Elevated": True})
    assert not p({"Elevated": False})


def test_missing_field_is_false_not_raise():
    r = _rule("""
        title: t
        logsource: {product: windows}
        detection:
            sel: {Image|endswith: '.exe'}
            condition: sel
    """)
    p = compile_rule(r)
    assert not p({})
    assert not p({"Image": None})
    assert not p({"Image": 42})  # numeric coerced via str → '42', no .exe
