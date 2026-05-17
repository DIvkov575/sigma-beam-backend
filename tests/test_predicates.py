import re

from sigma_beam.field_access import MISSING
from sigma_beam import predicates as p


def test_equals():
    f = p.equals(4624)
    assert f(4624)
    assert not f(4625)
    assert not f(MISSING)


def test_contains():
    f = p.contains("powershell")
    assert f("C:\\windows\\powershell.exe")
    assert not f("cmd.exe")
    assert not f(MISSING)
    assert not f(None)


def test_startswith_endswith():
    assert p.startswith("C:\\")("C:\\windows")
    assert not p.startswith("C:\\")("D:\\")
    assert p.endswith(".exe")("foo.exe")
    assert not p.endswith(".exe")("foo.dll")


def test_re_match():
    f = p.re_match(r"^\d{4}$")
    assert f("1234")
    assert not f("abc")
    assert not f(MISSING)


def test_re_flags():
    f = p.re_match(r"powershell", re.IGNORECASE)
    assert f("PowerShell.exe")


def test_cidr_contains():
    f = p.cidr_contains("10.0.0.0/8")
    assert f("10.5.6.7")
    assert not f("11.0.0.1")
    assert not f("not-an-ip")
    assert not f(MISSING)


def test_numeric_comparisons():
    assert p.gt(5)(10)
    assert not p.gt(5)(5)
    assert p.gte(5)(5)
    assert p.lt(5)(3)
    assert p.lte(5)(5)
    assert p.gt(5)("10")          # string coerced
    assert not p.gt(5)("abc")
    assert not p.gt(5)(MISSING)
    assert not p.gt(5)(None)
    assert not p.gt(5)(True)      # bool rejected


def test_in_list():
    f = p.in_list([1, 2, 3])
    assert f(2)
    assert not f(4)
    assert not f(MISSING)


def test_in_list_unhashable_value_returns_false():
    f = p.in_list([1, 2, 3])
    assert not f([1, 2])


def test_any_of_all_of():
    f = p.any_of([p.equals(1), p.equals(2)])
    assert f(1) and f(2) and not f(3)
    g = p.all_of([p.gt(0), p.lt(10)])
    assert g(5) and not g(11) and not g(-1)


def test_never_raises():
    # Throw a bunch of weird inputs at every predicate; nothing should explode.
    weird = [MISSING, None, 0, "", [], {}, object()]
    preds = [
        p.equals("x"), p.contains("x"), p.startswith("x"), p.endswith("x"),
        p.re_match("x"), p.cidr_contains("10.0.0.0/8"),
        p.gt(0), p.in_list([1, 2]),
    ]
    for v in weird:
        for pr in preds:
            pr(v)  # must not raise
