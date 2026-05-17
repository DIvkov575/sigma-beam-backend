from sigma_beam.field_access import MISSING, get_field


def test_flat_key():
    assert get_field({"a": 1}, "a") == 1


def test_nested_dotted():
    assert get_field({"a": {"b": {"c": "x"}}}, "a.b.c") == "x"


def test_missing_returns_sentinel():
    assert get_field({"a": 1}, "b") is MISSING
    assert get_field({"a": {"b": 1}}, "a.c") is MISSING


def test_explicit_none_is_not_missing():
    assert get_field({"a": None}, "a") is None


def test_array_index():
    assert get_field({"logs": [{"message": "first"}, {"message": "second"}]},
                     "logs.1.message") == "second"


def test_array_index_oob():
    assert get_field({"logs": []}, "logs.0") is MISSING


def test_traversal_into_scalar():
    assert get_field({"a": 5}, "a.b") is MISSING


def test_empty_path():
    assert get_field({"a": 1}, "") is MISSING


def test_case_sensitive():
    assert get_field({"EventID": 4624}, "eventid") is MISSING
    assert get_field({"EventID": 4624}, "EventID") == 4624


def test_missing_bool_false():
    assert not MISSING
