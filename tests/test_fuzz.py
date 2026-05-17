"""Property-based fuzz: random nested dicts vs. every compiled rule.

Invariants:
- Every predicate returns a bool (not None, not raises, not non-bool truthy).
- The result is independent of irrelevant key additions (limited check —
  adding a fresh unrelated key shouldn't change the verdict).

Runs against the SigmaHQ corpus if SIGMA_HQ_PATH is set; otherwise falls
back to the bundled smoke corpus so the property holds for our own
fixtures too.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from sigma_beam.loader import load_from_dir

_SIGMA_HQ = os.environ.get("SIGMA_HQ_PATH")
SMOKE = Path(__file__).parent / "fixtures" / "corpus_smoke"
CORPUS = Path(_SIGMA_HQ) if _SIGMA_HQ and Path(_SIGMA_HQ).is_dir() else SMOKE


def _bounded_value():
    return st.one_of(
        st.none(),
        st.booleans(),
        st.integers(min_value=-(2**31), max_value=2**31),
        st.floats(allow_nan=False, allow_infinity=False, width=32),
        st.text(max_size=64),
    )


def _bounded_dict():
    keys = st.sampled_from([
        "EventID", "User", "Image", "CommandLine", "ParentImage",
        "SourceIP", "dst_port", "src_ip", "eventName", "eventSource",
        "userIdentity", "data_stream", "Count", "Bytes", "Field",
        "msg", "type", "k", "u",
    ])
    return st.dictionaries(
        keys=keys,
        values=st.one_of(_bounded_value(), st.lists(_bounded_value(), max_size=3)),
        max_size=10,
    )


_RULES = load_from_dir(CORPUS).single_event


@pytest.mark.parametrize("rule", _RULES, ids=lambda r: r.id[:8])
@given(event=_bounded_dict())
@settings(
    max_examples=50,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
def test_predicate_returns_bool(rule, event):
    result = rule.predicate(event)
    assert isinstance(result, bool), (
        f"rule {rule.id} returned {type(result).__name__} on {event!r}"
    )


@pytest.mark.parametrize("rule", _RULES, ids=lambda r: r.id[:8])
@given(event=_bounded_dict())
@settings(max_examples=25, deadline=None,
          suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_irrelevant_key_does_not_flip_verdict(rule, event):
    # Adding a key the rule never references must not change the verdict.
    # Use a key we're certain is unused in real Sigma rules.
    sentinel_key = "__fuzz_sentinel_irrelevant_field__"
    base = rule.predicate(dict(event))
    augmented = dict(event)
    augmented[sentinel_key] = "anything goes"
    assert rule.predicate(augmented) == base
