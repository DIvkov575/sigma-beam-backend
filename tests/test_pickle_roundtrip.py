"""Verify that CompiledRule predicates survive cloudpickle roundtrip.

Dataflow serializes all DoFns/lambdas via cloudpickle to ship to workers.
If any predicate closure captures a non-picklable object, the job fails
at graph construction time.
"""
import pickle
from pathlib import Path

import cloudpickle

from sigma_beam.loader import load_from_dir

FIXTURES = Path(__file__).parent / "fixtures" / "rules"


def test_single_event_rules_pickle_roundtrip():
    rs = load_from_dir(FIXTURES)
    for rule in rs.single_event:
        data = cloudpickle.dumps(rule)
        restored = pickle.loads(data)
        assert restored.id == rule.id
        assert restored.predicate({"EventID": 4625}) == rule.predicate({"EventID": 4625})
        assert restored.predicate({"EventID": 9999}) == rule.predicate({"EventID": 9999})


def test_correlation_rules_pickle_roundtrip():
    rs = load_from_dir(FIXTURES)
    for corr in rs.correlation:
        data = cloudpickle.dumps(corr)
        restored = pickle.loads(data)
        assert restored.id == corr.id
        assert restored.kind == corr.kind


def test_lambda_over_refs_pickles():
    from sigma_beam.correlation._common import passes_any_referenced_rule

    rs = load_from_dir(FIXTURES)
    refs = list(rs.single_event)
    fn = lambda e: passes_any_referenced_rule(e, refs)
    data = cloudpickle.dumps(fn)
    restored_fn = pickle.loads(data)
    assert restored_fn({"EventID": 4625}) == fn({"EventID": 4625})
    assert restored_fn({"EventID": 9999}) == fn({"EventID": 9999})
