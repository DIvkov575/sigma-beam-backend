import apache_beam as beam
from apache_beam.testing.test_pipeline import TestPipeline
from apache_beam.testing.util import assert_that, equal_to

from sigma_beam.alerts import Alert
from sigma_beam.ruleset import CompiledRule
from sigma_beam.single_event import DLQ, MAIN, SingleEventDetect


def _rule(rid: str, pred):
    return CompiledRule(id=rid, title=f"t-{rid}", severity="medium", predicate=pred)


def _alert_keys(a: Alert):
    return (a.rule_id, a.severity, tuple(sorted(a.matched_events[0].items())))


def test_single_event_match_and_miss():
    events = [{"a": 1}, {"a": 2}, {"b": 3}]
    rules = [
        _rule("R1", lambda e: e.get("a") == 1),
        _rule("R2", lambda e: e.get("b") == 3),
    ]

    with TestPipeline() as p:
        out = (
            p
            | beam.Create(events)
            | SingleEventDetect(rules)
        )

        def _ids(alerts):
            return sorted((a.rule_id, tuple(sorted(a.matched_events[0].items()))) for a in alerts)

        assert_that(
            out[MAIN] | "Norm" >> beam.Map(lambda a: (a.rule_id, tuple(sorted(a.matched_events[0].items())))),
            equal_to([
                ("R1", (("a", 1),)),
                ("R2", (("b", 3),)),
            ]),
        )


def test_single_event_predicate_raises_goes_to_dlq():
    def boom(e):
        raise RuntimeError("kaboom")

    rules = [
        _rule("OK", lambda e: e.get("ok") is True),
        _rule("BAD", boom),
    ]
    events = [{"ok": True}]

    with TestPipeline() as p:
        out = (
            p
            | beam.Create(events)
            | SingleEventDetect(rules)
        )
        assert_that(
            out[MAIN] | "Ids" >> beam.Map(lambda a: a.rule_id),
            equal_to(["OK"]),
            label="alerts",
        )
        assert_that(
            out[DLQ] | "DlqCount" >> beam.combiners.Count.Globally(),
            equal_to([1]),
            label="dlq",
        )
