"""End-to-end test using DirectRunner, no Pub/Sub.

Constructs a Ruleset from disk fixtures, applies SingleEventDetect +
CorrelationFanout to an in-memory PCollection, and asserts the union of
alerts contains both shapes.
"""

from datetime import datetime, timedelta, timezone
from pathlib import Path

import apache_beam as beam
from apache_beam.testing.test_pipeline import TestPipeline
from apache_beam.testing.util import assert_that, equal_to

from sigma_beam.correlation.fanout import CorrelationFanout
from sigma_beam.loader import load_from_dir
from sigma_beam.single_event import MAIN, SingleEventDetect

FIX = Path(__file__).parent / "fixtures" / "rules"


def _ts(s):
    return (datetime(2026, 5, 16, tzinfo=timezone.utc) + timedelta(seconds=s)).isoformat()


def test_e2e_single_event_and_correlation():
    rs = load_from_dir(FIX)
    # Fixture rules: single-event matches EventID=4625; correlation fires on >=5 such events per User.
    events = [
        {"EventID": 4625, "User": "alice", "timestamp": _ts(i)} for i in range(5)
    ] + [{"EventID": 4624, "User": "alice", "timestamp": _ts(10)}]   # noise

    from apache_beam.transforms.window import GlobalWindows

    with TestPipeline() as p:
        coll = p | beam.Create(events)
        se = coll | "Single" >> SingleEventDetect(rs.single_event)
        corr = coll | "Corr" >> CorrelationFanout(rs)
        # Realign both to the global window before flattening.
        se_g = se[MAIN] | "SeGlobal" >> beam.WindowInto(GlobalWindows())
        corr_g = corr | "CorrGlobal" >> beam.WindowInto(GlobalWindows())
        alerts = (se_g, corr_g) | "Flatten" >> beam.Flatten()

        # 5 single-event alerts (one per matching event) + 1 correlation alert
        assert_that(
            alerts | beam.combiners.Count.Globally(),
            equal_to([6]),
        )
