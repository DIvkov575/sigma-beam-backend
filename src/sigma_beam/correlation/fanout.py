"""Dispatch each correlation rule in a Ruleset to the right per-kind transform
and flatten all resulting Alert PCollections into a single output."""

from __future__ import annotations

import apache_beam as beam

from ..ruleset import Ruleset
from .event_count import EventCountCorrelation
from .temporal import TemporalCorrelation
from .temporal_ordered import TemporalOrderedCorrelation
from .value_count import ValueCountCorrelation

_KIND_TO_TRANSFORM = {
    "event_count": EventCountCorrelation,
    "value_count": ValueCountCorrelation,
    "temporal": TemporalCorrelation,
    "temporal_ordered": TemporalOrderedCorrelation,
}


class UnknownCorrelationKind(Exception):
    pass


class CorrelationFanout(beam.PTransform):
    """PCollection[dict] → PCollection[Alert] across every correlation rule."""

    def __init__(self, ruleset: Ruleset) -> None:
        super().__init__()
        self._rs = ruleset

    def expand(self, pcoll):
        rs = self._rs
        by_id = rs.rules_by_id()
        if not rs.correlation:
            return pcoll | "EmptyFanout" >> beam.Filter(lambda _: False) \
                         | "AsAlert" >> beam.Map(lambda _: None)

        branches = []
        for c in rs.correlation:
            cls = _KIND_TO_TRANSFORM.get(c.kind)
            if cls is None:
                raise UnknownCorrelationKind(c.kind)
            refs = [by_id[r] for r in c.referenced_rule_ids if r in by_id]
            if not refs:
                continue  # nothing references it; skip silently
            branches.append(
                pcoll | f"Correlation[{c.id}]" >> cls(c, refs)
            )

        return branches | "FlattenAlerts" >> beam.Flatten()
