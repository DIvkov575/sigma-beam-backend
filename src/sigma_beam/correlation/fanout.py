"""Dispatch each correlation rule in a Ruleset to the right per-kind transform
and flatten all resulting Alert PCollections into a single output.

Nested correlations run as a second stage: first-level alerts are converted
to event dicts and fed through the nested rules' transforms."""

from __future__ import annotations

import apache_beam as beam

from ..ruleset import CompiledCorrelation, CompiledRule, Ruleset
from .event_count import EventCountCorrelation
from .nested import AlertsToEvents
from .temporal import TemporalCorrelation
from .temporal_ordered import TemporalOrderedCorrelation
from .percentile import PercentileCorrelation
from .value_count import ValueCountCorrelation

_KIND_TO_TRANSFORM = {
    "event_count": EventCountCorrelation,
    "value_count": ValueCountCorrelation,
    "temporal": TemporalCorrelation,
    "temporal_ordered": TemporalOrderedCorrelation,
    "percentile": PercentileCorrelation,
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

        branches = []

        for c in rs.correlation:
            cls = _KIND_TO_TRANSFORM.get(c.kind)
            if cls is None:
                raise UnknownCorrelationKind(c.kind)
            refs = [by_id[r] for r in c.referenced_rule_ids if r in by_id]
            if not refs:
                continue
            branches.append(
                pcoll | f"Correlation[{c.id}]" >> cls(c, refs)
            )

        if not branches and not rs.nested_correlation:
            return pcoll | "EmptyFanout" >> beam.Filter(lambda _: False) \
                         | "AsAlert" >> beam.Map(lambda _: None)

        if not branches:
            return pcoll | "EmptyFanout2" >> beam.Filter(lambda _: False) \
                         | "AsAlert2" >> beam.Map(lambda _: None)

        first_level_alerts = branches | "FlattenFirstLevel" >> beam.Flatten()

        if rs.nested_correlation:
            corr_by_id = rs.correlations_by_id()
            alert_events = first_level_alerts | "AlertsToEvents" >> AlertsToEvents()

            nested_branches = []
            for nc in rs.nested_correlation:
                cls = _KIND_TO_TRANSFORM.get(nc.kind)
                if cls is None:
                    raise UnknownCorrelationKind(nc.kind)
                refs = _build_nested_refs(nc, corr_by_id)
                if not refs:
                    continue
                nested_branches.append(
                    alert_events | f"Nested[{nc.id}]" >> cls(nc, refs)
                )

            if nested_branches:
                nested_alerts = nested_branches | "FlattenNested" >> beam.Flatten()
                return [first_level_alerts, nested_alerts] | "FlattenAll" >> beam.Flatten()

        return first_level_alerts


def _build_nested_refs(
    nc: CompiledCorrelation, corr_by_id: dict[str, CompiledCorrelation]
) -> list[CompiledRule]:
    """Build synthetic CompiledRule objects that match alert-events by rule_id."""
    refs = []
    for ref_id in nc.referenced_rule_ids:
        if ref_id not in corr_by_id:
            continue

        def _make_pred(rid: str):
            def pred(event: dict) -> bool:
                return event.get("rule_id") == rid
            return pred

        refs.append(CompiledRule(
            id=ref_id,
            title=f"(nested ref: {ref_id})",
            severity="internal",
            predicate=_make_pred(ref_id),
        ))
    return refs
