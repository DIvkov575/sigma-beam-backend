"""SingleEventDetect PTransform.

Fans every event through every single-event rule's predicate. Emits one
`Alert` per (event, rule) match on the main output. Per-rule evaluation
errors (predicate raised) go to the `errors` tagged output.
"""

from __future__ import annotations

from typing import Any

import apache_beam as beam
from apache_beam import pvalue

from . import metrics as m
from .alerts import Alert
from .dlq import format_dlq
from .ruleset import CompiledRule

MAIN = "alerts"
DLQ = "dlq"


class _DetectDoFn(beam.DoFn):
    def __init__(self, rules: list[CompiledRule]) -> None:
        self._rules = rules
        # Counters resolved lazily per worker; can't construct on __init__
        # because the Beam metrics layer needs an active context.
        self._evaluated = None
        self._match_counters: dict[str, Any] = {}
        self._error_counters: dict[str, Any] = {}

    def setup(self) -> None:
        self._evaluated = m.evaluated()
        for r in self._rules:
            self._match_counters[r.id] = m.matches(r.id)
            self._error_counters[r.id] = m.errors(r.id)

    def process(self, event: dict):
        self._evaluated.inc()
        for r in self._rules:
            try:
                hit = r.predicate(event)
            except Exception as exc:  # noqa: BLE001 — we DLQ everything
                self._error_counters[r.id].inc()
                yield pvalue.TaggedOutput(
                    DLQ,
                    format_dlq("predicate raised", event, exc, rule_id=r.id),
                )
                continue
            if hit:
                self._match_counters[r.id].inc()
                yield Alert(
                    rule_id=r.id,
                    rule_title=r.title,
                    severity=r.severity,
                    matched_events=[event],
                )


class SingleEventDetect(beam.PTransform):
    """PCollection[dict] → (MAIN: PCollection[Alert], DLQ: PCollection[bytes])."""

    def __init__(self, rules: list[CompiledRule]) -> None:
        super().__init__()
        self._rules = rules

    def expand(self, pcoll):
        return pcoll | "Detect" >> beam.ParDo(
            _DetectDoFn(self._rules)
        ).with_outputs(DLQ, main=MAIN)
