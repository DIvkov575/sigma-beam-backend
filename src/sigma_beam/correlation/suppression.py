"""Per-correlation alert suppression.

A correlation rule with `beaver.suppress_window_seconds: N` annotation will
emit at most one alert per `correlation_key` per N processing-time seconds.
Subsequent fires for the same key are dropped within the suppression window.

Implementation: stateful DoFn keyed on `correlation_key`, holding the last
fire's Unix timestamp. Re-windowed into the global window because Beam
stateful DoFns require a single window per key.

Use processing-time (`time.time()`) rather than event-time: suppression is
inherently a "don't page me twice" concern, not a property of the events
themselves.
"""

from __future__ import annotations

import time

import apache_beam as beam
from apache_beam.coders import VarIntCoder
from apache_beam.transforms.userstate import ReadModifyWriteStateSpec
from apache_beam.transforms.window import GlobalWindows


class _SuppressDoFn(beam.DoFn):
    LAST = ReadModifyWriteStateSpec("last_fire_unix", VarIntCoder())

    def __init__(self, suppress_seconds: int) -> None:
        self._suppress = int(suppress_seconds)

    def process(self, kv, state=beam.DoFn.StateParam(LAST)):
        _, alert = kv
        now = int(time.time())
        last = state.read() or 0
        if now - last < self._suppress:
            return
        state.write(now)
        yield alert


class Suppress(beam.PTransform):
    """Wrap an alerts PCollection with per-key suppression."""

    def __init__(self, suppress_seconds: int) -> None:
        super().__init__()
        self._suppress = int(suppress_seconds)

    def expand(self, alerts):
        if self._suppress <= 0:
            return alerts
        return (
            alerts
            | "ToGlobal" >> beam.WindowInto(GlobalWindows())
            | "KeyByCorr" >> beam.Map(lambda a: (a.correlation_key or "_", a))
            | "Suppress" >> beam.ParDo(_SuppressDoFn(self._suppress))
        )
