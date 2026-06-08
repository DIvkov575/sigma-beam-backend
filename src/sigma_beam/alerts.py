"""Alert dataclass + JSON (de)serialization."""

from __future__ import annotations

import dataclasses
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _dumps(obj: Any) -> str:
    """Single source of truth for alert JSON encoding policy.

    `default=str` lets non-JSON-native values (e.g. datetimes) serialize, and
    `sort_keys=True` makes the output deterministic across runs/field order.
    """
    return json.dumps(obj, default=str, sort_keys=True)


@dataclass
class Alert:
    rule_id: str
    rule_title: str
    severity: str
    fired_at: str = field(default_factory=_iso_now)
    window_start: str | None = None
    window_end: str | None = None
    correlation_key: str | None = None
    matched_events: list[dict[str, Any]] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)

    def to_json(self) -> str:
        return _dumps(dataclasses.asdict(self))

    def to_bytes(self) -> bytes:
        return self.to_json().encode("utf-8")

    def to_bq_bytes(self) -> bytes:
        """Serialize for a Pub/Sub→BigQuery subscription using `use_table_schema`.

        The `alerts` table types `matched_events` and `tags` as JSON columns. A
        BigQuery subscription maps those from message fields that are JSON
        *strings*, not native nested values — emitting native arrays makes
        BigQuery reject the row with `invalid_argument` (the rows are silently
        dropped, never reaching the table). Encode those two fields as JSON
        strings so the write succeeds.
        """
        d = dataclasses.asdict(self)
        d["matched_events"] = _dumps(d["matched_events"])
        d["tags"] = _dumps(d["tags"])
        return _dumps(d).encode("utf-8")
