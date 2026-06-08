"""Alert dataclass + JSON (de)serialization."""

from __future__ import annotations

import dataclasses
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


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

    def to_json(self) -> str:
        return json.dumps(dataclasses.asdict(self), default=str, sort_keys=True)

    def to_bytes(self) -> bytes:
        return self.to_json().encode("utf-8")

    def to_bq_bytes(self) -> bytes:
        """Serialize for Pub/Sub→BigQuery subscription (use_table_schema).

        BQ JSON columns must receive a JSON *string*, not a native array.
        """
        d = dataclasses.asdict(self)
        d["matched_events"] = json.dumps(d["matched_events"], default=str)
        d["tags"] = json.dumps(d.get("tags", []), default=str)
        return json.dumps(d, default=str, sort_keys=True).encode("utf-8")
