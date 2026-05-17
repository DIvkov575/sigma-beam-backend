"""Dead-letter helpers: format errors as JSON envelopes the pipeline can sink."""

from __future__ import annotations

import json
import traceback
from typing import Any


def format_dlq(reason: str, event: Any, exc: BaseException | None = None,
               rule_id: str | None = None) -> bytes:
    payload = {
        "reason": reason,
        "rule_id": rule_id,
        "event": event,
        "error": str(exc) if exc else None,
        "trace": traceback.format_exc() if exc else None,
    }
    return json.dumps(payload, default=str, sort_keys=True).encode("utf-8")
