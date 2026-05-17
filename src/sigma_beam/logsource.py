"""Logsource filtering.

A Sigma rule's `logsource` (product / category / service) declares which
log stream it applies to. With no filtering, Windows rules fire on AWS
events and vice versa — almost never what you want.

A `LogsourceFilter` is a callable that, given a `SigmaLogSource`, returns
either a predicate `(event: dict) -> bool` that decides whether an event
matches the rule's stream, or `None` to skip filtering for that source.

Operators wire up a filter at deploy time (different shops carry source
identifiers in different event fields — `eventSource`, `_index`,
`data_stream.dataset`, etc. — so we don't pick one for them).
"""

from __future__ import annotations

from typing import Callable, Optional

from sigma.rule import SigmaLogSource

from .conditions import Predicate

LogsourceFilter = Callable[[SigmaLogSource], Optional[Predicate]]


def null_filter(_ls: SigmaLogSource) -> None:
    """Default policy: no filtering, every rule sees every event."""
    return None


def dataset_field_filter(field: str) -> LogsourceFilter:
    """Build a filter that matches `event[field]` against `<product>.<service>`
    or `<product>.<category>`. Common shape used by Elastic Common Schema
    (`data_stream.dataset = windows.security`).
    """

    def factory(ls: SigmaLogSource) -> Optional[Predicate]:
        product = (ls.product or "").lower()
        category = (ls.category or "").lower()
        service = (ls.service or "").lower()
        if not product:
            return None
        candidates = set()
        if service:
            candidates.add(f"{product}.{service}")
        if category:
            candidates.add(f"{product}.{category}")
        if not service and not category:
            candidates.add(product)
        if not candidates:
            return None

        # Late import to avoid circulars; field_access already in tree.
        from .field_access import MISSING, get_field

        def predicate(event: dict) -> bool:
            v = get_field(event, field)
            return v is not MISSING and isinstance(v, str) and v.lower() in candidates

        return predicate

    return factory


def product_field_filter(field: str = "product") -> LogsourceFilter:
    """Simpler policy: just require `event[field] == ls.product`."""

    def factory(ls: SigmaLogSource) -> Optional[Predicate]:
        product = (ls.product or "").lower()
        if not product:
            return None
        from .field_access import MISSING, get_field

        def predicate(event: dict) -> bool:
            v = get_field(event, field)
            return v is not MISSING and isinstance(v, str) and v.lower() == product

        return predicate

    return factory
