"""Resolve |expand placeholders at load time using a user-supplied table.

pySigma's |expand modifier emits SigmaExpansion nodes when it can resolve
the placeholder, but leaves them as literal strings when it can't. We walk
the rule's detection items and replace %name% patterns with SigmaExpansion
nodes from the table BEFORE condition compilation.
"""

from __future__ import annotations

import re
from copy import deepcopy

from sigma.rule import SigmaRule
from sigma.types import SigmaExpansion, SigmaString

_PLACEHOLDER_RE = re.compile(r"^%([a-zA-Z0-9_]+)%$")


def resolve_placeholders(
    rule: SigmaRule, table: dict[str, list[str]]
) -> SigmaRule:
    """Return a copy of `rule` with all %placeholder% values expanded.

    Raises ValueError if a placeholder references a name not in `table`.
    """
    if not table:
        _check_no_placeholders(rule, table)
        return deepcopy(rule)

    rule = deepcopy(rule)
    for detection_item in _iter_detection_items(rule):
        for i, val in enumerate(detection_item.value):
            if isinstance(val, SigmaString) and not val.contains_special():
                plain = val.to_plain()
                m = _PLACEHOLDER_RE.match(plain)
                if m:
                    name = m.group(1)
                    if name not in table:
                        raise ValueError(
                            f"placeholder '{name}' not found in table "
                            f"(available: {sorted(table.keys())})"
                        )
                    expanded = SigmaExpansion(
                        [SigmaString(v) for v in table[name]]
                    )
                    detection_item.value[i] = expanded
    return rule


def _check_no_placeholders(rule: SigmaRule, table: dict) -> None:
    for detection_item in _iter_detection_items(rule):
        for val in detection_item.value:
            if isinstance(val, SigmaString) and not val.contains_special():
                m = _PLACEHOLDER_RE.match(val.to_plain())
                if m:
                    raise ValueError(
                        f"placeholder '{m.group(1)}' not found in table "
                        f"(available: {sorted(table.keys())})"
                    )


def _iter_detection_items(rule: SigmaRule):
    """Yield all SigmaDetectionItem objects from a rule's detections."""
    from sigma.rule import SigmaDetection, SigmaDetectionItem
    for det in rule.detection.detections.values():
        if isinstance(det, SigmaDetectionItem):
            yield det
        elif isinstance(det, SigmaDetection):
            for item in det.detection_items:
                if isinstance(item, SigmaDetectionItem):
                    yield item
                elif hasattr(item, "detection_items"):
                    for sub in item.detection_items:
                        if isinstance(sub, SigmaDetectionItem):
                            yield sub
