"""pySigma processing pipelines: apply per-logsource transformations at
load time so rules written against a high-level category (`process_creation`)
match the concrete shape of the underlying log (Sysmon EventID=1 + the
expected field names).

A `PipelineSelector` returns 0..N pySigma `ProcessingPipeline` objects to
apply to a rule based on its logsource. Default = no pipelines.

`default_selector()` returns a selector covering whichever pySigma pipeline
plugins are installed at import time (currently sysmon + windows). New
plugins (CrowdStrike Falcon, AWS, etc.) plug in by editing the table.
"""

from __future__ import annotations

import importlib
import logging
from typing import Callable, Iterable

from sigma.rule import SigmaLogSource

try:
    from sigma.processing.pipeline import ProcessingPipeline
except ImportError:  # pragma: no cover — pysigma is a hard dep
    ProcessingPipeline = object  # type: ignore

log = logging.getLogger(__name__)

PipelineSelector = Callable[[SigmaLogSource], Iterable[ProcessingPipeline]]


def null_selector(_ls: SigmaLogSource) -> Iterable[ProcessingPipeline]:
    return ()


def _try_import(modpath: str, attr: str):
    try:
        mod = importlib.import_module(modpath)
        return getattr(mod, attr)
    except (ImportError, AttributeError) as exc:
        log.info("pipeline plugin not available: %s.%s (%s)", modpath, attr, exc)
        return None


def default_selector() -> PipelineSelector:
    """Pipelines wired up by default when their plugin is installed."""
    sysmon = _try_import("sigma.pipelines.sysmon", "sysmon_pipeline")

    def selector(ls: SigmaLogSource) -> Iterable[ProcessingPipeline]:
        out = []
        product = (ls.product or "").lower()
        category = (ls.category or "").lower()
        if product == "windows" and category in {"process_creation", "image_load",
                                                  "network_connection", "registry_event",
                                                  "file_event", "dns_query"}:
            if sysmon is not None:
                out.append(sysmon())
        return out

    return selector


def apply_pipelines(rule, selector: PipelineSelector) -> None:
    """Mutate `rule` in place by applying every pipeline the selector returns."""
    for pipe in selector(rule.logsource):
        try:
            pipe.apply(rule)
        except Exception as exc:
            log.warning("pipeline %r failed on rule %r: %s",
                        pipe, getattr(rule, "id", "?"), exc)
