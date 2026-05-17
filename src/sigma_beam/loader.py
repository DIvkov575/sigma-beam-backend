"""Load Sigma rules from disk (or GCS) into a `Ruleset`."""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Iterable

from sigma.collection import SigmaCollection
from sigma.correlations import SigmaCorrelationRule
from sigma.rule import SigmaRule

from .conditions import compile_rule
from .logsource import LogsourceFilter, null_filter
from .processing import PipelineSelector, apply_pipelines, null_selector
from .ruleset import CompiledCorrelation, CompiledRule, Ruleset

log = logging.getLogger(__name__)


# Cardinality linter: refuse a group-by on any field name in this set unless
# the rule explicitly opts in. List is conservative — anything where the
# per-key state size scales with traffic.
HIGH_CARDINALITY_FIELDS = {
    "user_agent", "useragent", "url", "uri", "request_id", "trace_id",
    "session_id", "message_id", "timestamp", "ts",
}

# Map of "5m" / "1h" → seconds is delivered by pySigma's
# SigmaCorrelationTimespan.seconds. We just trust it.

# pySigma's condition op enum stringifies as e.g. "SigmaCorrelationConditionOperator.GTE"
_OP_MAP = {"GTE": "gte", "GT": "gt", "LTE": "lte", "LT": "lt", "EQ": "eq"}


class RuleLoadError(Exception):
    pass


def _extract_severity(rule) -> str:
    lvl = getattr(rule, "level", None)
    if lvl is None:
        return "medium"
    return getattr(lvl, "name", str(lvl)).lower()


def _annotation(rule, key: str, default):
    custom = getattr(rule, "custom_attributes", None) or {}
    beaver = custom.get("beaver", {})
    if isinstance(beaver, dict):
        return beaver.get(key, default)
    return default


def _lint_correlation(c: CompiledCorrelation) -> None:
    if c.allow_high_cardinality:
        return
    bad = [g for g in c.group_by if g.lower() in HIGH_CARDINALITY_FIELDS]
    if bad:
        raise RuleLoadError(
            f"correlation rule {c.id!r} groups by high-cardinality field(s) "
            f"{bad}; set `beaver.allow_high_cardinality: true` to override"
        )


def _compile_single(
    rule: SigmaRule,
    source_path: str | None,
    logsource_filter: LogsourceFilter = null_filter,
) -> CompiledRule:
    detection = compile_rule(rule)
    ls_pred = logsource_filter(rule.logsource) if rule.logsource else None
    if ls_pred is None:
        predicate = detection
    else:
        def predicate(e: dict) -> bool:
            return ls_pred(e) and detection(e)
    return CompiledRule(
        id=str(rule.id),
        title=rule.title or "",
        severity=_extract_severity(rule),
        predicate=predicate,
        source_path=source_path,
    )


def _compile_correlation(
    rule: SigmaCorrelationRule, source_path: str | None
) -> CompiledCorrelation:
    refs = tuple(str(r.reference) for r in rule.rules)
    cond = rule.condition
    threshold = getattr(cond, "count", None) if cond else None
    op_name = (
        cond.op.name if cond and getattr(cond, "op", None) is not None else "GTE"
    )
    op = _OP_MAP.get(op_name, "gte")
    value_field = getattr(cond, "fieldref", None) if cond else None

    kind = str(rule.type).split(".")[-1].lower() if hasattr(rule.type, "name") else str(rule.type).lower()
    # pySigma SigmaCorrelationType enum: event_count, value_count, temporal, temporal_ordered.

    return CompiledCorrelation(
        id=str(rule.id),
        title=rule.title or "",
        severity=_extract_severity(rule),
        kind=kind,
        referenced_rule_ids=refs,
        group_by=tuple(rule.group_by or ()),
        window_seconds=int(rule.timespan.seconds),
        threshold=int(threshold) if threshold is not None else None,
        threshold_op=op,
        value_field=value_field,
        ordered_sequence=refs if kind == "temporal_ordered" else (),
        allowed_lateness_seconds=int(_annotation(rule, "allowed_lateness_seconds", 300)),
        allow_high_cardinality=bool(_annotation(rule, "allow_high_cardinality", False)),
        source_path=source_path,
    )


def _iter_yaml_files(root: Path) -> Iterable[Path]:
    for p in sorted(root.rglob("*.y*ml")):
        if p.is_file():
            yield p


def load_from_paths(
    paths: Iterable[Path],
    *,
    logsource_filter: LogsourceFilter = null_filter,
    pipeline_selector: PipelineSelector = null_selector,
) -> Ruleset:
    rs = Ruleset()
    # Parse all files into one collection so cross-file correlation refs resolve.
    docs = []
    sources: list[str] = []
    for p in paths:
        text = p.read_text()
        docs.append(text)
        sources.append(str(p))
    if not docs:
        return rs

    collection = SigmaCollection.from_yaml("\n---\n".join(docs))
    collection.resolve_rule_references()

    # Apply processing pipelines before compilation so EventID injections,
    # field renames, and category expansions are baked into the predicate.
    for rule in collection.rules:
        if isinstance(rule, SigmaRule):
            apply_pipelines(rule, pipeline_selector)

    for rule in collection.rules:
        # We can't reliably tie a rule back to its source file after the
        # YAML join, so source_path becomes the directory for diagnostics.
        src = sources[0] if len(sources) == 1 else None
        if isinstance(rule, SigmaCorrelationRule):
            c = _compile_correlation(rule, src)
            _lint_correlation(c)
            rs.correlation.append(c)
        elif isinstance(rule, SigmaRule):
            rs.single_event.append(_compile_single(rule, src, logsource_filter))
        else:
            log.warning("skipping unknown rule type %s", type(rule).__name__)
    return rs


def load_from_dir(
    path: str | os.PathLike,
    *,
    logsource_filter: LogsourceFilter = null_filter,
    pipeline_selector: PipelineSelector = null_selector,
) -> Ruleset:
    root = Path(path)
    if not root.is_dir():
        raise RuleLoadError(f"not a directory: {root}")
    return load_from_paths(
        _iter_yaml_files(root),
        logsource_filter=logsource_filter,
        pipeline_selector=pipeline_selector,
    )


def load_from_gcs(uri: str) -> Ruleset:
    """Download every `*.y[a]ml` under a `gs://bucket/prefix/` URI and load.

    Imported lazily so the loader stays usable in unit tests without GCP deps.
    """
    if not uri.startswith("gs://"):
        raise RuleLoadError(f"expected gs:// URI, got {uri!r}")
    from google.cloud import storage  # type: ignore
    import tempfile

    rest = uri[len("gs://"):]
    bucket_name, _, prefix = rest.partition("/")
    client = storage.Client()
    bucket = client.bucket(bucket_name)

    with tempfile.TemporaryDirectory() as td:
        local_root = Path(td)
        for blob in client.list_blobs(bucket, prefix=prefix):
            if not (blob.name.endswith(".yml") or blob.name.endswith(".yaml")):
                continue
            local = local_root / Path(blob.name).name
            blob.download_to_filename(str(local))
        return load_from_dir(local_root)
