"""Coverage harness: load every Sigma YAML under a directory, classify
the outcome, and produce a report.

Categories:
- compile_ok            — loaded into Ruleset successfully
- parse_error           — pySigma rejected the YAML (bad structure, unknown
                          modifier, malformed correlation)
- unsupported           — our walker raised UnsupportedCondition (a Sigma
                          construct we know about but haven't implemented)
- compile_error         — anything else (a bug in this package or pySigma)

The harness also evaluates compiled single-event rules against a small
set of synthetic events to catch runtime explosions that compile-time
checks miss.
"""

from __future__ import annotations

import logging
import traceback
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from sigma.collection import SigmaCollection
from sigma.correlations import SigmaCorrelationRule
from sigma.rule import SigmaRule

from .conditions import UnsupportedCondition
from .loader import (
    RuleLoadError,
    _compile_correlation,
    _compile_single,
    _lint_correlation,
)
from .ruleset import CompiledCorrelation, CompiledRule

log = logging.getLogger(__name__)


# Canonical event shapes for runtime probing. Designed to (a) be plausible
# for the major log sources, and (b) include a few "boring" events that
# should not match most rules — anything that crashes on these is a bug.
SYNTHETIC_EVENTS: list[dict] = [
    {},  # empty
    {"EventID": 4624, "User": "alice", "LogonType": 3,
     "SourceIP": "10.0.0.1", "timestamp": "2026-05-16T00:00:00Z"},
    {"EventID": 4625, "User": "bob", "LogonType": 2,
     "SourceIP": "192.168.1.10", "FailureReason": "%%2313"},
    {"Image": "C:\\Windows\\System32\\powershell.exe",
     "CommandLine": "powershell -enc ZQBjAGgAbwA=",
     "ParentImage": "C:\\Windows\\explorer.exe",
     "User": "DOMAIN\\alice"},
    {"src_ip": "8.8.8.8", "dst_port": 443, "bytes": 1024,
     "user_agent": "Mozilla/5.0", "uri": "/login"},
    {"eventSource": "iam.amazonaws.com", "eventName": "CreateUser",
     "userIdentity": {"type": "IAMUser", "userName": "root"}},
    {"deeply": {"nested": {"value": "x" * 1000}}, "list": [1, 2, 3, "four"]},
]


@dataclass
class RuleOutcome:
    path: str
    category: str           # compile_ok / parse_error / unsupported / compile_error
    rule_type: str = ""     # rule / correlation
    detail: str = ""        # error message or summary
    runtime_errors: int = 0


@dataclass
class CoverageReport:
    outcomes: list[RuleOutcome] = field(default_factory=list)
    total_files: int = 0

    @property
    def by_category(self) -> Counter:
        return Counter(o.category for o in self.outcomes)

    @property
    def ok_rate(self) -> float:
        return self.by_category["compile_ok"] / max(1, len(self.outcomes))

    def top_unsupported(self, n: int = 10) -> list[tuple[str, int]]:
        return Counter(
            o.detail for o in self.outcomes if o.category == "unsupported"
        ).most_common(n)

    def top_parse_errors(self, n: int = 10) -> list[tuple[str, int]]:
        return Counter(
            _first_line(o.detail) for o in self.outcomes if o.category == "parse_error"
        ).most_common(n)

    def top_compile_errors(self, n: int = 10) -> list[tuple[str, int]]:
        return Counter(
            _first_line(o.detail) for o in self.outcomes if o.category == "compile_error"
        ).most_common(n)

    def format(self) -> str:
        bc = self.by_category
        total = len(self.outcomes)
        lines = [
            f"=== sigma_beam coverage on {self.total_files} files / {total} rules ===",
            f"  compile_ok      {bc['compile_ok']:>5} ({100*bc['compile_ok']/max(1,total):.1f}%)",
            f"  unsupported     {bc['unsupported']:>5} ({100*bc['unsupported']/max(1,total):.1f}%)",
            f"  parse_error     {bc['parse_error']:>5} ({100*bc['parse_error']/max(1,total):.1f}%)",
            f"  compile_error   {bc['compile_error']:>5} ({100*bc['compile_error']/max(1,total):.1f}%)",
        ]
        rte = sum(o.runtime_errors for o in self.outcomes)
        if rte:
            lines.append(f"  runtime probes  {rte:>5} predicates raised on synthetic events")
        if bc["unsupported"]:
            lines.append("\nTop unsupported constructs:")
            for msg, n in self.top_unsupported():
                lines.append(f"  {n:>4}  {msg}")
        if bc["parse_error"]:
            lines.append("\nTop parse_error reasons:")
            for msg, n in self.top_parse_errors():
                lines.append(f"  {n:>4}  {msg}")
        if bc["compile_error"]:
            lines.append("\nTop compile_error reasons:")
            for msg, n in self.top_compile_errors():
                lines.append(f"  {n:>4}  {msg}")
        return "\n".join(lines)


def _first_line(s: str) -> str:
    s = (s or "").strip()
    return s.splitlines()[0] if s else "<no detail>"


def _classify_exception(exc: BaseException) -> str:
    name = type(exc).__name__
    # pySigma exceptions live in sigma.exceptions and all subclass SigmaError.
    if name.startswith("Sigma") and ("Error" in name or "Exception" in name):
        return "parse_error"
    if isinstance(exc, RuleLoadError):
        # cardinality linter rejections etc. — treat as supported-but-rejected
        return "unsupported"
    if isinstance(exc, UnsupportedCondition):
        return "unsupported"
    return "compile_error"


def _analyze_one(path: Path, probe_runtime: bool) -> list[RuleOutcome]:
    """Parse + compile one file in isolation. Use only when the whole-corpus
    parse failed; cross-file correlation references won't resolve here."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return [RuleOutcome(str(path), "compile_error", detail=f"read: {exc}")]

    try:
        collection = SigmaCollection.from_yaml(text)
        collection.resolve_rule_references()
    except Exception as exc:
        return [RuleOutcome(str(path), _classify_exception(exc), detail=str(exc))]

    return _classify_collection(collection, str(path), probe_runtime)


def _classify_collection(collection, source: str, probe_runtime: bool) -> list[RuleOutcome]:
    out: list[RuleOutcome] = []
    for rule in collection.rules:
        path = _rule_source(rule) or source
        try:
            if isinstance(rule, SigmaCorrelationRule):
                c = _compile_correlation(rule, path)
                try:
                    _lint_correlation(c)
                except RuleLoadError:
                    pass  # linter rejection is policy, not a backend failure
                out.append(RuleOutcome(path, "compile_ok", "correlation"))
            elif isinstance(rule, SigmaRule):
                compiled = _compile_single(rule, path)
                runtime_errors = 0
                if probe_runtime:
                    for ev in SYNTHETIC_EVENTS:
                        try:
                            compiled.predicate(ev)
                        except Exception:
                            runtime_errors += 1
                out.append(RuleOutcome(
                    path, "compile_ok", "rule",
                    runtime_errors=runtime_errors,
                ))
            else:
                out.append(RuleOutcome(
                    path, "compile_error",
                    detail=f"unknown rule class {type(rule).__name__}",
                ))
        except Exception as exc:
            out.append(RuleOutcome(
                path,
                _classify_exception(exc),
                detail=str(exc) or repr(exc),
            ))
    return out


def _rule_source(rule) -> str | None:
    """Best-effort extraction of a rule's source path; pySigma's `source` is
    a `SigmaRuleLocation` when available, else None."""
    src = getattr(rule, "source", None)
    if src is None:
        return None
    return str(getattr(src, "path", None) or src)


def analyze_corpus(root: str | Path, *, probe_runtime: bool = True) -> CoverageReport:
    """Analyze every Sigma YAML under `root`.

    Parses the entire corpus as one `SigmaCollection` so cross-file
    correlation references resolve. If the whole-corpus parse fails (rare
    — usually one bad file poisons it), falls back to per-file parsing,
    losing cross-file correlation resolution but still producing per-rule
    classifications.
    """
    root = Path(root)
    report = CoverageReport()
    files = sorted(p for p in root.rglob("*.y*ml") if p.is_file())
    report.total_files = len(files)
    if not files:
        return report

    try:
        joined = "\n---\n".join(p.read_text(encoding="utf-8", errors="replace")
                                for p in files)
        collection = SigmaCollection.from_yaml(joined)
        collection.resolve_rule_references()
        report.outcomes = _classify_collection(collection, str(root), probe_runtime)
    except Exception:
        # Bulk parse blew up — fall back to per-file so we still get a
        # report, accepting that cross-file correlation refs won't resolve.
        log.warning("bulk corpus parse failed; falling back to per-file", exc_info=True)
        for p in files:
            for o in _analyze_one(p, probe_runtime):
                report.outcomes.append(o)
    return report
