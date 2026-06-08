"""Opt-in coverage test against the real SigmaHQ rule corpus.

Set SIGMA_HQ_PATH to a checkout of https://github.com/SigmaHQ/sigma (the
`rules/` directory works fine) and this test will measure the fraction of
real-world rules that our backend can compile, then classify the failures
by reason so we can prioritize fixes.

Default threshold: 90% compile_ok over the full corpus. Bump as we close gaps.

The test always *runs* if the env var is set; it doesn't enforce a hard floor
unless SIGMA_HQ_ENFORCE=1 (so CI can see the numbers without auto-failing).
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from sigma_beam.coverage import analyze_corpus

SIGMA_HQ_PATH = os.environ.get("SIGMA_HQ_PATH")
ENFORCE = os.environ.get("SIGMA_HQ_ENFORCE") == "1"
THRESHOLD = float(os.environ.get("SIGMA_HQ_THRESHOLD", "0.90"))


@pytest.mark.skipif(
    not SIGMA_HQ_PATH,
    reason="set SIGMA_HQ_PATH=<path/to/SigmaHQ/sigma/rules> to enable",
)
def test_sigmahq_corpus_coverage():
    root = Path(SIGMA_HQ_PATH)
    assert root.is_dir(), f"SIGMA_HQ_PATH not a directory: {root}"
    report = analyze_corpus(root, probe_runtime=False)
    print("\n" + report.format())
    if ENFORCE:
        assert report.ok_rate >= THRESHOLD, (
            f"compile_ok rate {report.ok_rate:.2%} < threshold {THRESHOLD:.0%}"
        )


@pytest.mark.skipif(
    not SIGMA_HQ_PATH,
    reason="set SIGMA_HQ_PATH=<path/to/SigmaHQ/sigma/rules> to enable",
)
def test_sigmahq_corpus_runtime_probe():
    """Evaluate every compiled rule against the synthetic event panel."""
    root = Path(SIGMA_HQ_PATH)
    assert root.is_dir(), f"SIGMA_HQ_PATH not a directory: {root}"
    report = analyze_corpus(root, probe_runtime=True)
    print("\n" + report.format())
    rte = sum(o.runtime_errors for o in report.outcomes)
    print(f"\nTotal runtime errors across panel: {rte}")
    if ENFORCE:
        assert rte == 0, f"{rte} predicate evaluations raised on synthetic events"
