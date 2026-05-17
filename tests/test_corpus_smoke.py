"""Always-on coverage smoke test against a small bundled rule set.

This isn't a substitute for the full SigmaHQ corpus (see test_corpus_sigmahq.py
for that — opt-in via env var) — it just guarantees the harness itself runs
and that representative rule shapes (single-event, modifier chains, regex,
CIDR, keyword search, quantifier, correlation count + temporal) all compile
without error.
"""

from pathlib import Path

from sigma_beam.coverage import analyze_corpus

CORPUS = Path(__file__).parent / "fixtures" / "corpus_smoke"


def test_smoke_corpus_all_compile():
    report = analyze_corpus(CORPUS)
    print("\n" + report.format())
    bc = report.by_category
    assert bc["compile_error"] == 0, (
        f"unexpected compile_error in curated smoke corpus:\n{report.format()}"
    )
    assert bc["parse_error"] == 0, (
        f"unexpected parse_error in curated smoke corpus:\n{report.format()}"
    )
    # Every rule should land in compile_ok or unsupported (no compile_error
    # in a hand-curated set; a few may legitimately be unsupported).
    assert bc["compile_ok"] >= report.total_files - bc["unsupported"]
    # No predicate should explode on the synthetic events.
    assert all(o.runtime_errors == 0 for o in report.outcomes), (
        "predicate raised on synthetic events:\n" +
        "\n".join(f"  {o.path}: {o.runtime_errors} errors"
                  for o in report.outcomes if o.runtime_errors)
    )


def test_report_format_includes_counts():
    report = analyze_corpus(CORPUS)
    text = report.format()
    assert "compile_ok" in text
    assert "%" in text
