"""CLI: print a coverage report for a directory of Sigma YAMLs.

Usage:
    python -m sigma_beam.cli_corpus <path-to-rules-dir>
"""

from __future__ import annotations

import argparse
import sys

from .coverage import analyze_corpus


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("root", help="directory containing Sigma YAML rules")
    ap.add_argument("--no-runtime", action="store_true",
                    help="skip runtime probing against synthetic events")
    args = ap.parse_args(argv)
    report = analyze_corpus(args.root, probe_runtime=not args.no_runtime)
    print(report.format())
    return 0 if report.by_category.get("compile_error", 0) == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
