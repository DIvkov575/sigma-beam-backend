"""sigma-beam-test-rule: evaluate a Sigma rule (or a whole directory of them)
against a JSON event without spinning up Beam.

Useful for fast local iteration while authoring rules — drop a rule YAML
and a representative event JSON in your editor, run this, and see exactly
which rule fired and which would have on a slightly different event.

Usage:
    sigma-beam-test-rule <rule.yml|rules-dir> <event.json|event.jsonl|->
    sigma-beam-test-rule rules/ events.jsonl

Reads either a single JSON object or one-per-line JSONL. Pass `-` to read
events from stdin.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .loader import load_from_dir


def _iter_events(source: str):
    if source == "-":
        text = sys.stdin.read()
    else:
        text = Path(source).read_text()
    text = text.strip()
    if not text:
        return
    # JSONL if it's multiple lines, JSON object/array otherwise.
    if "\n" in text and not text.lstrip().startswith("["):
        for line in text.splitlines():
            line = line.strip()
            if line:
                yield json.loads(line)
        return
    parsed = json.loads(text)
    if isinstance(parsed, list):
        yield from parsed
    else:
        yield parsed


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="sigma-beam-test-rule")
    ap.add_argument("rules", help="path to a single .yml/.yaml or a directory of rules")
    ap.add_argument("events", help="path to .json / .jsonl, or `-` for stdin")
    ap.add_argument("--verbose", "-v", action="store_true",
                    help="emit a line per (event, rule) pair, not just matches")
    ap.add_argument("--placeholders", default=None,
                    help="path to a JSON file: {'placeholder_name': ['v1', 'v2']}")
    args = ap.parse_args(argv)

    rules_path = Path(args.rules)
    if rules_path.is_file():
        # Wrap a single file in a temp dir so load_from_dir works uniformly.
        import tempfile
        import shutil
        with tempfile.TemporaryDirectory() as td:
            shutil.copy(rules_path, td)
            return _run(Path(td), args)
    return _run(rules_path, args)


def _run(rules_dir: Path, args) -> int:
    placeholders = None
    if args.placeholders:
        placeholders = json.loads(Path(args.placeholders).read_text())

    rs = load_from_dir(rules_dir, placeholders=placeholders)
    print(f"loaded {len(rs.single_event)} single-event rule(s), "
          f"{len(rs.correlation)} correlation rule(s)")
    if rs.correlation:
        print(f"  (correlations are not exercised by this CLI — "
              f"they need a Beam pipeline with windowing)")

    total = 0
    matches = 0
    errors = 0
    for event in _iter_events(args.events):
        total += 1
        for r in rs.single_event:
            try:
                hit = r.predicate(event)
            except Exception as exc:  # noqa: BLE001
                errors += 1
                print(f"  ERROR  {r.id} ({r.title}): {exc}")
                continue
            if hit:
                matches += 1
                print(f"  MATCH  {r.id} ({r.title}) "
                      f"severity={r.severity} tags={list(r.tags)}")
            elif args.verbose:
                print(f"  miss   {r.id} ({r.title})")

    print()
    print(f"summary: {matches} match(es), {errors} error(s), "
          f"{total} event(s) × {len(rs.single_event)} rule(s)")
    return 0 if errors == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
