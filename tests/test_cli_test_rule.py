"""sigma-beam-test-rule CLI tests."""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

from sigma_beam.cli_test_rule import main


def _write_rule(path: Path, body: str):
    path.write_text(textwrap.dedent(body).strip())


def test_cli_match_against_single_file(tmp_path, capsys):
    rule = tmp_path / "rule.yml"
    _write_rule(rule, """
        title: Failed Login
        id: 11111111-1111-1111-1111-111111111111
        status: test
        logsource: {product: windows}
        detection: {sel: {EventID: 4625}, condition: sel}
        tags: [attack.t1110]
    """)
    event = tmp_path / "evt.json"
    event.write_text(json.dumps({"EventID": 4625, "User": "alice"}))

    rc = main([str(rule), str(event)])
    out = capsys.readouterr().out
    assert rc == 0
    assert "MATCH" in out
    assert "attack.t1110" in out


def test_cli_jsonl_multi_event(tmp_path, capsys):
    rule = tmp_path / "rule.yml"
    _write_rule(rule, """
        title: Failed Login
        id: 22222222-2222-2222-2222-222222222222
        status: test
        logsource: {product: windows}
        detection: {sel: {EventID: 4625}, condition: sel}
    """)
    events = tmp_path / "events.jsonl"
    events.write_text("\n".join([
        json.dumps({"EventID": 4625}),
        json.dumps({"EventID": 4624}),
        json.dumps({"EventID": 4625}),
    ]))
    rc = main([str(rule), str(events)])
    out = capsys.readouterr().out
    assert rc == 0
    assert out.count("MATCH") == 2


def test_cli_directory_of_rules(tmp_path, capsys):
    _write_rule(tmp_path / "a.yml", """
        title: A
        id: 33333333-3333-3333-3333-333333333333
        status: test
        logsource: {product: windows}
        detection: {sel: {k: "a"}, condition: sel}
    """)
    _write_rule(tmp_path / "b.yml", """
        title: B
        id: 44444444-4444-4444-4444-444444444444
        status: test
        logsource: {product: windows}
        detection: {sel: {k: "b"}, condition: sel}
    """)
    event = tmp_path / "evt.json"
    event.write_text(json.dumps({"k": "a"}))

    rc = main([str(tmp_path), str(event)])
    out = capsys.readouterr().out
    assert rc == 0
    assert "loaded 2" in out
    assert "33333333" in out
    assert "44444444" not in out  # B shouldn't match


def test_cli_verbose_lists_misses(tmp_path, capsys):
    _write_rule(tmp_path / "rule.yml", """
        title: R
        id: 55555555-5555-5555-5555-555555555555
        status: test
        logsource: {product: x}
        detection: {sel: {k: "yes"}, condition: sel}
    """)
    event = tmp_path / "evt.json"
    event.write_text(json.dumps({"k": "no"}))

    rc = main([str(tmp_path), str(event), "-v"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "MATCH" not in out
    assert "miss" in out


def test_cli_placeholders_file(tmp_path, capsys):
    _write_rule(tmp_path / "rule.yml", """
        title: Admin Action
        id: 66666666-6666-6666-6666-666666666666
        status: test
        logsource: {product: x}
        detection:
            sel: {User|expand: '%admins%'}
            condition: sel
    """)
    event = tmp_path / "evt.json"
    event.write_text(json.dumps({"User": "alice"}))
    placeholders = tmp_path / "placeholders.json"
    placeholders.write_text(json.dumps({"admins": ["alice", "bob"]}))

    rc = main([str(tmp_path), str(event), "--placeholders", str(placeholders)])
    out = capsys.readouterr().out
    assert rc == 0
    assert "MATCH" in out


def test_cli_stdin(tmp_path, capsys, monkeypatch):
    import io
    _write_rule(tmp_path / "rule.yml", """
        title: R
        id: 77777777-7777-7777-7777-777777777777
        status: test
        logsource: {product: x}
        detection: {sel: {EventID: 4625}, condition: sel}
    """)
    monkeypatch.setattr("sys.stdin", io.StringIO('{"EventID": 4625}'))
    rc = main([str(tmp_path), "-"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "MATCH" in out
