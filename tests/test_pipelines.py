"""Processing-pipeline integration: the sysmon pipeline must inject EventID=1
for a process_creation rule so it matches a real Sysmon event."""

from pathlib import Path

import pytest

from sigma_beam.loader import load_from_dir
from sigma_beam.processing import default_selector, null_selector

try:
    import sigma.pipelines.sysmon  # noqa: F401
    _HAS_SYSMON = True
except ImportError:
    _HAS_SYSMON = False

FIX = Path(__file__).parent / "fixtures" / "corpus_smoke"


def _powershell_rule(rs):
    return next(r for r in rs.single_event if "PowerShell" in r.title)


def test_without_pipeline_matches_any_event_with_image():
    rs = load_from_dir(FIX, pipeline_selector=null_selector)
    rule = _powershell_rule(rs)
    # No EventID injected, so a non-Sysmon event with the right Image/CommandLine still matches.
    evt = {"Image": "C:\\powershell.exe", "CommandLine": "powershell.exe -enc AAA"}
    assert rule.predicate(evt)


@pytest.mark.skipif(not _HAS_SYSMON, reason="pySigma-pipeline-sysmon not installed")
def test_with_sysmon_pipeline_requires_eventid_1():
    rs = load_from_dir(FIX, pipeline_selector=default_selector())
    rule = _powershell_rule(rs)
    evt_no_eid = {"Image": "C:\\powershell.exe", "CommandLine": "powershell.exe -enc AAA"}
    assert not rule.predicate(evt_no_eid)
    evt_sysmon = {**evt_no_eid, "EventID": 1}
    assert rule.predicate(evt_sysmon)
    evt_wrong_eid = {**evt_no_eid, "EventID": 4624}
    assert not rule.predicate(evt_wrong_eid)
