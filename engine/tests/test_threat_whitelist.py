from __future__ import annotations

import os

from agentsec_engine.threat_whitelist import (
    apply_default_whitelist_to_snapshot,
    is_finding_fully_whitelisted,
    is_whitelisted_path,
)


def test_is_whitelisted_path_under_red_teaming(tmp_path, monkeypatch):
    home = tmp_path / "home"
    root = home / ".hermes" / "skills" / "red-teaming" / "case.md"
    root.parent.mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    assert is_whitelisted_path(str(root)) is True
    assert is_whitelisted_path(str(home / "other.txt")) is False


def test_apply_default_whitelist_to_snapshot(tmp_path, monkeypatch):
    home = tmp_path / "home"
    skill = home / ".hermes" / "skills" / "red-teaming" / "x.md"
    skill.parent.mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))

    finding = {
        "source": "hermes",
        "id": "ATR-TEST",
        "location": f"{skill}:1",
        "locations": [f"{skill}:1"],
    }
    snap = {"exposure_findings": [finding], "ignored_threat_keys": []}
    apply_default_whitelist_to_snapshot(snap)
    assert snap["ignored_threat_keys"] == ["hermes::ATR-TEST"]
    assert is_finding_fully_whitelisted(finding) is True
