from __future__ import annotations

from agentsec_engine.paths import finding_path_only, frozen_engine_filename


def test_finding_path_only_strips_line_suffix():
    assert finding_path_only("/tmp/SKILL.md:42") == "/tmp/SKILL.md"
    assert finding_path_only("C:\\Users\\me\\skill.md:10") == "C:\\Users\\me\\skill.md"


def test_finding_path_only_empty():
    assert finding_path_only("") == ""


def test_frozen_engine_filename_platform():
    assert frozen_engine_filename() in ("agentsec-engine", "agentsec-engine.exe")
