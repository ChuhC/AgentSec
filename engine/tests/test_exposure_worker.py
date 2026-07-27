from __future__ import annotations

from agentsec_engine.detectors import exposure
from agentsec_engine.detectors.exposure import ExposureDetector, ScanTarget


def test_pathological_regex_input_times_out_without_hanging_scan(
    tmp_path, monkeypatch
):
    skill = tmp_path / "SKILL.md"
    skill.write_text(
        "---\nname: timeout-test\n---\n" + ("A" * 8192),
        encoding="utf-8",
    )
    monkeypatch.setattr(exposure, "_ATR_FILE_TIMEOUT_SECONDS", 0.25)
    detector = ExposureDetector()
    detector.scan(
        [],
        [ScanTarget(str(skill), "skill", ["test"])],
        run_openclaw_audit=False,
    )
    assert detector.last_diagnostics["status"] == "partial"
    assert detector.last_diagnostics["timed_out_paths"] == [str(skill)]
