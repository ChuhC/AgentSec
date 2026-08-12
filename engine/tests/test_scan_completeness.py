from __future__ import annotations

from agentsec_engine.models import Agent, CVEStatus, ScanStatus
from agentsec_engine.orchestrator import ScanOrchestrator
from agentsec_engine.store import SnapshotStore


def _stub_detectors(orchestrator: ScanOrchestrator) -> None:
    orchestrator.exposure.scan = lambda *args, **kwargs: []
    orchestrator.exposure.last_diagnostics = {
        "status": "ok",
        "timed_out_paths": [],
        "read_error_paths": [],
        "worker_errors": [],
    }
    orchestrator.cve.scan = lambda *args, **kwargs: (
        [],
        CVEStatus.OK.value,
    )
    orchestrator.cve.last_diagnostics = {
        "queried": 0,
        "skipped": 0,
        "detail_errors": 0,
        "result_mismatch": False,
    }


def test_all_adapter_failures_do_not_produce_complete_snapshot(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(
        "agentsec_engine.orchestrator.discover_all",
        lambda *args, **kwargs: (
            [],
            [],
            [],
            {
                "hermes": "error: denied",
                "openclaw": "error: invalid",
                "claude": "error: denied",
                "codex": "error: denied",
            },
        ),
    )
    store = SnapshotStore(str(tmp_path))
    orchestrator = ScanOrchestrator(store, cve_online=False)
    _stub_detectors(orchestrator)
    result = orchestrator.run(simulate_delay=False)
    assert result["meta"]["scan_status"] == ScanStatus.NO_AGENTS.value
    assert result["meta"]["adapter_status"]["hermes"].startswith("error")
    store.close()


def test_one_adapter_error_marks_result_partial(tmp_path, monkeypatch):
    agent = Agent(id="x", name="x", kind="x", version="1")
    monkeypatch.setattr(
        "agentsec_engine.orchestrator.discover_all",
        lambda *args, **kwargs: (
            [agent],
            [],
            [],
            {"x": "ok", "codex": "error: denied"},
        ),
    )
    store = SnapshotStore(str(tmp_path))
    orchestrator = ScanOrchestrator(store, cve_online=False)
    _stub_detectors(orchestrator)
    result = orchestrator.run(simulate_delay=False)
    assert result["meta"]["scan_status"] == ScanStatus.PARTIAL.value
    store.close()
