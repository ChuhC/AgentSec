from __future__ import annotations

from unittest.mock import patch

from agentsec_engine.agent_manager import scan_replacement_cves
from agentsec_engine.models import (
    Agent,
    Asset,
    AssetType,
    CVEStatus,
    ScanMeta,
    ScanSnapshot,
    ScanStatus,
)
from agentsec_engine.store import SnapshotStore


def dependency(agent_id: str, name: str) -> Asset:
    return Asset(
        id=f"{agent_id}-dep-{name}",
        agent_id=agent_id,
        type=AssetType.DEPENDENCY.value,
        name=name,
        version="1.0.0",
        ecosystem="npm",
    )


def test_replacement_cve_scan_includes_other_agents_dependencies():
    snapshot = {
        "assets": [
            dependency("a", "old-a").to_dict(),
            dependency("b", "keep-b").to_dict(),
        ]
    }
    replacement = [dependency("a", "new-a")]
    with patch(
        "agentsec_engine.detectors.cve.CVEDetector.scan",
        return_value=([], CVEStatus.OK.value),
    ) as scan:
        payload, status, diagnostics = scan_replacement_cves(
            snapshot, "a", replacement, online=True
        )
    names = {item.name for item in scan.call_args.args[0]}
    assert names == {"new-a", "keep-b"}
    assert payload == []
    assert status == CVEStatus.OK.value
    assert diagnostics["dependency_count"] == 2


def test_malformed_legacy_dependency_marks_refresh_partial():
    snapshot = {
        "assets": [
            {
                "agent_id": "b",
                "type": AssetType.DEPENDENCY.value,
                "version": "1.0.0",
                "ecosystem": "npm",
            }
        ]
    }
    with patch(
        "agentsec_engine.detectors.cve.CVEDetector.scan",
        return_value=([], CVEStatus.OK.value),
    ):
        _, status, diagnostics = scan_replacement_cves(
            snapshot, "a", [], online=True
        )
    assert status == CVEStatus.PARTIAL.value
    assert diagnostics["invalid_dependencies"] == 1
    assert diagnostics["skipped"] == 1


def test_agent_refresh_updates_cve_meta_and_scan_completeness(tmp_path):
    store = SnapshotStore(str(tmp_path))
    original = ScanSnapshot(
        meta=ScanMeta(
            scan_status=ScanStatus.PARTIAL.value,
            adapter_status={"a": "ok"},
            cve_status=CVEStatus.UNAVAILABLE.value,
            cve_skipped_count=1,
        ),
        agents=[Agent(id="a", name="A", kind="a", version="1")],
        assets=[dependency("a", "old-a")],
    )
    store.commit_replace(original)

    patched = store.patch_agent_discovery(
        "a",
        Agent(id="a", name="A", kind="a", version="2").to_dict(),
        [dependency("a", "new-a").to_dict()],
        cve_findings=[],
        replace_all_cve_findings=True,
        cve_status=CVEStatus.OK.value,
        cve_diagnostics={"queried": 1, "skipped": 0, "detail_errors": 0},
    )

    assert patched is not None
    assert patched["meta"]["cve_status"] == CVEStatus.OK.value
    assert patched["meta"]["cve_scanned_count"] == 1
    assert patched["meta"]["cve_skipped_count"] == 0
    assert patched["meta"]["scan_status"] == ScanStatus.COMPLETE.value
    store.close()
