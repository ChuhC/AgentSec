from __future__ import annotations

from unittest.mock import patch

from agentsec_engine.detectors.cve import (
    CVEDetector,
    RemoteOSVProvider,
    _finding_from_dep,
    _query_version,
)
from agentsec_engine.models import Asset, AssetType, CVEStatus


def dependency(version: str = "1.0.0", ecosystem: str = "npm") -> Asset:
    return Asset(
        id="x-dep-demo",
        agent_id="x",
        type=AssetType.DEPENDENCY.value,
        name="demo",
        version=version,
        ecosystem=ecosystem,
    )


def test_query_version_removes_display_v_prefix():
    assert _query_version("v1.2.3") == "1.2.3"
    assert _query_version("1.2.3") == "1.2.3"


def test_unversioned_dependency_is_reported_as_skipped():
    provider = RemoteOSVProvider(online=True)
    findings, status = provider.query([dependency(version="")])
    assert findings == []
    assert status == CVEStatus.OK.value
    assert provider.last_diagnostics["queried"] == 0
    assert provider.last_diagnostics["skipped"] == 1


def test_offline_scan_without_dependencies_is_complete():
    provider = RemoteOSVProvider(online=False)
    findings, status = provider.query([])
    assert findings == []
    assert status == CVEStatus.OK.value
    assert provider.last_diagnostics["skipped"] == 0


def test_hydration_failure_is_partial_and_not_low_risk():
    provider = RemoteOSVProvider(online=True)
    with (
        patch.object(
            provider,
            "_fetch_vuln",
            side_effect=OSError("partial network failure"),
        ),
        patch.object(
            provider,
            "_query_one",
            side_effect=lambda *_: provider._hydrate_vulns(
                [{"id": "GHSA-DEMO"}]
            ),
        ),
    ):
        findings, status = provider.query([dependency()])
    assert status == CVEStatus.PARTIAL.value
    assert provider.last_diagnostics["detail_errors"] == 1
    assert findings[0].severity == "info"
    assert findings[0].cves[0].data_status == "incomplete"


def test_incomplete_stub_has_unknown_severity():
    finding = _finding_from_dep(
        dependency(),
        [{"id": "GHSA-DEMO", "_agentsec_incomplete": True}],
        "npm",
    )
    assert finding is not None
    assert finding.severity == "info"
    assert finding.cves[0].cvss == 0


def test_detector_exposes_provider_diagnostics():
    provider = RemoteOSVProvider(online=True)
    detector = CVEDetector(provider)
    findings, status = detector.scan([dependency(version="")])
    assert findings == []
    assert status == CVEStatus.OK.value
    assert detector.last_diagnostics["skipped"] == 1
