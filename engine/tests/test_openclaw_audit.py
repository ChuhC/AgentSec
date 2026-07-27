from __future__ import annotations

from agentsec_engine.detectors.exposure import OpenClawAuditCollector
from agentsec_engine.models import Agent


def _agent() -> Agent:
    return Agent(
        id="openclaw",
        name="OpenClaw",
        kind="openclaw",
        version="",
        enabled=True,
        description="",
        permissions=[],
    )


def test_openclaw_audit_filters_summary_records():
    findings = OpenClawAuditCollector()._map(
        {
            "findings": [
                {
                    "checkId": "summary.attack_surface",
                    "severity": "info",
                    "title": "Attack surface summary",
                },
                {
                    "checkId": "gateway.insecure_auth",
                    "severity": "warning",
                    "title": "Insecure auth",
                },
            ]
        },
        _agent(),
    )
    assert [f.id for f in findings] == ["gateway.insecure_auth"]
