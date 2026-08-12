from __future__ import annotations

from agentsec_engine.discovery import registry
from agentsec_engine.models import Agent


class _Adapter:
    kind = "fake"

    def __init__(self, scope_path=None):
        self.scope_path = scope_path

    def resolve_home(self):
        return None

    def detect(self):
        return Agent(
            id="fake",
            name="Fake",
            kind="fake",
            version="",
            enabled=True,
            description="",
            permissions=[],
        )

    def discover_assets(self, agent):
        return []

    def atr_targets(self, agent):
        return []


def test_discovery_reports_incremental_adapter_progress(monkeypatch):
    monkeypatch.setattr(registry, "ADAPTERS", [_Adapter, _Adapter])
    monkeypatch.setattr(registry, "enrich_discovery", lambda *a, **k: None)
    events = []

    registry.discover_all(
        online=False,
        on_progress=lambda done, total, agents, assets: events.append(
            (done, total, len(agents), len(assets))
        ),
    )

    assert events == [(1, 2, 1, 0), (2, 2, 2, 0)]
