from __future__ import annotations

import json

import pytest

from agentsec_engine.asset_manager import AssetManager, AssetOperationError
from agentsec_engine.store import SnapshotStore


def _seed_snapshot(store: SnapshotStore, snap: dict) -> None:
    payload = json.dumps(snap, ensure_ascii=False)
    with store._lock:
        store._conn.execute("DELETE FROM snapshot")
        store._conn.execute(
            "INSERT INTO snapshot (id, schema_version, payload, committed_at) VALUES (1, 1, ?, ?)",
            (payload, "test"),
        )
        store._conn.commit()


@pytest.fixture
def openclaw_skill_snapshot(tmp_path):
    cfg = tmp_path / "openclaw.json"
    cfg.write_text(json.dumps({"skills": {"entries": {}}}), encoding="utf-8")
    snap = {
        "version": 1,
        "assets": [
            {
                "id": "openclaw-skill-demo",
                "agent_id": "openclaw",
                "type": "skill",
                "name": "demo",
                "status": "enabled",
                "path": str(cfg),
                "config_key": "skills:demo",
                "can_disable": True,
            }
        ],
    }
    store = SnapshotStore(str(tmp_path))
    _seed_snapshot(store, snap)
    return cfg, store


def test_toggle_openclaw_skill_writes_config(openclaw_skill_snapshot):
    cfg, store = openclaw_skill_snapshot
    mgr = AssetManager(store)
    mgr.disable("openclaw-skill-demo")
    data = json.loads(cfg.read_text(encoding="utf-8"))
    assert data["skills"]["entries"]["demo"]["enabled"] is False
    mgr.enable("openclaw-skill-demo")
    data = json.loads(cfg.read_text(encoding="utf-8"))
    assert data["skills"]["entries"]["demo"]["enabled"] is True


def test_toggle_skill_without_config_key_fails(tmp_path):
    store = SnapshotStore(str(tmp_path))
    _seed_snapshot(
        store,
        {
            "version": 1,
            "assets": [
                {
                    "id": "hermes-skill-x",
                    "agent_id": "hermes",
                    "type": "skill",
                    "name": "x",
                    "status": "enabled",
                    "path": str(tmp_path / "SKILL.md"),
                    "can_disable": False,
                }
            ],
        },
    )
    mgr = AssetManager(store)
    with pytest.raises(AssetOperationError, match="不支持禁用"):
        mgr.disable("hermes-skill-x")
