from __future__ import annotations

import json

import pytest

from agentsec_engine.discovery.hermes import HermesAdapter
from agentsec_engine.discovery.openclaw import OpenClawAdapter


@pytest.fixture
def hermes_layout(tmp_path, monkeypatch):
    home = tmp_path / ".hermes"
    home.mkdir()
    (home / "config.yaml").write_text(
        "model:\n  default: test-model\nmcp_servers:\n  fs:\n    command: npx\n    args: [\"-y\", \"@modelcontextprotocol/server-filesystem\"]\n",
        encoding="utf-8",
    )
    standalone = home / "mcp.json"
    standalone.write_text(
        json.dumps({"mcpServers": {"standalone": {"command": "node", "args": ["srv.js"]}}}),
        encoding="utf-8",
    )
    skill_dir = home / "skills" / "demo-skill"
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text(
        "---\nname: demo-skill\ndescription: test\n---\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("AGENTSEC_HERMES_HOME", str(home))
    return home


@pytest.fixture
def openclaw_layout(tmp_path, monkeypatch):
    home = tmp_path / ".openclaw"
    home.mkdir()
    ws = home / "workspace"
    ws.mkdir()
    (ws / "skills").mkdir()
    skill_dir = ws / "skills" / "oc-skill"
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text(
        "---\nname: oc-skill\ndescription: test\n---\n",
        encoding="utf-8",
    )
    (home / "openclaw.json").write_text(
        json.dumps(
            {
                "agents": {"defaults": {"workspace": str(ws)}},
                "mcp_servers": {
                    "http": {"command": "npx", "args": ["-y", "some-mcp"]},
                },
            }
        ),
        encoding="utf-8",
    )
    (ws / ".mcp.json").write_text(
        json.dumps({"mcpServers": {"proj-mcp": {"command": "node", "args": ["proj.js"]}}}),
        encoding="utf-8",
    )
    monkeypatch.setenv("AGENTSEC_OPENCLAW_HOME", str(home))
    return home, ws


def test_hermes_atr_targets_includes_mcp_json(hermes_layout):
    adapter = HermesAdapter()
    agent = adapter.detect()
    assert agent is not None
    targets = dict(adapter.atr_targets(agent))
    cfg_path = str(hermes_layout / "config.yaml")
    mcp_path = str(hermes_layout / "mcp.json")
    skill_path = str(hermes_layout / "skills" / "demo-skill" / "SKILL.md")
    assert cfg_path in targets
    assert targets[cfg_path] == "agent_config"
    assert mcp_path in targets
    assert targets[mcp_path] == "mcp"
    assert skill_path in targets
    assert targets[skill_path] == "skill"


def test_openclaw_atr_targets_includes_workspace_mcp_json(openclaw_layout):
    home, ws = openclaw_layout
    adapter = OpenClawAdapter()
    agent = adapter.detect()
    assert agent is not None
    targets = dict(adapter.atr_targets(agent))
    cfg_path = str(home / "openclaw.json")
    mcp_path = str(ws / ".mcp.json")
    skill_path = str(ws / "skills" / "oc-skill" / "SKILL.md")
    assert cfg_path in targets
    assert targets[cfg_path] == "agent_config"
    assert mcp_path in targets
    assert targets[mcp_path] == "mcp"
    assert skill_path in targets
    assert targets[skill_path] == "skill"
