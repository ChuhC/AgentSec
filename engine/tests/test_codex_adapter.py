from __future__ import annotations

import os

import pytest

from agentsec_engine.discovery.codex import CodexAdapter, resolve_codex_installed_version
from agentsec_engine.models import AssetType


@pytest.fixture
def codex_layout(tmp_path, monkeypatch):
    home = tmp_path / ".codex"
    home.mkdir()
    (home / "config.toml").write_text(
        """
model = "gpt-test"
model_reasoning_effort = "medium"

[mcp_servers.demo]
command = "npx"
args = ["-y", "demo-mcp"]

[mcp_servers.disabled]
command = "node"
args = ["off.js"]
enabled = false

[plugins."docs@demo"]
enabled = true

[projects."/tmp/demo-project"]
trust_level = "trusted"
""".strip(),
        encoding="utf-8",
    )
    project = tmp_path / "demo-project"
    project.mkdir()
    (project / "AGENTS.md").write_text("# Project agents\n", encoding="utf-8")
    proj_codex = project / ".codex"
    proj_codex.mkdir()
    (proj_codex / "config.toml").write_text(
        """
[mcp_servers.project-mcp]
url = "https://example.com/mcp"
""".strip(),
        encoding="utf-8",
    )

    config = home / "config.toml"
    config.write_text(
        config.read_text(encoding="utf-8").replace('"/tmp/demo-project"', f'"{project}"'),
        encoding="utf-8",
    )

    (home / "AGENTS.md").write_text("# Global rules\n", encoding="utf-8")
    rules = home / "rules"
    rules.mkdir()
    (rules / "default.rules").write_text('prefix_rule(pattern=["git", "push"], decision="allow")\n', encoding="utf-8")

    skill_dir = home / "skills" / "my-skill"
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text(
        "---\nname: my-skill\ndescription: demo\n---\n",
        encoding="utf-8",
    )

    monkeypatch.setenv("AGENTSEC_CODEX_HOME", str(home))
    monkeypatch.setattr(
        "agentsec_engine.discovery.codex.resolve_codex_installed_version",
        lambda: "v0.142.5",
    )
    return home, project


def test_detect(codex_layout):
    adapter = CodexAdapter()
    agent = adapter.detect()
    assert agent is not None
    assert agent.id == "codex"
    assert agent.name == "Codex"
    assert "gpt-test" in agent.description
    assert any(p.category == "网络" for p in agent.permissions)


def test_discover_assets_mcp_and_plugins(codex_layout):
    adapter = CodexAdapter()
    agent = adapter.detect()
    assert agent is not None
    assets = adapter.discover_assets(agent)
    mcp = [a for a in assets if a.type == AssetType.MCP.value]
    names = {a.name for a in mcp}
    assert "demo" in names
    assert "project-mcp" in names
    assert any(a.name == "demo" and a.status == "enabled" for a in mcp)
    assert any(a.name == "disabled" and a.status == "disabled" for a in mcp)
    plugins = [a for a in assets if a.purpose == "Codex 插件"]
    assert any(a.name == "docs@demo" for a in plugins)


def test_discover_skills_rules_dependency(codex_layout):
    adapter = CodexAdapter()
    agent = adapter.detect()
    assert agent is not None
    assets = adapter.discover_assets(agent)
    skills = [a for a in assets if a.type == AssetType.SKILL.value]
    assert any(a.name == "my-skill" for a in skills)
    knowledge = [a for a in assets if a.type == AssetType.KNOWLEDGE.value]
    assert any("AGENTS.md" in a.name for a in knowledge)
    assert any(a.name.startswith("rules/") for a in knowledge)
    deps = [a for a in assets if a.type == AssetType.DEPENDENCY.value]
    assert deps[0].name == "@openai/codex"


def test_atr_targets(codex_layout):
    home, project = codex_layout
    adapter = CodexAdapter()
    agent = adapter.detect()
    assert agent is not None
    targets = dict(adapter.atr_targets(agent))
    assert str(home / "config.toml") in targets
    assert str(home / "skills" / "my-skill" / "SKILL.md") in targets
    assert str(project / "AGENTS.md") in targets


def test_version_from_models_cache(tmp_path, monkeypatch):
    cache = tmp_path / "models_cache.json"
    cache.write_text('{"client_version": "0.142.5"}', encoding="utf-8")
    monkeypatch.setattr("agentsec_engine.discovery.codex._resolve_codex_cli", lambda: None)
    monkeypatch.setattr("agentsec_engine.discovery.codex.shutil.which", lambda _: None)

    def _isfile(path):
        return path == str(cache)

    monkeypatch.setattr("agentsec_engine.discovery.codex.os.path.isfile", _isfile)
    monkeypatch.setattr("agentsec_engine.discovery.codex.os.path.expanduser", lambda _: str(tmp_path))
    assert resolve_codex_installed_version() == "v0.142.5"
