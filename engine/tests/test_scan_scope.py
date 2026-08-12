from __future__ import annotations

import pytest

from agentsec_engine.discovery.base import AgentAdapter
from agentsec_engine.discovery.claude import ClaudeAdapter
from agentsec_engine.ipc import _validate_scan_scope


class HermesScopeAdapter(AgentAdapter):
    kind = "hermes"


def test_custom_scope_does_not_fall_back_to_user_home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    (home / ".hermes").mkdir(parents=True)
    custom = tmp_path / "custom"
    custom.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("AGENTSEC_HERMES_HOME", raising=False)

    assert HermesScopeAdapter(scope_path=str(custom)).resolve_home() is None


def test_custom_scope_accepts_selecting_agent_home_directly(tmp_path):
    agent_home = tmp_path / ".hermes"
    agent_home.mkdir()
    assert HermesScopeAdapter(scope_path=str(agent_home)).resolve_home() == str(agent_home)


def test_custom_scope_requires_existing_directory(tmp_path):
    with pytest.raises(ValueError, match="扫描路径"):
        _validate_scan_scope("custom", "")
    with pytest.raises(ValueError, match="扫描路径"):
        _validate_scan_scope("custom", str(tmp_path / "missing"))
    assert _validate_scan_scope("custom", str(tmp_path)) == str(tmp_path.resolve())


def test_all_scope_ignores_custom_path():
    assert _validate_scan_scope("all", "/should/not/be/used") is None


def test_claude_custom_scope_does_not_read_global_claude_json(
    tmp_path, monkeypatch
):
    custom = tmp_path / "custom"
    custom.mkdir()
    outside = tmp_path / ".claude.json"
    outside.write_text('{"projects": {}}', encoding="utf-8")
    monkeypatch.setattr(
        "agentsec_engine.discovery.claude.claude_json_path",
        lambda: str(outside),
    )
    assert ClaudeAdapter(scope_path=str(custom)).detect() is None


def test_path_in_scope_rejects_symlink_escape(tmp_path):
    scope = tmp_path / "scope"
    outside = tmp_path / "outside"
    scope.mkdir()
    outside.mkdir()
    link = scope / "linked"
    link.symlink_to(outside, target_is_directory=True)
    adapter = HermesScopeAdapter(scope_path=str(scope))
    assert adapter.path_in_scope(str(scope / "inside.txt"))
    assert not adapter.path_in_scope(str(link / "secret.txt"))
