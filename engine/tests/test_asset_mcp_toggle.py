from __future__ import annotations

import json
import tomllib

from agentsec_engine.asset_manager import _toggle_mcp_config


def test_toggle_mcp_json_remains_valid_json(tmp_path):
    path = tmp_path / "openclaw.json"
    path.write_text(
        json.dumps({"mcp_servers": {"demo": {"command": "npx"}}}),
        encoding="utf-8",
    )
    _toggle_mcp_config(str(path), "demo", False)
    parsed = json.loads(path.read_text(encoding="utf-8"))
    assert parsed["mcp_servers"]["demo"]["enabled"] is False


def test_toggle_camel_case_mcp_json(tmp_path):
    path = tmp_path / ".mcp.json"
    path.write_text(
        json.dumps({"mcpServers": {"demo": {"url": "https://example.com"}}}),
        encoding="utf-8",
    )
    _toggle_mcp_config(str(path), "demo", False)
    parsed = json.loads(path.read_text(encoding="utf-8"))
    assert parsed["mcpServers"]["demo"]["enabled"] is False


def test_toggle_codex_toml_preserves_valid_toml_and_other_sections(tmp_path):
    path = tmp_path / "config.toml"
    path.write_text(
        (
            'model = "gpt-test"\n\n'
            '[mcp_servers."demo.server"]\n'
            'command = "npx"\n'
            'args = ["demo"] # keep\n\n'
            '[projects."/tmp/project"]\n'
            'trust_level = "trusted"\n'
        ),
        encoding="utf-8",
    )
    _toggle_mcp_config(str(path), "demo.server", False)
    parsed = tomllib.loads(path.read_text(encoding="utf-8"))
    assert parsed["mcp_servers"]["demo.server"]["enabled"] is False
    assert parsed["projects"]["/tmp/project"]["trust_level"] == "trusted"
    assert 'args = ["demo"] # keep' in path.read_text(encoding="utf-8")


def test_toggle_hermes_yaml(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text(
        "mcp_servers:\n  demo:\n    command: npx\n",
        encoding="utf-8",
    )
    _toggle_mcp_config(str(path), "demo", False)
    assert "enabled: false" in path.read_text(encoding="utf-8")
