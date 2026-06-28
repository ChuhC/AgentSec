from __future__ import annotations

import json
import os

import agentsec_engine.config as config


def test_default_config_when_missing_file(data_dir):
    cfg = config.get_config(reload=True, data_dir=str(data_dir))
    assert cfg["ui"]["language"] == "zh"
    assert cfg["scan"]["cve_online"] is True


def test_patch_config_persists(data_dir):
    config.patch_config({"ui": {"language": "en"}}, data_dir=str(data_dir))
    path = config.config_path(str(data_dir))
    assert os.path.isfile(path)
    with open(path, encoding="utf-8") as f:
        saved = json.load(f)
    assert saved["ui"]["language"] == "en"


def test_env_overrides_cve_offline(data_dir, monkeypatch):
    monkeypatch.setenv("AGENTSEC_CVE_OFFLINE", "1")
    config._cache = None
    cfg = config.get_config(reload=True, data_dir=str(data_dir))
    assert cfg["scan"]["cve_online"] is False


def test_env_overrides_agent_home(data_dir, monkeypatch):
    monkeypatch.setenv("AGENTSEC_HERMES_HOME", "/tmp/hermes-test")
    config._cache = None
    assert config.get_agent_home("hermes") == "/tmp/hermes-test"
