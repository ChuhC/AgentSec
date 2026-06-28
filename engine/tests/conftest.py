"""Pytest fixtures for agentsec_engine."""

from __future__ import annotations

import pytest

import agentsec_engine.config as config_mod


@pytest.fixture(autouse=True)
def reset_config_cache():
    config_mod._cache = None
    yield
    config_mod._cache = None


@pytest.fixture
def data_dir(tmp_path, monkeypatch):
    root = tmp_path / "AgentSec"
    root.mkdir()
    monkeypatch.setenv("AGENTSEC_DATA_DIR", str(root))
    config_mod._cache = None
    return root
