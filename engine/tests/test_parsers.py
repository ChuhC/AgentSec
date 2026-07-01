from __future__ import annotations

import json
import os
import tempfile

from agentsec_engine.discovery.parsers import (
    _parse_lock_packages,
    deps_from_npm_workspace,
    perm,
    perms_from_mcp_server,
)
from agentsec_engine.models import FindingSource, Severity


def test_perm_maps_known_key():
    entry = perm("p1", "shell", FindingSource.MCP, "test MCP")
    assert entry.category == "Shell"
    assert entry.severity == Severity.HIGH.value


def test_perms_from_mcp_server_includes_network():
    perms = perms_from_mcp_server("fs", {"command": "npx", "args": ["-y", "server"]})
    categories = {p.category for p in perms}
    assert "网络" in categories or "Shell" in categories


def test_parse_lock_packages_skips_dev_when_production_only():
    lock = {
        "packages": {
            "": {"name": "demo", "version": "1.0.0"},
            "node_modules/lodash": {"version": "4.17.21"},
            "node_modules/typescript": {"version": "5.4.0", "dev": True},
        }
    }
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump(lock, f)
        path = f.name
    try:
        all_pkgs = {n for n, _ in _parse_lock_packages(path)}
        prod_pkgs = {n for n, _ in _parse_lock_packages(path, production_only=True)}
        assert "lodash" in all_pkgs
        assert "typescript" in all_pkgs
        assert "lodash" in prod_pkgs
        assert "typescript" not in prod_pkgs
    finally:
        os.unlink(path)


def test_deps_from_npm_workspace_production_only():
    with tempfile.TemporaryDirectory() as tmp:
        pkg = {
            "name": "demo-agent",
            "dependencies": {"lodash": "^4.17.21"},
            "devDependencies": {"typescript": "^5.4.0"},
            "peerDependencies": {"react": "^18.0.0"},
            "optionalDependencies": {"fsevents": "^2.3.0"},
        }
        lock = {
            "packages": {
                "": {"name": "demo-agent", "version": "1.0.0"},
                "node_modules/lodash": {"version": "4.17.21"},
                "node_modules/typescript": {"version": "5.4.0", "dev": True},
                "node_modules/react": {"version": "18.2.0", "dev": True},
                "node_modules/fsevents": {"version": "2.3.3", "optional": True},
            }
        }
        with open(os.path.join(tmp, "package.json"), "w", encoding="utf-8") as f:
            json.dump(pkg, f)
        with open(os.path.join(tmp, "package-lock.json"), "w", encoding="utf-8") as f:
            json.dump(lock, f)

        names = {d.name for d in deps_from_npm_workspace(tmp, "test")}
        assert "lodash" in names
        assert "typescript" not in names
        assert "react" not in names
        assert "fsevents" not in names
