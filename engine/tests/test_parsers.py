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


def test_pyproject_dependencies_use_installed_versions_and_skip_cve_for_absent_packages(tmp_path):
    """CVE 查询必须使用实际安装版本，不能把约束下限当成当前版本。"""
    (tmp_path / "pyproject.toml").write_text(
        """[project]
dependencies = [
  "jinja2==3.1.6",
  "fastapi>=0.104.0,<1",
  "python-multipart>=0.0.9,<1",
]
""",
        encoding="utf-8",
    )
    site = tmp_path / ".venv" / "lib" / "python3.11" / "site-packages"
    for dist, name, version in (
        ("Jinja2-3.1.6.dist-info", "Jinja2", "3.1.6"),
        ("fastapi-0.133.1.dist-info", "fastapi", "0.133.1"),
    ):
        meta = site / dist
        meta.mkdir(parents=True)
        (meta / "METADATA").write_text(
            f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n",
            encoding="utf-8",
        )

    deps = {d.name.lower(): d for d in deps_from_npm_workspace(str(tmp_path), "test")}

    assert deps["jinja2"].version == "3.1.6"
    assert deps["fastapi"].version == "0.133.1"
    assert deps["python-multipart"].version in (None, "")
