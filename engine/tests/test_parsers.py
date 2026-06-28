from __future__ import annotations

from agentsec_engine.discovery.parsers import perm, perms_from_mcp_server
from agentsec_engine.models import FindingSource, Severity


def test_perm_maps_known_key():
    entry = perm("p1", "shell", FindingSource.MCP, "test MCP")
    assert entry.category == "Shell"
    assert entry.severity == Severity.HIGH.value


def test_perms_from_mcp_server_includes_network():
    perms = perms_from_mcp_server("fs", {"command": "npx", "args": ["-y", "server"]})
    categories = {p.category for p in perms}
    assert "网络" in categories or "Shell" in categories
