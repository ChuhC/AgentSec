from __future__ import annotations

import pytest

from agentsec_engine.models import (
    Agent,
    Asset,
    ExposureFinding,
    ScanMeta,
    ScanSnapshot,
)
from agentsec_engine.reporter import redact_snapshot_dict
from agentsec_engine.store import SnapshotStore


def sensitive_snapshot() -> dict:
    return {
        "assets": [
            {
                "purpose": (
                    "https://example.invalid/mcp?"
                    "token=FAKESECRET123456"
                )
            }
        ],
        "exposure_findings": [
            {
                "evidence": (
                    "Authorization: Bearer "
                    "eyJhbGciOiJIUzI1NiJ9.FAKEPAYLOAD12.FAKESIGNATURE12"
                )
            }
        ],
    }


def test_recursive_snapshot_redaction_covers_assets_and_jwt():
    redacted = redact_snapshot_dict(sensitive_snapshot())
    payload = str(redacted)
    assert "FAKESECRET123456" not in payload
    assert "FAKEPAYLOAD12" not in payload
    assert "[REDACTED]" in payload


@pytest.mark.parametrize(
    ("secret", "visible_fragment"),
    [
        ("Authorization: Bearer abcdefghijklmnop", "abcdefghijklmnop"),
        (
            "eyJhbGciOiJIUzI1NiJ9.FAKEPAYLOAD12.FAKESIGNATURE12",
            "FAKEPAYLOAD12",
        ),
        ("https://user:supersecret@example.invalid", "supersecret"),
        ("https://example.invalid?a=1&token=TOPSECRET123", "TOPSECRET123"),
        ("github_pat_ABCD_1234567890123456", "1234567890123456"),
        (
            "-----BEGIN PRIVATE KEY-----\nSECRETKEYBODY\n"
            "-----END PRIVATE KEY-----",
            "SECRETKEYBODY",
        ),
    ],
)
def test_redaction_contract_covers_supported_secret_shapes(
    secret: str, visible_fragment: str
):
    payload = str(redact_snapshot_dict({"nested": [{"value": secret}]}))
    assert visible_fragment not in payload


def test_snapshot_store_redacts_before_persisting(tmp_path):
    store = SnapshotStore(str(tmp_path))
    snapshot = ScanSnapshot(
        meta=ScanMeta(),
        agents=[Agent(id="x", name="x", kind="x", version="1")],
        assets=[
            Asset(
                id="x-mcp",
                agent_id="x",
                type="mcp",
                name="remote",
                purpose=(
                    "https://example.invalid/mcp?"
                    "token=FAKESECRET123456"
                ),
            )
        ],
        exposure_findings=[
            ExposureFinding(
                id="R1",
                title="demo",
                severity="high",
                category="demo",
                source="mcp",
                evidence=(
                    "Bearer "
                    "eyJhbGciOiJIUzI1NiJ9.FAKEPAYLOAD12.FAKESIGNATURE12"
                ),
            )
        ],
    )
    store.commit_replace(snapshot)
    loaded = store.load()
    payload = str(loaded)
    assert "FAKESECRET123456" not in payload
    assert "FAKEPAYLOAD12" not in payload
    store.close()
