from __future__ import annotations

import json

from agentsec_engine import update_check


def test_offline_hermes_enrichment_does_not_run_update_command(tmp_path, monkeypatch):
    (tmp_path / ".update_check").write_text(
        json.dumps({"ver": "1.2.3", "behind": 0}), encoding="utf-8"
    )
    monkeypatch.setattr(update_check, "_resolve_hermes_cli", lambda: "/usr/bin/hermes")

    def fail_if_called(*args, **kwargs):
        raise AssertionError("offline discovery must not run hermes update --check")

    monkeypatch.setattr(update_check, "_run_hermes_update_check", fail_if_called)
    info = update_check.check_hermes_update(
        str(tmp_path), online=False, current_version="1.2.3"
    )
    assert info.current_version == "1.2.3"
