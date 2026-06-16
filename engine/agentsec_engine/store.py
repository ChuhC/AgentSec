"""SnapshotStore：SQLite 持久化，仅保留最近一次完整快照（NF-D1）。

策略（architecture.md 四·1）：
- 扫描完成 → replace 覆盖唯一快照行
- 资产写操作成功 → 对快照局部 patch（B3-b），不改 Finding
- 重启应用仍可读（snapshot.db 落盘）
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
from typing import Optional

from .models import ScanSnapshot
from .paths import safe_normalize_readable_path
from .threat_whitelist import apply_default_whitelist_to_snapshot


def default_data_dir() -> str:
    """macOS: ~/Library/Application Support/agentSec/。

    允许用 AGENTSEC_DATA_DIR 覆盖（开发/测试用）。
    """
    override = os.environ.get("AGENTSEC_DATA_DIR")
    if override:
        return override
    home = os.path.expanduser("~")
    return os.path.join(home, "Library", "Application Support", "agentSec")


class SnapshotStore:
    def __init__(self, data_dir: Optional[str] = None):
        self.data_dir = data_dir or default_data_dir()
        os.makedirs(self.data_dir, exist_ok=True)
        self.db_path = os.path.join(self.data_dir, "snapshot.db")
        # 扫描在独立线程提交，需允许跨线程使用并以锁串行化写操作
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._lock = threading.Lock()
        self._init_schema()

    def _init_schema(self) -> None:
        with self._lock:
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS snapshot (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    schema_version INTEGER NOT NULL,
                    payload TEXT NOT NULL,
                    committed_at TEXT NOT NULL
                )
                """
            )
            self._conn.commit()

    def commit_replace(self, snapshot: ScanSnapshot) -> None:
        """扫描完成：覆盖唯一快照。"""
        snap_dict = snapshot.to_dict()
        prev = self.load()
        if prev and prev.get("ignored_threat_keys"):
            valid = {
                f"{f.get('source')}::{f.get('id')}"
                for f in snap_dict.get("exposure_findings", [])
            }
            snap_dict["ignored_threat_keys"] = [
                k for k in prev["ignored_threat_keys"] if k in valid
            ]
        apply_default_whitelist_to_snapshot(snap_dict)
        payload = json.dumps(snap_dict, ensure_ascii=False)
        with self._lock:
            self._conn.execute("DELETE FROM snapshot")
            self._conn.execute(
                "INSERT INTO snapshot (id, schema_version, payload, committed_at) "
                "VALUES (1, ?, ?, ?)",
                (snapshot.schema_version, payload, snapshot.meta.finished_at),
            )
            self._conn.commit()

    @staticmethod
    def threat_finding_key(source: str, finding_id: str) -> str:
        return f"{source}::{finding_id}"

    def ignore_threat(self, finding_key: str) -> Optional[dict]:
        """将威胁加入忽略列表（持久化于快照）。"""
        snap = self.load()
        if not snap:
            return None
        valid = {
            self.threat_finding_key(f.get("source", ""), f.get("id", ""))
            for f in snap.get("exposure_findings", [])
        }
        if finding_key not in valid:
            raise ValueError("未找到该威胁：" + str(finding_key))
        keys = list(snap.get("ignored_threat_keys") or [])
        if finding_key not in keys:
            keys.append(finding_key)
        snap["ignored_threat_keys"] = keys
        return self.write_full(snap)

    def unignore_threat(self, finding_key: str) -> Optional[dict]:
        """从忽略列表移除威胁。"""
        snap = self.load()
        if not snap:
            return None
        keys = [k for k in (snap.get("ignored_threat_keys") or []) if k != finding_key]
        snap["ignored_threat_keys"] = keys
        return self.write_full(snap)

    def collect_allowed_read_paths(self, snap: dict) -> set:
        """快照内可读取的本地文件路径（realpath）。"""
        allowed: set = set()
        for f in snap.get("exposure_findings", []):
            locs = list(f.get("locations") or [])
            if f.get("location"):
                locs.append(f["location"])
            for loc in locs:
                if not loc:
                    continue
                norm = safe_normalize_readable_path(loc)
                if norm and os.path.isfile(norm):
                    allowed.add(norm)
        for asset in snap.get("assets", []):
            p = asset.get("path")
            if not p:
                continue
            norm = safe_normalize_readable_path(p)
            if norm and os.path.isfile(norm):
                allowed.add(norm)
        return allowed

    def is_readable_finding_path(self, snap: dict, norm_path: str) -> bool:
        """请求路径是否在快照暴露面/资产路径白名单内。"""
        if norm_path in self.collect_allowed_read_paths(snap):
            return True
        for f in snap.get("exposure_findings", []):
            locs = list(f.get("locations") or [])
            if f.get("location"):
                locs.append(f["location"])
            for loc in locs:
                if not loc:
                    continue
                if safe_normalize_readable_path(loc) == norm_path:
                    return True
        for asset in snap.get("assets", []):
            p = asset.get("path")
            if not p:
                continue
            if safe_normalize_readable_path(p) == norm_path:
                return True
        return False

    def load(self) -> Optional[dict]:
        """读取最近一次快照（dict 形态，直接供 IPC 返回）。"""
        with self._lock:
            row = self._conn.execute(
                "SELECT payload FROM snapshot WHERE id = 1"
            ).fetchone()
        if not row:
            return None
        return json.loads(row[0])

    def patch_asset(self, asset_id: str, changes: dict) -> Optional[dict]:
        """资产写操作成功后的局部 patch（B3-b）。

        仅更新资产的 version/status/can_* 等字段以及派生统计；
        不触碰 exposure_findings / cve_findings。
        返回更新后的完整快照 dict（供 UI 刷新），无快照则返回 None。
        """
        snap = self.load()
        if not snap:
            return None
        for asset in snap.get("assets", []):
            if asset.get("id") == asset_id:
                asset.update(changes)
                break
        else:
            return None
        payload = json.dumps(snap, ensure_ascii=False)
        with self._lock:
            self._conn.execute("UPDATE snapshot SET payload = ? WHERE id = 1", (payload,))
            self._conn.commit()
        return snap

    def write_full(self, snap: dict) -> dict:
        """覆盖写入完整快照 dict（供 AssetManager 卸载等整体改写）。"""
        payload = json.dumps(snap, ensure_ascii=False)
        with self._lock:
            self._conn.execute("UPDATE snapshot SET payload = ? WHERE id = 1", (payload,))
            self._conn.commit()
        return snap

    def patch_agent_discovery(
        self, agent_id: str, agent_dict: dict, assets: list,
        cve_findings: Optional[list] = None,
    ) -> Optional[dict]:
        """单 Agent 资产刷新：更新 agent 字段并替换该 agent 的资产列表。"""
        snap = self.load()
        if not snap:
            return None
        agents = snap.get("agents", [])
        found = False
        for i, a in enumerate(agents):
            if a.get("id") == agent_id:
                agents[i] = {**a, **agent_dict}
                found = True
                break
        if not found:
            agents.append(agent_dict)
        snap["agents"] = agents
        snap["assets"] = [
            a for a in snap.get("assets", []) if a.get("agent_id") != agent_id
        ] + assets
        if cve_findings is not None:
            snap["cve_findings"] = [
                f for f in snap.get("cve_findings", [])
                if agent_id not in f.get("agent_ids", [])
            ] + cve_findings
        return self.write_full(snap)

    def close(self) -> None:
        self._conn.close()
