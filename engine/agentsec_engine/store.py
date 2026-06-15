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
        payload = json.dumps(snapshot.to_dict(), ensure_ascii=False)
        with self._lock:
            self._conn.execute("DELETE FROM snapshot")
            self._conn.execute(
                "INSERT INTO snapshot (id, schema_version, payload, committed_at) "
                "VALUES (1, ?, ?, ?)",
                (snapshot.schema_version, payload, snapshot.meta.finished_at),
            )
            self._conn.commit()

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

    def close(self) -> None:
        self._conn.close()
