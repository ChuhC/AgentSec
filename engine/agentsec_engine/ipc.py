"""stdio JSON IPC server（与 Electron 主进程通信）。

协议：换行分隔的 JSON（NDJSON），每行一条消息。
  请求 (UI→Engine):  {"id": <int>, "method": <str>, "params": {...}}
  响应 (Engine→UI):  {"id": <int>, "result": {...}}  或  {"id": <int>, "error": {...}}
  事件 (Engine→UI):  {"event": "progress", "data": {...}}   # 无 id，扫描进度推送

stdout 仅用于协议消息；日志走 stderr，避免污染管道。
"""

from __future__ import annotations

import json
import sys
import threading
from typing import Optional

from .asset_manager import AssetManager, AssetOperationError
from .orchestrator import ScanOrchestrator
from .store import SnapshotStore


def _log(*args):
    print("[engine]", *args, file=sys.stderr, flush=True)


class IPCServer:
    def __init__(self):
        self.store = SnapshotStore()
        self.asset_manager = AssetManager(self.store)
        self._orchestrator: Optional[ScanOrchestrator] = None
        self._scan_thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

    # ---- 输出 ----

    def _send(self, obj: dict) -> None:
        with self._lock:
            sys.stdout.write(json.dumps(obj, ensure_ascii=False) + "\n")
            sys.stdout.flush()

    def _reply(self, req_id, result) -> None:
        self._send({"id": req_id, "result": result})

    def _error(self, req_id, message, code="error") -> None:
        self._send({"id": req_id, "error": {"code": code, "message": message}})

    def _emit(self, event: str, data: dict) -> None:
        self._send({"event": event, "data": data})

    # ---- 方法分发 ----

    def handle(self, msg: dict) -> None:
        req_id = msg.get("id")
        method = msg.get("method")
        params = msg.get("params") or {}
        try:
            if method == "ping":
                self._reply(req_id, {"pong": True})
            elif method == "scan.start":
                self._scan_start(req_id, params)
            elif method == "scan.cancel":
                self._scan_cancel(req_id)
            elif method == "snapshot.get":
                self._reply(req_id, {"snapshot": self.store.load()})
            elif method == "asset.update":
                self._reply(req_id, {"snapshot": self.asset_manager.update(params["assetId"])})
            elif method == "asset.disable":
                self._reply(req_id, {"snapshot": self.asset_manager.disable(params["assetId"])})
            elif method == "asset.enable":
                self._reply(req_id, {"snapshot": self.asset_manager.enable(params["assetId"])})
            elif method == "asset.uninstall":
                self._reply(req_id, {"snapshot": self.asset_manager.uninstall(params["assetId"])})
            else:
                self._error(req_id, "未知方法: " + str(method), code="unknown_method")
        except AssetOperationError as exc:
            self._error(req_id, str(exc), code="asset_op_failed")
        except Exception as exc:  # noqa: BLE001
            _log("handle error:", repr(exc))
            self._error(req_id, str(exc))

    def _scan_start(self, req_id, params) -> None:
        if self._scan_thread and self._scan_thread.is_alive():
            self._error(req_id, "已有扫描进行中", code="scan_busy")
            return
        scope = params.get("scope", "本机全部")
        scope_path = params.get("scopePath")
        cve_online = params.get("cveOnline", True)
        self._orchestrator = ScanOrchestrator(self.store, cve_online=cve_online)

        def run():
            try:
                result = self._orchestrator.run(
                    scope=scope,
                    scope_path=scope_path,
                    on_progress=lambda data: self._emit("progress", data),
                    simulate_delay=False,
                )
                if result.get("cancelled"):
                    self._emit("scan.cancelled", {})
                else:
                    self._emit("scan.completed", {"snapshot": result})
            except Exception as exc:  # noqa: BLE001
                _log("scan error:", repr(exc))
                self._emit("scan.error", {"message": str(exc)})

        self._scan_thread = threading.Thread(target=run, daemon=True)
        self._scan_thread.start()
        self._reply(req_id, {"started": True})

    def _scan_cancel(self, req_id) -> None:
        if self._orchestrator:
            self._orchestrator.cancel()
        self._reply(req_id, {"cancelling": True})

    # ---- 主循环 ----

    def serve_forever(self) -> None:
        _log("agentSec engine ready (stdio IPC)")
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                _log("bad json:", line[:120])
                continue
            self.handle(msg)
        _log("stdin closed, engine exiting")
