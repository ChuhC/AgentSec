"""agentSec 本地扫描引擎。

模块划分对齐架构文档（docs/architecture/architecture.md 第三节模块图）：

- discovery   : Agent 发现与 Adapter（Hermes / OpenClaw）
- detectors   : ExposureDetector（ATR + OpenClaw audit）、CVEDetector（OSV）
- reporter    : 脱敏 + 聚合，产出 ScanSnapshot
- asset_manager: 资产管理写操作 + 快照增量 patch
- store       : SnapshotStore（SQLite，仅保留最近一次快照）
- orchestrator: ScanOrchestrator 调度扫描流水线
- ipc         : stdio JSON IPC server（与 Electron 主进程通信）
"""

__version__ = "0.1.0"
