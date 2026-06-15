# agentSec

面向普通本机用户的 **macOS 桌面安全工具**：一键扫描本机 Agent（Hermes / OpenClaw）的
暴露面 / 基线风险与组件 CVE，并在同一应用内查看与管理 MCP / Skills / 知识库 / 依赖。

> 暗紫毛玻璃桌面 UI · 纯本地扫描 · 暴露面与 CVE 双管线分离

## 仓库结构

```
agentSec/
├── engine/          # Python 扫描引擎（Discovery / ExposureDetector(ATR) / CVEDetector(OSV) / Reporter / AssetManager）
│   └── agentsec_engine/
│       ├── __main__.py        # 入口：python -m agentsec_engine（stdio JSON IPC）
│       ├── models.py          # 领域对象
│       ├── orchestrator.py    # 扫描流水线
│       ├── store.py           # SnapshotStore（SQLite，仅最近一次快照）
│       ├── discovery/         # Adapter：Hermes / OpenClaw
│       ├── detectors/         # exposure（ATR + OpenClaw audit）/ cve（OSV）
│       └── data/              # fixtures + 内置 ATR 规则子集
├── app/             # Electron + React + Vite + TypeScript 桌面壳
│   ├── electron/    # 主进程 + preload + 引擎桥接
│   └── src/         # React UI（pages 对应设计稿 step1-9）
└── docs/            # 需求 / 架构 / 设计稿（设计准绳）
```

## 架构概览

- **双进程**：Electron UI ⇄ Python 引擎（stdio 换行分隔 JSON IPC）
- **暴露面**：ATR（pyATR + 内置 rules 子集，纯离线）+ `openclaw security audit`
- **CVE**：联网 OSV（失败则 CVE 不可用，暴露面不受影响）
- **存储**：SQLite，仅保留最近一次快照；资产写操作成功后增量 patch
- 详见 [`docs/architecture/architecture.md`](docs/architecture/architecture.md)

> 当前为 **MVP 第一里程碑**：端到端骨架打通，引擎以对齐设计稿的 fixture 数据驱动；
> ATR(pyATR) / OSV / 真实 Adapter 解析逻辑的接入点已在各模块以 `TODO` 标出。

## 运行（开发）

前置：Node ≥ 18、Python 3（系统自带 3.8 即可运行引擎骨架）。

```bash
cd app
npm install          # 国内网络如下载 electron 失败：见下方镜像说明
npm run dev          # 启动 Vite + Electron，并自动 spawn Python 引擎
```

若 `npm install` 阶段 Electron 二进制下载失败（socket hang up），使用镜像：

```bash
ELECTRON_MIRROR="https://npmmirror.com/mirrors/electron/" npm install
```

### 环境变量

| 变量 | 说明 |
|------|------|
| `AGENTSEC_PYTHON` | 指定 Python 解释器（默认 `python3`） |
| `AGENTSEC_ENGINE_DIR` | 指定引擎目录（默认 `app/../engine`） |
| `AGENTSEC_DATA_DIR` | 覆盖快照/配置存储目录（默认 `~/Library/Application Support/agentSec/`） |

## 引擎独立联调

```bash
cd engine
printf '%s\n' '{"id":1,"method":"scan.start","params":{}}' | python3 -m agentsec_engine
```

IPC 方法：`ping` / `scan.start` / `scan.cancel` / `snapshot.get` /
`asset.update` / `asset.disable` / `asset.enable` / `asset.uninstall`。

## 构建

```bash
cd app && npm run build   # 类型检查 + 构建 renderer 与 electron 主进程/preload
```

## 打包 DMG（macOS）

一键脚本（推荐）：

```bash
./scripts/package-dmg.sh
```

可选参数：

| 参数 | 说明 |
|------|------|
| `--skip-engine` | 跳过 PyInstaller 引擎冻结（引擎代码未改时可加速） |
| `--skip-npm-install` | 跳过 `app/npm install` |

产物路径：`app/release/agentSec-<version>.dmg`

脚本会自动：创建/更新 `engine/.venv`、冻结 Python 引擎、构建前端、调用 electron-builder 打 dmg。
国内网络默认使用 npmmirror 镜像下载 Electron 与 builder 二进制。

也可在 `app/` 内手动执行：

```bash
cd app && npm run dist
```
