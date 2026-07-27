# AgentSec 测试与质量门禁

## 分层策略

| 层级 | 覆盖内容 | PR / push 门禁 |
|---|---|---|
| 前端单元测试 | 扫描路径、结果完整性评分、目录选择 | Vitest；核心纯逻辑行/函数/语句 ≥90%，分支 ≥85% |
| 引擎单元测试 | Adapter、解析器、CVE、脱敏、安全写回 | Python 3.10 / 3.11 / 3.12 全量执行 |
| 精准度回归 | 恶意/良性 ATR 语料、规则来源路由、行号、长文件 | 恶意样本命中指定检测器；良性样本零告警；语料规模不可静默缩水 |
| 流水线集成测试 | 自定义范围发现 → ATR worker → CVE → Reporter → 快照 | 使用真实文件与真实 ATR 子进程，禁止联网 |
| 冻结产物冒烟 | PyInstaller、stdio IPC、`freeze_support`、扫描结果 | Linux 与 Windows 均构建并执行真实扫描 |
| 发布门禁 | 上述全部检查 | Release 工作流必须先通过可复用 CI 工作流 |

## 覆盖率

- Python 使用分支覆盖率，当前最低门槛为 **52%**。这是全引擎口径的基线，
  后续只能提高，不能在未补测试的情况下调低。
- 前端只统计直接承载扫描决策的纯逻辑模块，避免用未渲染 UI 行数稀释门槛。
- CI 保存 Python XML 和前端 LCOV 报告，便于定位覆盖缺口。

## 本地运行

```bash
# Python 全量测试
./scripts/run-engine-tests.sh

# Python 覆盖率门禁
./scripts/run-engine-tests.sh \
  --cov=agentsec_engine --cov-branch \
  --cov-report=term-missing --cov-fail-under=52

# 前端测试与覆盖率
cd app
npm ci
npm run test:coverage
npm run build

# 冻结引擎冒烟（先构建）
npm run build:engine
cd ..
python3 scripts/smoke-frozen-engine.py
```

## 精准度语料维护

语料位于 `engine/tests/fixtures/atr_accuracy.json`：

1. 每个线上误报或漏报先加入最小复现，再修改规则。
2. 恶意样本必须声明 `expected_any_of`，不能靠无关规则碰巧通过。
3. 良性样本必须零告警。
4. 样本 ID 必须唯一；删除或缩减基线会触发契约测试。
5. 规则包升级必须单独提交，并运行全量精准度与冻结产物门禁。
