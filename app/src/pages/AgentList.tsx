import React from "react";
import { useApp } from "../store";
import { assetCounts, assetsByAgent } from "../selectors";
import {
  IconBolt,
  IconChevron,
  IconCube,
  IconHexAgent,
  IconLayers,
  IconPlug,
} from "../components/Icons";

export function AgentList() {
  const { snapshot, navigate, startScan } = useApp();

  if (!snapshot) {
    return (
      <main className="main">
        <div className="page-title">资产管理</div>
        <div className="card" style={{ padding: 40, marginTop: 20, textAlign: "center" }}>
          <div className="muted">尚未扫描，暂无资产数据。</div>
          <button
            className="btn btn-primary"
            style={{ marginTop: 16 }}
            onClick={() => startScan("本机全部")}
          >
            立即扫描
          </button>
        </div>
      </main>
    );
  }

  const ac = assetCounts(snapshot);

  return (
    <main className="main">
      <div className="page-title">资产管理</div>
      <div className="page-sub">选择 Agent 查看组件与权限</div>

      {/* 汇总条 */}
      <div className="card" style={{ padding: "18px 24px", margin: "18px 0 18px" }}>
        <div className="row" style={{ justifyContent: "space-around" }}>
          <SummaryStat icon={<IconLayers size={22} />} value={ac.agents} label="Agents" />
          <SummaryStat icon={<IconCube size={22} />} value={ac.mcp} label="MCP" />
          <SummaryStat icon={<IconBolt size={22} />} value={ac.skills} label="Skills" />
        </div>
      </div>

      {/* Agent 卡片 */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
        {snapshot.agents.map((agent, i) => {
          const assets = assetsByAgent(snapshot, agent.id);
          const mcp = assets.filter((a) => a.type === "mcp").length;
          const skills = assets.filter((a) => a.type === "skill").length;
          const updatable = assets.filter((a) => a.status === "updatable").length;
          const hue = agent.kind === "openclaw" ? "#60a5fa" : "#a855f7";
          return (
            <div key={agent.id} className="card" style={{ padding: 22 }}>
              <div className="row" style={{ gap: 14 }}>
                <IconHexAgent size={48} hue={hue} />
                <div>
                  <div className="row" style={{ gap: 10 }}>
                    <span style={{ fontSize: 20, fontWeight: 700 }}>{agent.name}</span>
                    <span className="ver-badge">{agent.version}</span>
                  </div>
                  <div className="muted" style={{ fontSize: 13, marginTop: 4 }}>
                    {agent.description}
                  </div>
                </div>
              </div>

              <div className="row" style={{ gap: 38, margin: "22px 0 20px" }}>
                <MiniStat icon={<IconCube size={18} />} value={mcp} label="MCP" />
                <MiniStat icon={<IconBolt size={18} />} value={skills} label="Skills" />
                <MiniStat
                  icon={<IconPlug size={18} />}
                  value={updatable}
                  label="待更新"
                  highlight={updatable > 0}
                />
              </div>

              <button
                className="btn btn-primary"
                style={{ width: "100%", padding: "13px" }}
                onClick={() => navigate({ name: "agent-workbench", agentId: agent.id })}
              >
                <span className="row" style={{ gap: 8, justifyContent: "center" }}>
                  进入 <IconChevron size={15} />
                </span>
              </button>
            </div>
          );
        })}
      </div>
    </main>
  );
}

function SummaryStat({
  icon,
  value,
  label,
}: {
  icon: React.ReactNode;
  value: number;
  label: string;
}) {
  return (
    <div className="row" style={{ gap: 14 }}>
      <span
        className="row"
        style={{
          width: 44,
          height: 44,
          borderRadius: 12,
          background: "var(--purple-soft)",
          color: "var(--purple-2)",
          justifyContent: "center",
        }}
      >
        {icon}
      </span>
      <div>
        <div style={{ fontSize: 24, fontWeight: 800 }}>{value}</div>
        <div className="muted" style={{ fontSize: 12 }}>
          {label}
        </div>
      </div>
    </div>
  );
}

function MiniStat({
  icon,
  value,
  label,
  highlight,
}: {
  icon: React.ReactNode;
  value: number;
  label: string;
  highlight?: boolean;
}) {
  return (
    <div className="row" style={{ gap: 9 }}>
      <span style={{ color: highlight ? "var(--safe)" : "var(--purple-2)" }}>{icon}</span>
      <div>
        <div style={{ fontSize: 18, fontWeight: 700 }}>{value}</div>
        <div className="dim" style={{ fontSize: 11 }}>
          {label}
        </div>
      </div>
    </div>
  );
}
