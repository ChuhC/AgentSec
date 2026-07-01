import React from "react";
import { useApp } from "../store";
import {
  activeThreatCount,
  agentSecurityScore,
  assetCounts,
  assetsByAgent,
  agentHue,
  cveForAgent,
} from "../selectors";
import {
  IconAlert,
  IconBolt,
  IconBook,
  IconChevron,
  IconCube,
  IconHexAgent,
  IconLayers,
  IconShield,
} from "../components/Icons";

function scoreColor(score: number): string {
  if (score < 60) return "var(--high)";
  if (score < 80) return "var(--med)";
  return "var(--safe)";
}

export function AgentList() {
  const { snapshot, navigate, startScan, t } = useApp();

  if (!snapshot) {
    return (
      <main className="main">
        <div className="page-title">{t("agentList.title")}</div>
        <div className="card" style={{ padding: 40, marginTop: 20, textAlign: "center" }}>
          <div className="muted">{t("agentList.empty")}</div>
          <button
            className="btn btn-primary"
            style={{ marginTop: 16 }}
            onClick={() => startScan("all")}
          >
            {t("agentList.scanNow")}
          </button>
        </div>
      </main>
    );
  }

  const ac = assetCounts(snapshot);

  return (
    <main className="main">
      <div className="page-title">{t("agentList.title")}</div>
      <div className="page-sub">{t("agentList.subtitle")}</div>

      <div className="card" style={{ padding: "18px 24px", margin: "18px 0 18px" }}>
        <div className="row" style={{ justifyContent: "space-around" }}>
          <SummaryStat icon={<IconLayers size={22} />} value={ac.agents} label={t("agentList.statAgents")} />
          <SummaryStat icon={<IconCube size={22} />} value={ac.mcp} label={t("agentList.statMcp")} />
          <SummaryStat icon={<IconBolt size={22} />} value={ac.skills} label={t("agentList.statSkills")} />
        </div>
      </div>

      <div className="agent-list-grid">
        {snapshot.agents.map((agent) => {
          const assets = assetsByAgent(snapshot, agent.id);
          const components = assets.length;
          const mcp = assets.filter((a) => a.type === "mcp").length;
          const skills = assets.filter((a) => a.type === "skill").length;
          const knowledge = assets.filter((a) => a.type === "knowledge").length;
          const threats = activeThreatCount(snapshot, agent.id);
          const vulnCount = cveForAgent(snapshot, agent.id).filter((c) => c.cves.length > 0).length;
          const score = agentSecurityScore(snapshot, agent.id);
          const hue = agentHue(agent.kind);
          return (
            <div key={agent.id} className="card agent-card">
              <div className="agent-card-head">
                <IconHexAgent size={44} hue={hue} />
                <div className="agent-card-title">
                  <span className="agent-card-name">{agent.name}</span>
                  {agent.version && (
                    <span className="agent-card-version dim">
                      {t("agentList.cardVersion", { version: agent.version })}
                    </span>
                  )}
                </div>
                <AgentCardScore score={score} label={t("agentList.statScore")} />
              </div>

              <div className="agent-card-stats">
                <CardStat
                  icon={<IconLayers size={15} />}
                  value={components}
                  label={t("agentList.statComponents")}
                />
                <CardStat
                  icon={<IconShield size={15} />}
                  value={threats}
                  label={t("agentList.statThreats")}
                  highlight={threats > 0}
                  highlightColor="var(--high)"
                />
                <CardStat
                  icon={<IconAlert size={15} />}
                  value={vulnCount}
                  label={t("agentList.statCve")}
                  highlight={vulnCount > 0}
                  highlightColor="var(--high)"
                />
                <CardStat icon={<IconCube size={15} />} value={mcp} label={t("agentList.statMcp")} />
                <CardStat icon={<IconBolt size={15} />} value={skills} label={t("agentList.statSkills")} />
                <CardStat
                  icon={<IconBook size={15} />}
                  value={knowledge}
                  label={t("agentWorkbench.assetKnowledge")}
                />
              </div>

              <button
                className="btn btn-primary agent-card-enter"
                onClick={() => navigate({ name: "agent-workbench", agentId: agent.id })}
              >
                <span className="row" style={{ gap: 8, justifyContent: "center" }}>
                  {t("agentList.enter")} <IconChevron size={15} />
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

function AgentCardScore({ score, label }: { score: number; label: string }) {
  const color = scoreColor(score);
  const r = 18;
  const circumference = 2 * Math.PI * r;
  const pct = score / 100;

  return (
    <div className="agent-card-score" aria-label={`${label} ${score}`}>
      <div className="agent-card-score-ring">
        <svg viewBox="0 0 44 44" aria-hidden>
          <circle cx="22" cy="22" r={r} fill="none" className="score-gauge-track" strokeWidth="3.5" />
          <circle
            cx="22"
            cy="22"
            r={r}
            fill="none"
            stroke={color}
            strokeWidth="3.5"
            strokeLinecap="round"
            strokeDasharray={circumference}
            strokeDashoffset={circumference * (1 - pct)}
          />
        </svg>
        <span className="agent-card-score-num" style={{ color }}>
          {score}
        </span>
      </div>
      <span className="agent-card-score-label dim">{label}</span>
    </div>
  );
}

function CardStat({
  icon,
  value,
  label,
  highlight,
  highlightColor = "var(--safe)",
}: {
  icon: React.ReactNode;
  value: number;
  label: string;
  highlight?: boolean;
  highlightColor?: string;
}) {
  return (
    <div className="agent-card-stat">
      <span style={{ color: highlight ? highlightColor : "var(--purple-2)" }}>{icon}</span>
      <div>
        <div className="agent-card-stat-value">{value}</div>
        <div className="agent-card-stat-label dim">{label}</div>
      </div>
    </div>
  );
}
