import React from "react";
import { useApp } from "../store";
import {
  activeThreatCount,
  agentPermissionRadars,
  assetCounts,
  cveCounts,
  exposureCounts,
  pendingActions,
  riskCategoryBreakdown,
  scanSecurityScore,
} from "../selectors";
import { threatListRoute, vulnListRoute } from "../navigation";
import { Radar } from "../components/Radar";
import { RiskCategoryChart } from "../components/RiskCategoryChart";
import {
  IconChevron,
  IconClock,
  IconCube,
  IconLayers,
  IconMonitor,
  IconRefresh,
  IconShield,
  IconShieldBadge,
  IconCheck,
  IconBolt,
} from "../components/Icons";

interface StatItem {
  value: number;
  label: string;
  subLabel?: string;
  color: string;
}

interface ExposureStatItem extends StatItem {
  tone: "high" | "med" | "low";
}

function ResultsScoreCard({
  score,
  onViewDetail,
}: {
  score: number;
  onViewDetail: () => void;
}) {
  const label =
    score >= 80 ? "安全" : score >= 60 ? "良好" : score >= 40 ? "注意" : "风险";
  const labelColor =
    score >= 80 ? "var(--safe)" : score >= 60 ? "#34d399" : score >= 40 ? "var(--med)" : "var(--high)";
  const ringColor =
    score >= 80 ? "var(--purple-2)" : score >= 60 ? "#34d399" : score >= 40 ? "var(--med)" : "var(--high)";
  const pct = score / 100;
  const r = 46;
  const c = 2 * Math.PI * r;
  const desc =
    score >= 80
      ? "未发现高风险行为，请继续保持。"
      : score >= 60
        ? "存在少量中低风险项，建议查看威胁管理。"
        : "发现需关注的风险项，请尽快处理。";

  return (
    <div className="card security-score-card results-score-card">
      <div className="results-score-title">综合安全评分</div>
      <div className="security-score-body results-score-body">
        <div className="security-score-gauge results-score-gauge">
          <svg viewBox="0 0 100 100">
            <circle cx="50" cy="50" r={r} fill="none" stroke="rgba(255,255,255,0.08)" strokeWidth="7" />
            <circle
              cx="50"
              cy="50"
              r={r}
              fill="none"
              stroke={ringColor}
              strokeWidth="7"
              strokeLinecap="round"
              strokeDasharray={`${c * pct} ${c}`}
            />
          </svg>
          <div className="security-score-value">
            <div className="results-score-num">{score}</div>
            <div className="results-score-denom">/ 100</div>
          </div>
        </div>
        <div className="security-score-info results-score-info">
          <div className="security-score-label results-score-status" style={{ color: labelColor }}>
            <IconShield size={16} />
            {label}
          </div>
          <div className="security-score-desc results-score-desc">{desc}</div>
          <button type="button" className="btn btn-primary btn-sm security-score-detail-btn" onClick={onViewDetail}>
            查看威胁
          </button>
        </div>
      </div>
    </div>
  );
}

function ThreatSummaryCard({
  stats,
  total,
  onClick,
}: {
  stats: StatItem[];
  total: number;
  onClick: () => void;
}) {
  const tones: Record<string, "high" | "med" | "low"> = {
    高危: "high",
    中危: "med",
    低危: "low",
  };
  const items: ExposureStatItem[] = stats.map((s) => ({
    ...s,
    tone: tones[s.label] || "low",
  }));

  return (
    <div className="card exposure-summary-card" onClick={onClick}>
      <div className="exposure-summary-top">
        <div className="exposure-summary-title">
          <span className="exposure-summary-icon">
            <IconShield size={18} />
          </span>
          威胁管理
        </div>
        <span className="exposure-summary-meta">共 {total} 项检查结论</span>
      </div>
      <div className="exposure-summary-body">
        <div className="exposure-summary-stats">
          {items.map((s) => (
            <div key={s.label} className={`exposure-stat-card exposure-stat-${s.tone}`}>
              <span className="exposure-stat-shield" style={{ color: s.color }}>
                <IconShieldBadge size={26} symbol={s.tone === "low" ? "info" : "alert"} />
              </span>
              <div className="exposure-stat-body">
                <div className="exposure-stat-label">{s.label}</div>
                <div className="exposure-stat-value" style={{ color: s.color }}>
                  {s.value}
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
      <div className="exposure-summary-foot">
        查看详情
        <IconChevron size={13} />
      </div>
    </div>
  );
}

function SummaryCard({
  icon,
  title,
  stats,
  note,
  empty,
  featured,
  cve,
  onClick,
}: {
  icon: React.ReactNode;
  title: string;
  stats?: StatItem[];
  note?: string;
  empty?: React.ReactNode;
  featured?: boolean;
  cve?: boolean;
  onClick: () => void;
}) {
  const mod = featured ? " summary-card-featured" : cve ? " summary-card-cve" : "";
  return (
    <div className={`card summary-card${mod}`} onClick={onClick}>
      <div className="summary-card-head">
        <span className="ic">{icon}</span>
        {title}
      </div>
      <div className="summary-card-body">
        {stats ? (
          <>
            <div className="summary-stats">
              {stats.map((s) => (
                <div key={s.label} className="summary-stat">
                  <div className="summary-stat-value" style={{ color: s.color }}>
                    {s.value}
                  </div>
                  <div className="summary-stat-label">
                    {s.label}
                    {s.subLabel && <span className="summary-stat-sublabel">{s.subLabel}</span>}
                  </div>
                </div>
              ))}
            </div>
            {note && <div className="summary-card-note">{note}</div>}
          </>
        ) : (
          <div className="summary-card-empty">{empty}</div>
        )}
      </div>
      <div className="summary-card-foot">
        查看详情
        <IconChevron size={13} />
      </div>
    </div>
  );
}

export function Results() {
  const { snapshot, navigate, startScan } = useApp();
  if (!snapshot) {
    return (
      <main className="main">
        <div className="muted">暂无扫描结果，请先在「安全扫描」发起扫描。</div>
      </main>
    );
  }
  const exp = exposureCounts(snapshot);
  const cve = cveCounts(snapshot);
  const ac = assetCounts(snapshot);
  const cveUnavailable = snapshot.meta.cve_status === "unavailable";
  const scannedDeps = snapshot.meta.cve_scanned_count ?? ac.dependencies;
  const riskCats = riskCategoryBreakdown(snapshot);
  const pending = pendingActions(snapshot);
  const { axes: radarAxes, series: radarSeries } = agentPermissionRadars(snapshot);
  const score = scanSecurityScore(snapshot);

  const goPending = (id: string) => {
    if (id === "threat-high") {
      navigate(threatListRoute(snapshot, { severity: "high" }));
      return;
    }
    if (id === "threat-medium") {
      navigate(threatListRoute(snapshot, { severity: "medium" }));
      return;
    }
    if (id === "cve-vuln") {
      navigate(vulnListRoute(snapshot));
      return;
    }
    if (id === "updatable") {
      const agent = snapshot.agents[0];
      if (agent) navigate({ name: "agent-workbench", agentId: agent.id, tab: "资产管理" });
      else navigate({ name: "agent-list" });
      return;
    }
    if (id === "disabled-skills" || id === "disabled-mcp") {
      const agent = snapshot.agents[0];
      if (agent) {
        navigate({
          name: "agent-workbench",
          agentId: agent.id,
          tab: "资产管理",
          focusSource: id === "disabled-skills" ? "Skills" : "MCP",
        });
      } else navigate({ name: "agent-list" });
    }
  };

  const activeThreats = activeThreatCount(snapshot);

  const exposureStats: StatItem[] = [
    { value: exp.high, label: "高危", color: "var(--high)" },
    { value: exp.medium, label: "中危", color: "var(--med)" },
    { value: exp.low, label: "低危", color: "var(--low)" },
  ];

  const cveStats: StatItem[] = [
    { value: cve.high, label: "高危", subLabel: "CVE", color: "var(--high)" },
    { value: cve.medium, label: "中危", color: "var(--med)" },
    { value: cve.affected, label: "受影响", subLabel: "组件", color: "var(--text-1)" },
  ];

  const assetStats: StatItem[] = [
    { value: ac.agents, label: "Agents", color: "var(--purple-2)" },
    { value: ac.mcp, label: "MCP", color: "var(--purple-2)" },
    { value: ac.skills, label: "Skills", color: "var(--purple-2)" },
  ];

  return (
    <main className="main">
      <div className="card results-toolbar">
        <div className="results-toolbar-inner">
          <div className="row results-toolbar-meta">
            <div className="row results-toolbar-title" style={{ gap: 10 }}>
              <IconCheck size={20} style={{ color: "var(--safe)" }} />
              扫描完成
            </div>
            <span className="muted row" style={{ gap: 6 }}>
              <IconClock size={15} />
              {snapshot.meta.duration_seconds} 秒
            </span>
            <span className="muted row" style={{ gap: 6 }}>
              <IconMonitor size={15} />
              {snapshot.meta.scope}
            </span>
            <div className="spacer" />
            <button
              className="btn btn-primary results-rescan-btn"
              onClick={() => startScan(snapshot.meta.scope)}
            >
              <span className="row" style={{ gap: 7 }}>
                <IconRefresh size={15} />
                重新扫描
              </span>
            </button>
          </div>
        </div>
      </div>

      <div className="results-exposure-row">
        <ResultsScoreCard
          score={score}
          onViewDetail={() => navigate(threatListRoute(snapshot))}
        />
        <ThreatSummaryCard
          stats={exposureStats}
          total={activeThreats}
          onClick={() => navigate(threatListRoute(snapshot))}
        />
        <div className="card results-insight-card results-risk-card results-risk-card-square">
          <div className="results-insight-head">威胁类别分布</div>
          <div className="results-risk-chart-wrap">
            <RiskCategoryChart rows={riskCats} />
          </div>
        </div>
      </div>

      <div className="results-summary-bottom">
        <SummaryCard
          icon={<IconLayers size={20} />}
          title="Agent 资产"
          stats={assetStats}
          onClick={() => navigate({ name: "agent-list" })}
        />
        <SummaryCard
          cve
          icon={<IconCube size={20} />}
          title="组件漏洞"
          stats={
            cveUnavailable
              ? undefined
              : [
                  {
                    value: scannedDeps,
                    label: "已扫描",
                    subLabel: "组件",
                    color: "var(--purple-2)",
                  },
                  ...cveStats,
                ]
          }
          note={
            cveUnavailable
              ? undefined
              : cve.affected === 0
                ? "暂无已知 CVE"
                : undefined
          }
          empty={
            cveUnavailable ? (
              <span>
                CVE 检测不可用
                <br />
                <span className="dim">联网失败，可稍后重试</span>
              </span>
            ) : undefined
          }
          onClick={() => navigate(vulnListRoute(snapshot))}
        />
      </div>

      <div className="results-insights">
        <div className="card results-insight-card radar-card">
          <div className="results-insight-head">全机权限雷达</div>
          <div className="results-radar-wrap">
            <Radar axes={radarAxes} series={radarSeries} size={218} />
            {radarSeries.length > 0 && (
              <div className="radar-legend">
                {radarSeries.map((s) => (
                  <div key={s.agentId} className="radar-legend-item">
                    <span className="radar-legend-dot" style={{ background: s.color }} />
                    {s.name}
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        <div className="card results-insight-card results-pending-section">
          <div className="results-insight-head row" style={{ gap: 8 }}>
            <IconBolt size={16} style={{ color: "var(--purple-2)" }} />
            待处理动作
          </div>
          {pending.length === 0 ? (
            <div className="muted" style={{ fontSize: 13, padding: "24px 0", textAlign: "center" }}>
              暂无待处理项，当前状态良好
            </div>
          ) : (
            <div className="pending-list">
              {pending.map((p) => (
                <div key={p.id} className="pending-item" onClick={() => goPending(p.id)}>
                  <div className={`pending-count ${p.tone}`}>{p.count}</div>
                  <div className="pending-text">
                    <div className="title">{p.label}</div>
                    <div className="detail">{p.detail}</div>
                  </div>
                  <IconChevron size={14} className="dim" />
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </main>
  );
}
