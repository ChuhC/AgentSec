import React, { useEffect } from "react";
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
import { scopeFromSetting } from "../i18n";
import { Radar } from "../components/Radar";
import { RiskCategoryChart } from "../components/RiskCategoryChart";
import type { Severity } from "../types";
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
  sev?: Severity;
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
  const { t } = useApp();
  const statusKey =
    score >= 80 ? "safe" : score >= 60 ? "good" : score >= 40 ? "caution" : "risk";
  const label = t(`results.scoreStatus.${statusKey}`);
  const labelColor =
    score >= 80 ? "var(--safe)" : score >= 60 ? "#34d399" : score >= 40 ? "var(--med)" : "var(--high)";
  const ringColor =
    score >= 80 ? "var(--purple-2)" : score >= 60 ? "#34d399" : score >= 40 ? "var(--med)" : "var(--high)";
  const pct = score / 100;
  const r = 46;
  const c = 2 * Math.PI * r;
  const desc =
    score >= 80
      ? t("results.scoreDesc.safe")
      : score >= 60
        ? t("results.scoreDesc.good")
        : t("results.scoreDesc.risk");

  return (
    <div className="card security-score-card results-score-card">
      <div className="results-score-title">{t("results.scoreTitle")}</div>
      <div className="security-score-body results-score-body">
        <div className="security-score-gauge results-score-gauge">
          <svg viewBox="0 0 100 100">
            <circle cx="50" cy="50" r={r} fill="none" className="score-gauge-track" strokeWidth="7" />
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
            {t("results.viewThreats")}
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
  const { t } = useApp();
  const tones: Record<Severity, "high" | "med" | "low"> = {
    high: "high",
    medium: "med",
    low: "low",
    safe: "low",
    info: "low",
  };
  const items: ExposureStatItem[] = stats.map((s) => ({
    ...s,
    tone: s.sev ? tones[s.sev] : "low",
  }));

  return (
    <div className="card exposure-summary-card" onClick={onClick}>
      <div className="exposure-summary-top">
        <div className="exposure-summary-title">
          <span className="exposure-summary-icon">
            <IconShield size={18} />
          </span>
          {t("results.threatTitle")}
        </div>
        <span className="exposure-summary-meta">{t("results.threatMeta", { total })}</span>
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
        {t("common.viewDetail")}
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
  const { t } = useApp();
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
        {t("common.viewDetail")}
        <IconChevron size={13} />
      </div>
    </div>
  );
}

export function Results() {
  const { snapshot, navigate, startScan, scanState, t, layer } = useApp();

  useEffect(() => {
    if (scanState === "scanning" || scanState === "cancelling") {
      navigate({ name: "scanning" });
    }
  }, [scanState, navigate]);

  if (!snapshot) {
    return (
      <main className="main">
        <div className="muted">{t("common.empty.noScanResult")}</div>
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
  const { axes: radarAxesRaw, series: radarSeries } = agentPermissionRadars(snapshot);
  const radarAxes = radarAxesRaw.map((a) => ({
    ...a,
    label: layer.permissionCategory(a.label),
  }));
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
    { value: exp.high, label: t("common.severity.high"), color: "var(--high)", sev: "high" },
    { value: exp.medium, label: t("common.severity.medium"), color: "var(--med)", sev: "medium" },
    { value: exp.low, label: t("common.severity.low"), color: "var(--low)", sev: "low" },
  ];

  const cveStats: StatItem[] = [
    { value: cve.high, label: t("common.severity.high"), subLabel: "CVE", color: "var(--high)" },
    { value: cve.medium, label: t("common.severity.medium"), color: "var(--med)" },
    { value: cve.affected, label: t("common.stat.affected"), subLabel: t("common.stat.component"), color: "var(--text-1)" },
  ];

  const assetStats: StatItem[] = [
    { value: ac.agents, label: t("agentList.statAgents"), color: "var(--purple-2)" },
    { value: ac.mcp, label: t("agentList.statMcp"), color: "var(--purple-2)" },
    { value: ac.skills, label: t("agentList.statSkills"), color: "var(--purple-2)" },
  ];

  return (
    <main className="main">
      <div className="card results-toolbar">
        <div className="results-toolbar-inner">
          <div className="row results-toolbar-meta">
            <div className="row results-toolbar-title" style={{ gap: 10 }}>
              <IconCheck size={20} style={{ color: "var(--safe)" }} />
              {t("results.scanComplete")}
            </div>
            <span className="muted row" style={{ gap: 6 }}>
              <IconClock size={15} />
              {snapshot.meta.duration_seconds} {t("results.durationUnit")}
            </span>
            <span className="muted row" style={{ gap: 6 }}>
              <IconMonitor size={15} />
              {layer.scopeLabel(snapshot.meta.scope)}
            </span>
            <div className="spacer" />
            <button
              className="btn btn-primary results-rescan-btn"
              onClick={() => startScan(scopeFromSetting(snapshot.meta.scope))}
            >
              <span className="row" style={{ gap: 7 }}>
                <IconRefresh size={15} />
                {t("results.rescan")}
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
          <div className="results-insight-head">{t("results.threatCategory")}</div>
          <div className="results-risk-chart-wrap">
            <RiskCategoryChart rows={riskCats} />
          </div>
        </div>
      </div>

      <div className="results-summary-bottom">
        <SummaryCard
          icon={<IconLayers size={20} />}
          title={t("common.nav.assets")}
          stats={assetStats}
          onClick={() => navigate({ name: "agent-list" })}
        />
        <SummaryCard
          cve
          icon={<IconCube size={20} />}
          title={t("results.componentVulns")}
          stats={
            cveUnavailable
              ? undefined
              : [
                  {
                    value: scannedDeps,
                    label: t("common.stat.scanned"),
                    subLabel: t("common.stat.component"),
                    color: "var(--purple-2)",
                  },
                  ...cveStats,
                ]
          }
          note={
            cveUnavailable
              ? undefined
              : cve.affected === 0
                ? t("results.noKnownCve")
                : undefined
          }
          empty={
            cveUnavailable ? (
              <span>
                {t("results.cveUnavailable")}
                <br />
                <span className="dim">{t("results.cveNetworkFailed")}</span>
              </span>
            ) : undefined
          }
          onClick={() => navigate(vulnListRoute(snapshot))}
        />
      </div>

      <div className="results-insights">
        <div className="card results-insight-card radar-card">
          <div className="results-insight-head">{t("results.radarTitle")}</div>
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
            {t("results.pendingTitle")}
          </div>
          {pending.length === 0 ? (
            <div className="muted" style={{ fontSize: 13, padding: "24px 0", textAlign: "center" }}>
              {t("results.pendingEmpty")}
            </div>
          ) : (
            <div className="pending-list">
              {pending.map((p) => (
                <div key={p.id} className="pending-item" onClick={() => goPending(p.id)}>
                  <div className={`pending-count ${p.tone}`}>{p.count}</div>
                  <div className="pending-text">
                    <div className="title">{layer.pendingActionLabel(p.id)}</div>
                    <div className="detail">{layer.pendingActionDetail(p.id, p.count)}</div>
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
