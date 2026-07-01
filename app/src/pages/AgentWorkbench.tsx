import React, { useCallback, useEffect, useMemo, useState } from "react";
import { useApp } from "../store";
import { ThreatList } from "./ThreatList";
import { VulnList } from "./VulnList";
import {
  agentHue,
  agentOptimizationSuggestions,
  agentSecurityScore,
  activeThreatCount,
  assetsByAgent,
  cveForAgent,
  exposureFindingKey,
  exposureFindingsForSkill,
  exposureForAgent,
  flattenPermissionMatrixRows,
  groupPermissionsBySection,
  isThreatIgnored,
  permissionsForMatrixCell,
  resolvePermissionLocate,
  type PermissionSectionKey,
  type PermissionSourceGroup,
} from "../selectors";
import { Radar, RadarAxis } from "../components/Radar";
import { SituationTopology } from "../components/topology/SituationTopology";

import { SeverityPill, ConfirmModal, useSeverityLabels } from "../components/common";
import type { Agent, Asset, AgentRuntime, CVEItem, ExposureFinding, PermissionEntry, ScanSnapshot, Severity } from "../types";
import {
  IconArrowLeft,
  IconBolt,
  IconBook,
  IconCube,
  IconFile,
  IconGlobe,
  IconTerminal,
  IconDatabase,
  IconHexAgent,
  IconChevron,
  IconLayers,
  IconRefresh,
  IconShield,
  IconShieldBadge,
} from "../components/Icons";

const SEV_W: Record<Severity, number> = { high: 3, medium: 2, low: 1, info: 0, safe: 0 };
const RADAR_CATS = ["文件", "Shell", "网络", "工具", "知识库"];
const MAIN_TABS = ["概览", "态势拓扑", "权限管理", "资产管理", "威胁管理", "漏洞管理"] as const;
const ASSET_SUB_TABS = ["MCP", "Skills", "Hooks", "知识库", "通道", "依赖"] as const;
const ASSET_TAB_TYPE: Record<(typeof ASSET_SUB_TABS)[number], string> = {
  MCP: "mcp",
  Skills: "skill",
  Hooks: "hook",
  知识库: "knowledge",
  通道: "channel",
  依赖: "dependency",
};

type TFn = ReturnType<typeof useApp>["t"];

function mainTabLabel(tab: (typeof MAIN_TABS)[number], t: TFn): string {
  const map: Record<(typeof MAIN_TABS)[number], string> = {
    概览: "tabOverview",
    权限管理: "tabPermissions",
    资产管理: "tabAssets",
    威胁管理: "tabThreats",
    漏洞管理: "tabVulns",
    态势拓扑: "tabTopology",
  };
  return t(`agentWorkbench.${map[tab]}`);
}

function assetSubTabLabel(tab: (typeof ASSET_SUB_TABS)[number], t: TFn): string {
  const map: Record<(typeof ASSET_SUB_TABS)[number], string> = {
    MCP: "assetMcp",
    Skills: "assetSkills",
    Hooks: "assetHooks",
    知识库: "assetKnowledge",
    通道: "assetChannel",
    依赖: "assetDeps",
  };
  return t(`agentWorkbench.${map[tab]}`);
}

function resolveInitialTab(initialTab?: string): {
  main: (typeof MAIN_TABS)[number];
  assetSub: (typeof ASSET_SUB_TABS)[number];
} {
  if (initialTab === "风险管理") initialTab = "威胁管理";
  if (
    initialTab === "资产管理" ||
    initialTab === "权限管理" ||
    initialTab === "威胁管理" ||
    initialTab === "漏洞管理" ||
    initialTab === "态势拓扑" ||
    initialTab === "概览"
  ) {
    return { main: initialTab, assetSub: "MCP" };
  }
  if (initialTab && ASSET_SUB_TABS.includes(initialTab as (typeof ASSET_SUB_TABS)[number])) {
    return { main: "资产管理", assetSub: initialTab as (typeof ASSET_SUB_TABS)[number] };
  }
  return { main: "概览", assetSub: "MCP" };
}

export function AgentWorkbench({
  agentId,
  initialTab,
  focusSource,
}: {
  agentId: string;
  initialTab?: string;
  focusSource?: string;
}) {
  const { snapshot, navigate, refreshAgentAssets, updateAgent, settings, t } = useApp();
  const init = resolveInitialTab(initialTab);
  const [tab, setTab] = useState<(typeof MAIN_TABS)[number]>(init.main);
  const [assetSubTab, setAssetSubTab] = useState<(typeof ASSET_SUB_TABS)[number]>(() => {
    if (focusSource && ASSET_SUB_TABS.includes(focusSource as (typeof ASSET_SUB_TABS)[number])) {
      return focusSource as (typeof ASSET_SUB_TABS)[number];
    }
    return init.assetSub;
  });
  const [refreshing, setRefreshing] = useState(false);
  const [threatFindingId, setThreatFindingId] = useState<string | undefined>();
  const [highlightAssetId, setHighlightAssetId] = useState<string | undefined>();
  const [permFocusSource, setPermFocusSource] = useState<string | undefined>();
  const [confirmAgentUpdate, setConfirmAgentUpdate] = useState<Agent | null>(null);
  const [manualUpdateAgent, setManualUpdateAgent] = useState<Agent | null>(null);
  const [updatingAgent, setUpdatingAgent] = useState(false);

  const agent = snapshot?.agents.find((a) => a.id === agentId);
  if (!snapshot || !agent) {
    return (
      <main className="main">
        <div className="muted">{t("agentWorkbench.notFound")}</div>
      </main>
    );
  }

  const assets = assetsByAgent(snapshot, agentId);
  const activeThreats = activeThreatCount(snapshot, agentId);
  const hue = agentHue(agent.kind);

  const goAssets = (sub: (typeof ASSET_SUB_TABS)[number] = "MCP", assetId?: string) => {
    setAssetSubTab(sub);
    setHighlightAssetId(assetId);
    setTab("资产管理");
  };

  const goThreat = (findingId?: string) => {
    setThreatFindingId(findingId);
    setTab("威胁管理");
  };

  const handleTopoNavigate = useCallback(
    (target: { tab: "权限管理" | "威胁管理" | "漏洞管理" | "资产管理"; permSource?: string; assetSubTab?: string }) => {
      if (target.tab === "权限管理") {
        setPermFocusSource(target.permSource);
        setTab("权限管理");
      } else if (target.tab === "威胁管理") {
        goThreat();
      } else if (target.tab === "漏洞管理") {
        setTab("漏洞管理");
      } else if (target.tab === "资产管理") {
        goAssets((target.assetSubTab as (typeof ASSET_SUB_TABS)[number]) || "MCP");
      }
    },
    []
  );

  return (
    <main className="main flush">
      <div className="row" style={{ gap: 8 }}>
        <span className="link" onClick={() => navigate({ name: "agent-list" })}>
          <IconArrowLeft size={18} /> {t("common.action.back")}
        </span>
        {focusSource && tab !== "概览" && (
          <span className="dim" style={{ fontSize: 12, marginLeft: 8 }}>
            {t("agentWorkbench.fromOverview", { source: focusSource })}
          </span>
        )}
      </div>

      <div className="row agent-workbench-head" style={{ gap: 14, marginTop: 12 }}>
        <IconHexAgent size={42} hue={hue} />
        <span style={{ fontSize: 24, fontWeight: 800 }}>{agent.name}</span>
        <span className="ver-badge">{agent.version || "—"}</span>
        <span className="row muted" style={{ gap: 5, fontSize: 13 }}>
          <span style={{ width: 8, height: 8, borderRadius: 4, background: "var(--safe)" }} />
          {agent.enabled ? t("common.status.enabled") : t("common.status.disabled")}
        </span>
        <span className="spacer" />
        <button
          type="button"
          className="btn btn-ghost agent-refresh-btn"
          disabled={refreshing}
          title={t("agentWorkbench.refreshAssetsTitle")}
          onClick={async () => {
            setRefreshing(true);
            try {
              await refreshAgentAssets(agentId);
            } finally {
              setRefreshing(false);
            }
          }}
        >
          <span className="row" style={{ gap: 6 }}>
            <IconRefresh size={15} className={refreshing ? "spin" : undefined} />
            {t("agentWorkbench.refreshAssets")}
          </span>
        </button>
      </div>

      <div className="tabs">
        {MAIN_TABS.map((tabKey) => (
          <div
            key={tabKey}
            className={`tab ${tab === tabKey ? "active" : ""}`}
            onClick={() => setTab(tabKey)}
          >
            {mainTabLabel(tabKey, t)}
          </div>
        ))}
      </div>

      {tab === "概览" && (
        <Overview
          agent={agent}
          agentId={agentId}
          snapshot={snapshot}
          assets={assets}
          activeThreats={activeThreats}
          onGoAssets={() => goAssets("MCP")}
          onGoPermissions={() => setTab("权限管理")}
          onGoThreat={() => goThreat()}
          onGoVuln={() => setTab("漏洞管理")}
          onSelectFinding={(findingId) => goThreat(findingId)}
          onCheckUpdate={async () => {
            setRefreshing(true);
            try {
              const snap = await refreshAgentAssets(agentId);
              const fresh = snap?.agents.find((a) => a.id === agentId);
              if (!fresh?.update_available) return;
              if (fresh.can_update) {
                if (settings.confirmUpdate) setConfirmAgentUpdate(fresh);
                else {
                  setUpdatingAgent(true);
                  try {
                    await updateAgent(agentId);
                  } finally {
                    setUpdatingAgent(false);
                  }
                }
              } else {
                setManualUpdateAgent(fresh);
              }
            } finally {
              setRefreshing(false);
            }
          }}
          updating={refreshing || updatingAgent}
        />
      )}
      {confirmAgentUpdate && (
        <ConfirmModal
          title={t("agentWorkbench.confirmAgentUpdateTitle")}
          message={t("agentWorkbench.confirmAgentUpdateMsg", {
            command: confirmAgentUpdate.update_command || "update",
          })}
          confirmLabel={t("agentWorkbench.checkUpdate")}
          onConfirm={async () => {
            const id = confirmAgentUpdate.id;
            setConfirmAgentUpdate(null);
            setUpdatingAgent(true);
            try {
              await updateAgent(id);
            } finally {
              setUpdatingAgent(false);
            }
          }}
          onCancel={() => setConfirmAgentUpdate(null)}
        />
      )}
      {manualUpdateAgent && (
        <ConfirmModal
          title={t("agentWorkbench.manualUpdateTitle")}
          message={`${t("agentWorkbench.manualUpdateMsg")}\n${manualUpdateAgent.update_command || ""}`}
          confirmLabel={t("common.action.close")}
          onConfirm={() => setManualUpdateAgent(null)}
          onCancel={() => setManualUpdateAgent(null)}
        />
      )}
      {tab === "权限管理" && (
        <PermissionManagementTab
          agent={agent}
          assets={assets}
          onLocateSource={(sub, assetId) => goAssets(sub, assetId)}
          focusSource={permFocusSource}
        />
      )}
      {tab === "资产管理" && (
        <AssetManagementView
          agentId={agentId}
          assets={assets}
          subTab={assetSubTab}
          onSubTabChange={(sub) => {
            setHighlightAssetId(undefined);
            setAssetSubTab(sub);
          }}
          highlightAssetId={highlightAssetId}
          onGoThreat={goThreat}
        />
      )}
      {tab === "威胁管理" && (
        <ThreatList agentId={agentId} findingId={threatFindingId} embedded />
      )}
      {tab === "漏洞管理" && <VulnList agentId={agentId} embedded />}
      {tab === "态势拓扑" && (
        <SituationTopology
          agentId={agentId}
          agentLabel={agent ? agent.name : agentId}
          snapshot={snapshot}
          onNavigate={handleTopoNavigate}
        />
      )}
    </main>
  );
}

/* ---------- 概览 ---------- */
function Overview({
  agent,
  agentId,
  snapshot,
  assets,
  activeThreats,
  onGoAssets,
  onGoPermissions,
  onGoThreat,
  onGoVuln,
  onSelectFinding,
  onCheckUpdate,
  updating,
}: {
  agent: Agent;
  agentId: string;
  snapshot: ScanSnapshot;
  assets: Asset[];
  activeThreats: number;
  onGoAssets: () => void;
  onGoPermissions: () => void;
  onGoThreat: () => void;
  onGoVuln: () => void;
  onSelectFinding: (findingId: string) => void;
  onCheckUpdate: () => void;
  updating: boolean;
}) {
  const { t, layer } = useApp();
  const perms: PermissionEntry[] = [
    ...agent.permissions,
    ...assets.flatMap((a) => a.permissions),
  ];
  const radarAxes: RadarAxis[] = RADAR_CATS.map((cat) => {
    const inCat = perms.filter((p) => p.category === cat);
    const max = inCat.reduce((m, p) => Math.max(m, SEV_W[p.severity]), 0);
    return { label: layer.permissionCategory(cat), score: max / 3 };
  });

  const mcp = assets.filter((a) => a.type === "mcp").length;
  const skills = assets.filter((a) => a.type === "skill").length;
  const knowledge = assets.filter((a) => a.type === "knowledge").length;
  const channels = assets.filter((a) => a.type === "channel").length;

  const vulnComponents = cveForAgent(snapshot, agentId).length;
  const scannedDeps = assets.filter((a) => a.type === "dependency").length;

  const ports = agent.listen_ports?.length ? agent.listen_ports.join(", ") : "—";
  const latestVer = agent.update_available
    ? agent.latest_version || "—"
    : agent.version || "—";
  const versionUpToDate = !agent.update_available;
  const updateBtnLabel = versionUpToDate
    ? t("agentWorkbench.recheckUpdate")
    : agent.can_update
      ? t("agentWorkbench.checkUpdate")
      : t("agentWorkbench.updateAvailable");
  const score = agentSecurityScore(snapshot, agentId);
  const suggestions = agentOptimizationSuggestions(snapshot, agentId);

  let expHigh = 0;
  let expMed = 0;
  let expLow = 0;
  for (const f of exposureForAgent(snapshot, agentId)) {
    if (isThreatIgnored(snapshot, f)) continue;
    if (f.severity === "high") expHigh++;
    else if (f.severity === "medium") expMed++;
    else if (f.severity === "low") expLow++;
  }

  const cveFindings = cveForAgent(snapshot, agentId);
  let cveHigh = 0;
  let cveMed = 0;
  for (const c of cveFindings) {
    if (c.severity === "high") cveHigh++;
    else if (c.severity === "medium") cveMed++;
  }

  const exposureStats = [
    { value: expHigh, label: t("common.severity.high"), color: "var(--high)", sev: "high" as Severity },
    { value: expMed, label: t("common.severity.medium"), color: "var(--med)", sev: "medium" as Severity },
    { value: expLow, label: t("common.severity.low"), color: "var(--low)", sev: "low" as Severity },
  ];

  const assetStats = [
    { value: mcp, label: "MCP", color: "var(--purple-2)" },
    { value: skills, label: "Skills", color: "var(--purple-2)" },
    { value: knowledge, label: t("agentWorkbench.assetKnowledge"), color: "var(--purple-2)" },
    { value: channels, label: t("agentWorkbench.assetChannel"), color: "var(--purple-2)" },
  ];

  const cveStats = [
    { value: scannedDeps, label: t("common.stat.scanned"), subLabel: t("common.stat.component"), color: "var(--purple-2)" },
    { value: cveHigh, label: t("common.severity.high"), subLabel: "CVE", color: "var(--high)" },
    { value: cveMed, label: t("common.severity.medium"), color: "var(--med)" },
    { value: vulnComponents, label: t("common.stat.affected"), subLabel: t("common.stat.component"), color: "var(--text-1)" },
  ];

  return (
    <div className="overview-wrap">
      <div className="card overview-meta" style={{ padding: "14px 18px" }}>
        <div className="overview-meta-row">
          <button
            type="button"
            className={`btn btn-ghost overview-update-btn${!versionUpToDate ? " is-available" : ""}`}
            disabled={updating}
            onClick={onCheckUpdate}
          >
            <span className="row" style={{ gap: 6 }}>
              <IconRefresh size={14} className={updating ? "spin" : undefined} />
              {updating ? t("agentWorkbench.updatingAgent") : updateBtnLabel}
            </span>
          </button>
          <MetaCell label={t("agentWorkbench.currentVersion")} value={agent.version || "—"} />
          <MetaCell label={t("agentWorkbench.latestVersion")} value={latestVer} highlight={!versionUpToDate} />
          {agent.update_detail && !versionUpToDate && (
            <MetaCell label={t("agentWorkbench.updateDetail")} value={agent.update_detail} />
          )}
          <MetaCell label={t("agentWorkbench.listenPorts")} value={ports} mono />
        </div>
      </div>

      <div className="results-exposure-row agent-overview-hero">
        <OverviewScoreCard score={score} onViewDetail={onGoThreat} />
        <OverviewThreatCard
          stats={exposureStats}
          total={activeThreats}
          onClick={onGoThreat}
        />
        <div className="card results-insight-card agent-overview-radar">
          <div className="results-insight-head">{t("agentWorkbench.permissionRadar")}</div>
          <div
            className="results-radar-wrap radar-detail-wrap"
            role="button"
            tabIndex={0}
            title={t("agentWorkbench.viewPermissions")}
            onClick={onGoPermissions}
            onKeyDown={(e) => {
              if (e.key === "Enter" || e.key === " ") {
                e.preventDefault();
                onGoPermissions();
              }
            }}
          >
            <Radar axes={radarAxes} size={200} />
            <span className="radar-detail-entry" aria-hidden>
              <IconLayers size={14} />
            </span>
          </div>
        </div>
      </div>

      <div className="results-summary-bottom agent-overview-mid">
        <OverviewSummaryCard
          icon={<IconLayers size={20} />}
          title={t("common.nav.assets")}
          stats={assetStats}
          onClick={onGoAssets}
        />
        <OverviewSummaryCard
          cve
          icon={<IconCube size={20} />}
          title={t("results.componentVulns")}
          stats={cveStats}
          note={vulnComponents === 0 ? t("results.noKnownCve") : undefined}
          onClick={onGoVuln}
        />
      </div>

      <div className="results-insights agent-overview-bottom">
        <RuntimePanel agentId={agentId} />
        <OptimizationPanel
          items={suggestions}
          onGoThreat={onGoThreat}
          onSelectFinding={onSelectFinding}
        />
      </div>
    </div>
  );
}

interface OverviewStatItem {
  value: number;
  label: string;
  subLabel?: string;
  color: string;
  sev?: Severity;
}

function OverviewScoreCard({
  score,
  onViewDetail,
}: {
  score: number;
  onViewDetail: () => void;
}) {
  const { t, layer } = useApp();
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
      <div className="results-score-title">{t("agentWorkbench.scoreTitle")}</div>
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

function OverviewThreatCard({
  stats,
  total,
  onClick,
}: {
  stats: OverviewStatItem[];
  total: number;
  onClick: () => void;
}) {
  const { t, layer } = useApp();
  const tones: Record<Severity, "high" | "med" | "low"> = {
    high: "high",
    medium: "med",
    low: "low",
    safe: "low",
    info: "low",
  };

  return (
    <div className="card exposure-summary-card" onClick={onClick}>
      <div className="exposure-summary-top">
        <div className="exposure-summary-title">
          <span className="exposure-summary-icon">
            <IconShield size={18} />
          </span>
          {t("common.nav.threats")}
        </div>
        <span className="exposure-summary-meta">{t("agentWorkbench.threatMeta", { total })}</span>
      </div>
      <div className="exposure-summary-body">
        <div className="exposure-summary-stats">
          {stats.map((s) => {
            const tone = s.sev ? tones[s.sev] : "low";
            return (
              <div key={s.label} className={`exposure-stat-card exposure-stat-${tone}`}>
                <span className="exposure-stat-shield" style={{ color: s.color }}>
                  <IconShieldBadge size={26} symbol={tone === "low" ? "info" : "alert"} />
                </span>
                <div className="exposure-stat-body">
                  <div className="exposure-stat-label">{s.label}</div>
                  <div className="exposure-stat-value" style={{ color: s.color }}>
                    {s.value}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </div>
      <div className="exposure-summary-foot">
        {t("common.viewDetail")}
        <IconChevron size={13} />
      </div>
    </div>
  );
}

function OverviewSummaryCard({
  icon,
  title,
  stats,
  note,
  cve,
  onClick,
}: {
  icon: React.ReactNode;
  title: string;
  stats: OverviewStatItem[];
  note?: string;
  cve?: boolean;
  onClick: () => void;
}) {
  const { t, layer } = useApp();
  const mod = cve ? " summary-card-cve" : "";
  return (
    <div className={`card summary-card${mod}`} onClick={onClick}>
      <div className="summary-card-head">
        <span className="ic">{icon}</span>
        {title}
      </div>
      <div className="summary-card-body">
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
      </div>
      <div className="summary-card-foot">
        {t("common.viewDetail")}
        <IconChevron size={13} />
      </div>
    </div>
  );
}

function OptimizationPanel({
  items,
  onGoThreat,
  onSelectFinding,
}: {
  items: ReturnType<typeof agentOptimizationSuggestions>;
  onGoThreat: () => void;
  onSelectFinding: (findingId: string) => void;
}) {
  const { t, layer } = useApp();
  return (
    <div className="card results-insight-card results-pending-section">
      <div className="results-insight-head row" style={{ gap: 8 }}>
        <IconBolt size={16} style={{ color: "var(--purple-2)" }} />
        {t("agentWorkbench.optimizationTitle")}
      </div>
      {items.length === 0 ? (
        <div className="muted" style={{ fontSize: 13, padding: "24px 0", textAlign: "center" }}>
          {t("agentWorkbench.optimizationEmpty")}
        </div>
      ) : (
        <div className="pending-list">
          {items.map((item) => (
            <div
              key={item.id}
              className="pending-item"
              onClick={() => {
                if (item.findingId) onSelectFinding(item.findingId);
                else onGoThreat();
              }}
            >
              <SeverityPill sev={item.severity} />
              <div className="pending-text">
                <div className="title">{layer.optimizationTitle(item)}</div>
              </div>
              <IconChevron size={14} className="dim" />
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function PermissionManagementTab({
  agent,
  assets,
  onLocateSource,
  focusSource,
}: {
  agent: Agent;
  assets: Asset[];
  onLocateSource: (sub: (typeof ASSET_SUB_TABS)[number], assetId: string) => void;
  focusSource?: string;
}) {
  const { t, layer } = useApp();
  const sections = useMemo(() => groupPermissionsBySection(agent, assets), [agent, assets]);

  const [catFilter, setCatFilter] = useState("all");
  const [sourceFilter, setSourceFilter] = useState<PermissionSectionKey | "all">(
    (focusSource as PermissionSectionKey) || "all"
  );
  useEffect(() => {
    if (focusSource) setSourceFilter(focusSource as PermissionSectionKey);
  }, [focusSource]);
  const [query, setQuery] = useState("");
  const [selection, setSelection] = useState<
    | { kind: "row"; rowKey: string }
    | { kind: "cell"; rowKey: string; category: string }
    | null
  >(null);

  const totalPerms = useMemo(
    () => sections.reduce((n, s) => n + s.subGroups.reduce((m, g) => m + g.permissions.length, 0), 0),
    [sections]
  );
  const componentCount = useMemo(
    () => sections.reduce((n, s) => n + s.subGroups.length, 0),
    [sections]
  );

  const availableSources = useMemo(() => sections.map((s) => s.key), [sections]);

  const filteredSections = useMemo(() => {
    const q = query.trim().toLowerCase();
    const base =
      sourceFilter === "all" ? sections : sections.filter((s) => s.key === sourceFilter);
    return base
      .map((section) => {
        const subGroups = section.subGroups
          .map((g) => {
            const permissions = g.permissions.filter((p) => {
              if (catFilter !== "all" && p.category !== catFilter) return false;
              if (q) {
                const hay = [
                  p.name,
                  p.category,
                  layer.permissionName(p.name),
                  layer.permissionCategory(p.category),
                  g.sourceLabel,
                  layer.permissionSourceLabel(g.sourceLabel),
                  permissionSectionTitle(section.key, t),
                ]
                  .join(" ")
                  .toLowerCase();
                if (!hay.includes(q)) return false;
              }
              return true;
            });
            return { ...g, permissions };
          })
          .filter((g) => g.permissions.length > 0);
        return { ...section, subGroups };
      })
      .filter((s) => s.subGroups.length > 0);
  }, [sections, catFilter, sourceFilter, query, layer, t]);

  const matrixRows = useMemo(
    () => flattenPermissionMatrixRows(filteredSections),
    [filteredSections]
  );

  const filteredPerms = useMemo(
    () => matrixRows.reduce((n, r) => n + r.group.permissions.length, 0),
    [matrixRows]
  );

  const selectedRow = useMemo(() => {
    if (!selection) return null;
    return matrixRows.find((r) => r.key === selection.rowKey) ?? null;
  }, [selection, matrixRows]);

  const detailPermissions = useMemo(() => {
    if (!selectedRow) return [];
    if (selection?.kind === "cell") {
      return permissionsForMatrixCell(selectedRow.group, selection.category);
    }
    return selectedRow.group.permissions;
  }, [selectedRow, selection]);

  const handleLocate = (group: PermissionSourceGroup) => {
    const target = resolvePermissionLocate(group, assets);
    if (!target) return;
    onLocateSource(target.subTab, target.assetId);
  };

  const selectRow = (rowKey: string) => {
    setSelection((prev) =>
      prev?.kind === "row" && prev.rowKey === rowKey ? null : { kind: "row", rowKey }
    );
  };

  return (
    <div className="permission-list-embedded">
      <div className="dim" style={{ fontSize: 12.5, marginBottom: 6 }}>
        {t("agentWorkbench.permissionTabMeta", { count: totalPerms, sources: componentCount })}
        {filteredPerms !== totalPerms && (
          <> · {t("threatList.metaFiltered", { count: filteredPerms })}</>
        )}
      </div>
      <div className="dim" style={{ fontSize: 12, marginBottom: 14 }}>
        {t("agentWorkbench.permissionMatrixHint")}
      </div>

      <div className="card cve-toolbar" style={{ padding: "14px 16px", marginBottom: 14 }}>
        <div className="row" style={{ gap: 10, flexWrap: "wrap" }}>
          <select
            className="select-input cve-filter"
            value={catFilter}
            onChange={(e) => setCatFilter(e.target.value)}
          >
            <option value="all">{t("agentWorkbench.permissionMatrixFilterDimension")}</option>
            {RADAR_CATS.map((cat) => (
              <option key={cat} value={cat}>
                {layer.permissionCategory(cat)}
              </option>
            ))}
          </select>
          <select
            className="select-input cve-filter"
            value={sourceFilter}
            onChange={(e) => setSourceFilter(e.target.value as PermissionSectionKey | "all")}
          >
            <option value="all">{t("agentWorkbench.permissionMatrixFilterSource")}</option>
            {availableSources.map((key) => (
              <option key={key} value={key}>
                {permissionSectionTitle(key, t)}
              </option>
            ))}
          </select>
          <input
            className="text-input cve-search"
            placeholder={t("agentWorkbench.permissionSearchPlaceholder")}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
        </div>
      </div>

      {matrixRows.length === 0 ? (
        <div className="card permission-detail-empty muted">
          {sections.length === 0
            ? t("agentWorkbench.permissionEmptyNone")
            : t("agentWorkbench.permissionEmptyNoMatch")}
        </div>
      ) : (
        <>
          <div className="card permission-matrix-card">
            <div className="permission-matrix-scroll">
              <table className="permission-matrix">
                <thead>
                  <tr>
                    <th className="permission-matrix-sticky-col">{t("common.table.name")}</th>
                    {RADAR_CATS.map((cat) => (
                      <th key={cat} className="permission-matrix-cat-col">
                        {layer.permissionCategory(cat)}
                      </th>
                    ))}
                    <th className="permission-matrix-action-col">{t("common.table.actions")}</th>
                  </tr>
                </thead>
                <tbody>
                  {matrixRows.map((row, idx) => {
                    const prevSection = idx > 0 ? matrixRows[idx - 1].sectionKey : null;
                    const sectionBreak = prevSection !== null && prevSection !== row.sectionKey;
                    const rowSelected = selection?.rowKey === row.key && selection.kind === "row";
                    const locate = resolvePermissionLocate(row.group, assets);
                    return (
                      <tr
                        key={row.key}
                        className={`permission-matrix-row${sectionBreak ? " section-break" : ""}${rowSelected ? " row-selected" : ""}`}
                      >
                        <td className="permission-matrix-sticky-col">
                          <button
                            type="button"
                            className={`permission-matrix-name${rowSelected ? " active" : ""}`}
                            onClick={() => selectRow(row.key)}
                          >
                            <span className="permission-matrix-name-text">
                              {layer.permissionSourceLabel(row.group.sourceLabel)}
                            </span>
                            <span className="tag tag-muted permission-matrix-type">
                              {permissionSectionTitle(row.sectionKey, t)}
                            </span>
                          </button>
                        </td>
                        {RADAR_CATS.map((cat) => {
                          const cellPerms = permissionsForMatrixCell(row.group, cat);
                          const hasPerm = cellPerms.length > 0;
                          return (
                            <td key={cat} className="permission-matrix-cat-col">
                              {hasPerm ? (
                                <span
                                  className="permission-matrix-cell has-perm permission-matrix-cell-readonly"
                                  title={t("agentWorkbench.permissionGroupCount", {
                                    count: cellPerms.length,
                                  })}
                                >
                                  {cellPerms.length > 1 ? cellPerms.length : ""}
                                </span>
                              ) : (
                                <span className="permission-matrix-empty">—</span>
                              )}
                            </td>
                          );
                        })}
                        <td className="permission-matrix-action-col">
                          {locate ? (
                            <span className="permission-locate-btn" onClick={() => handleLocate(row.group)}>
                              {t("agentWorkbench.locateSource")}
                            </span>
                          ) : (
                            <span className="dim">—</span>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
            <div className="permission-matrix-legend row">
              <span className="permission-matrix-legend-item">
                <span className="permission-matrix-cell has-perm permission-matrix-legend-swatch" />
                {t("agentWorkbench.permissionMatrixLegend")}
              </span>
            </div>
          </div>

          {selectedRow && detailPermissions.length > 0 && (
            <div className="card permission-matrix-detail">
              <div className="permission-matrix-detail-head row">
                <div className="permission-matrix-detail-title">
                  {selection?.kind === "cell"
                    ? t("agentWorkbench.permissionMatrixDetailCell", {
                        name: layer.permissionSourceLabel(selectedRow.group.sourceLabel),
                        category: layer.permissionCategory(selection.category),
                      })
                    : t("agentWorkbench.permissionMatrixDetailAll", {
                        name: layer.permissionSourceLabel(selectedRow.group.sourceLabel),
                      })}
                </div>
                <span className="spacer" />
                {resolvePermissionLocate(selectedRow.group, assets) && (
                  <span
                    className="permission-locate-btn"
                    onClick={() => handleLocate(selectedRow.group)}
                  >
                    {t("agentWorkbench.locateSource")}
                  </span>
                )}
              </div>
              <PermissionRowList permissions={detailPermissions} layer={layer} />
            </div>
          )}
        </>
      )}
    </div>
  );
}

function PermissionRowList({
  permissions,
  layer,
}: {
  permissions: PermissionEntry[];
  layer: ReturnType<typeof useApp>["layer"];
}) {
  return (
    <>
      {permissions.map((p) => (
        <div key={p.id} className="row perm-row permission-detail-row asset-perm-row">
          <span className="asset-perm-icon">{permIcon(p.category)}</span>
          <div className="asset-perm-body">
            <div className="asset-perm-name">{layer.permissionName(p.name)}</div>
            <div className="asset-perm-cat dim">{layer.permissionCategory(p.category)}</div>
          </div>
        </div>
      ))}
    </>
  );
}

function skillScopeLabel(scope: string | null | undefined, t: TFn): string {
  if (scope === "global") return t("agentWorkbench.skillScopeGlobal");
  if (scope === "user") return t("agentWorkbench.skillScopeUser");
  return "—";
}

function permissionSectionTitle(key: PermissionSectionKey, t: TFn): string {
  const map: Record<PermissionSectionKey, string> = {
    agent_default: t("data.permissionSource.agentDefault"),
    mcp: t("agentWorkbench.assetMcp"),
    skill: t("agentWorkbench.assetSkills"),
    hook: t("agentWorkbench.assetHooks"),
    knowledge: t("agentWorkbench.assetKnowledge"),
    channel: t("agentWorkbench.assetChannel"),
  };
  return map[key];
}

function AssetManagementView({
  agentId,
  assets,
  subTab,
  onSubTabChange,
  highlightAssetId,
  onGoThreat,
}: {
  agentId: string;
  assets: Asset[];
  subTab: (typeof ASSET_SUB_TABS)[number];
  onSubTabChange: (t: (typeof ASSET_SUB_TABS)[number]) => void;
  highlightAssetId?: string;
  onGoThreat: (findingId?: string) => void;
}) {
  const { t } = useApp();
  const filtered = assets.filter((a) => a.type === ASSET_TAB_TYPE[subTab]);
  return (
    <div>
      <div className="sub-tabs-pill">
        {ASSET_SUB_TABS.map((tabKey) => (
          <div
            key={tabKey}
            className={`sub-tab-pill ${subTab === tabKey ? "active" : ""}`}
            onClick={() => onSubTabChange(tabKey)}
          >
            {assetSubTabLabel(tabKey, t)}
          </div>
        ))}
      </div>
      <AssetTab
        agentId={agentId}
        assets={filtered}
        typeLabel={subTab}
        highlightAssetId={highlightAssetId}
        onGoThreat={onGoThreat}
      />
    </div>
  );
}

function MetaCell({
  label,
  value,
  mono,
  highlight,
}: {
  label: string;
  value: string;
  mono?: boolean;
  highlight?: boolean;
}) {
  return (
    <div className="overview-meta-cell">
      <div className="dim" style={{ fontSize: 12 }}>
        {label}
      </div>
      <div
        className={mono ? "mono" : undefined}
        style={{
          fontSize: 15,
          fontWeight: 700,
          marginTop: 4,
          color: highlight ? "var(--med)" : undefined,
        }}
      >
        {value}
      </div>
    </div>
  );
}

function RuntimePanel({ agentId }: { agentId: string }) {
  const { fetchAgentRuntime, t } = useApp();
  const [runtime, setRuntime] = useState<AgentRuntime | null>(null);
  const [loading, setLoading] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const data = await fetchAgentRuntime(agentId);
      if (data) setRuntime(data);
    } finally {
      setLoading(false);
    }
  }, [agentId, fetchAgentRuntime]);

  useEffect(() => {
    load();
  }, [load]);

  const r = runtime;

  return (
    <div className="card results-insight-card runtime-panel">
      <div className="results-insight-head row runtime-panel-head">
        <span>{t("agentWorkbench.runtimeTitle")}</span>
        <span className="spacer" />
        <button
          type="button"
          className="btn btn-ghost runtime-refresh-btn"
          disabled={loading}
          title={t("agentWorkbench.refreshRuntimeTitle")}
          onClick={load}
        >
          <span className="row" style={{ gap: 5, fontSize: 12.5 }}>
            <IconRefresh size={14} className={loading ? "spin" : undefined} />
            {t("common.action.refresh")}
          </span>
        </button>
      </div>
      <div className="runtime-metrics">
        <RuntimeMetric
          label="CPU"
          value={r ? `${r.cpu_percent}% / 100%` : "—"}
          percent={r?.cpu_percent ?? 0}
          max={100}
          history={r?.cpu_history ?? []}
          color="var(--purple-2)"
          t={t}
        />
        <RuntimeMetric
          label={t("agentWorkbench.memory")}
          value={r ? formatMemoryTotal(r.memory_mb, r.memory_percent) : "—"}
          percent={r?.memory_percent ?? 0}
          max={100}
          history={r?.memory_history ?? []}
          color="#60a5fa"
          t={t}
        />
        <RuntimeMetric
          label={t("agentWorkbench.disk")}
          value={r ? formatDiskTotal(r.disk_mb, r.disk_percent) : "—"}
          percent={r?.disk_percent ?? 0}
          max={100}
          history={r?.disk_history ?? []}
          color="#34d399"
          t={t}
        />
      </div>
    </div>
  );
}

function RuntimeMetric({
  label,
  value,
  percent,
  max,
  history,
  color,
  t,
}: {
  label: string;
  value: string;
  percent: number;
  max: number;
  history: number[];
  color: string;
  t: TFn;
}) {
  const barPct = Math.min(100, Math.max(0, (percent / max) * 100));
  return (
    <div className="runtime-metric">
      <div className="row" style={{ justifyContent: "space-between", marginBottom: 8 }}>
        <span className="dim" style={{ fontSize: 12.5 }}>
          {label}
        </span>
        <span style={{ fontSize: 13, fontWeight: 600 }}>{value}</span>
      </div>
      <div className="runtime-metric-body">
        <div className="runtime-bar-track">
          <div
            className="runtime-bar-fill"
            style={{ width: `${barPct}%`, background: color }}
          />
        </div>
        {history.length > 1 ? (
          <div className="runtime-sparkline-wrap" title={t("agentWorkbench.trendTitle")}>
            <span className="runtime-sparkline-label">{t("agentWorkbench.trendLabel")}</span>
            <Sparkline data={history} color={color} max={max} />
          </div>
        ) : (
          <div className="runtime-sparkline-empty">{t("agentWorkbench.trendEmpty")}</div>
        )}
      </div>
    </div>
  );
}

function Sparkline({
  data,
  color,
  max,
}: {
  data: number[];
  color: string;
  max: number;
}) {
  const w = 160;
  const h = 36;
  const pad = 2;
  const min = Math.min(...data);
  const peak = Math.max(...data);
  const span = Math.max(peak - min, max * 0.08, 1);
  const pts = data.map((v, i) => {
    const x = pad + (i / Math.max(data.length - 1, 1)) * (w - pad * 2);
    const norm = (Math.min(v, max) - min) / span;
    const y = h - pad - norm * (h - pad * 2);
    return `${x},${y}`;
  });
  const area = `${pad},${h - pad} ${pts.join(" ")} ${w - pad},${h - pad}`;
  const last = pts[pts.length - 1]?.split(",") ?? [];
  return (
    <svg className="runtime-sparkline" viewBox={`0 0 ${w} ${h}`} preserveAspectRatio="none" aria-hidden>
      <rect x={0} y={0} width={w} height={h} rx={4} className="runtime-sparkline-bg" />
      <polygon points={area} className="runtime-sparkline-area" style={{ fill: color }} />
      <polyline
        fill="none"
        stroke={color}
        strokeWidth="2"
        strokeLinejoin="round"
        strokeLinecap="round"
        points={pts.join(" ")}
      />
      {last.length === 2 && (
        <circle cx={last[0]} cy={last[1]} r="2.5" fill={color} stroke="rgba(255,255,255,0.35)" strokeWidth="0.75" />
      )}
    </svg>
  );
}

function formatMemoryTotal(mb: number, percent: number): string {
  if (mb <= 0) return "—";
  if (percent > 0) {
    const totalMb = Math.round(mb / (percent / 100));
    const totalGb = totalMb >= 1024 ? `${(totalMb / 1024).toFixed(0)} GB` : `${totalMb} MB`;
    return `${mb} MB / ${totalGb}`;
  }
  return `${mb} MB`;
}

function formatDiskTotal(mb: number, percent: number): string {
  if (mb <= 0) return "—";
  if (percent > 0) {
    const totalMb = Math.round(mb / (percent / 100));
    const totalGb = totalMb >= 1024 ? `${(totalMb / 1024).toFixed(1)} GB` : `${totalMb} MB`;
    return `${mb} MB / ${totalGb}`;
  }
  return `${mb} MB`;
}

/* ---------- 资产 Tab（列表 + 详情 + 管理） ---------- */
function permIcon(cat: string) {
  if (cat === "文件") return <IconFile size={17} />;
  if (cat === "Shell") return <IconTerminal size={17} />;
  if (cat === "网络") return <IconGlobe size={17} />;
  if (cat === "知识库") return <IconBook size={17} />;
  return <IconDatabase size={17} />;
}

function statusInfo(a: Asset, t: TFn): { label: string; color: string } {
  if (a.status === "updatable") return { label: t("common.status.updatable"), color: "var(--med)" };
  if (a.status === "disabled") return { label: t("common.status.disabled"), color: "var(--high)" };
  return { label: t("common.status.enabled"), color: "var(--safe)" };
}

function AssetTab({
  agentId,
  assets,
  typeLabel,
  highlightAssetId,
  onGoThreat,
}: {
  agentId: string;
  assets: Asset[];
  typeLabel: string;
  highlightAssetId?: string;
  onGoThreat: (findingId?: string) => void;
}) {
  const { updateAsset, disableAsset, enableAsset, uninstallAsset, settings, snapshot, t, layer } =
    useApp();
  const [detailAsset, setDetailAsset] = useState<Asset | null>(null);
  const [depModal, setDepModal] = useState<Asset | null>(null);
  const [confirm, setConfirm] = useState<{ kind: string; id: string } | null>(null);

  useEffect(() => {
    setDetailAsset(null);
    setDepModal(null);
  }, [typeLabel, assets.length]);

  useEffect(() => {
    if (!highlightAssetId) return;
    const hit = assets.find((a) => a.id === highlightAssetId);
    if (hit) setDetailAsset(hit);
  }, [highlightAssetId, assets]);

  const isDep = typeLabel === "依赖";
  const isChannel = typeLabel === "通道";
  const isKnowledge = typeLabel === "知识库";
  const isMcpOrSkill = typeLabel === "MCP" || typeLabel === "Skills" || typeLabel === "Hooks";
  const isSkills = typeLabel === "Skills";

  const listedAssets = useMemo(() => {
    if (!isSkills) return assets;
    const order: Record<string, number> = { user: 0, global: 1 };
    return [...assets].sort((a, b) => {
      const oa = order[a.skill_scope ?? ""] ?? 2;
      const ob = order[b.skill_scope ?? ""] ?? 2;
      return oa - ob || a.name.localeCompare(b.name);
    });
  }, [assets, isSkills]);

  if (assets.length === 0) {
    return (
      <div className="card" style={{ padding: 30 }}>
        <span className="muted">{t("agentWorkbench.assetsEmpty", { type: assetSubTabLabel(typeLabel as (typeof ASSET_SUB_TABS)[number], t) })}</span>
      </div>
    );
  }

  const openDepModal = (asset: Asset) => {
    setDepModal(asset);
  };

  const doOp = (kind: string, id: string, needConfirm: boolean) => {
    if (needConfirm) setConfirm({ kind, id });
    else runOp(kind, id);
  };
  const runOp = (kind: string, id: string) => {
    if (kind === "update") updateAsset(id);
    else if (kind === "disable") disableAsset(id);
    else if (kind === "enable") enableAsset(id);
    else if (kind === "uninstall") uninstallAsset(id);
  };

  return (
    <div className="asset-tab">
      <div className="card asset-tab-list">
        <table className="data-table">
          <thead>
            <tr>
              <th>{t("common.table.name")}</th>
              <th style={{ width: 110 }}>{t("common.table.status")}</th>
              {!isKnowledge && (
                <th style={{ width: 100 }}>
                  {isChannel ? t("agentWorkbench.colAccess") : t("common.table.version")}
                </th>
              )}
              {!isDep && !isChannel && !isMcpOrSkill && !isKnowledge && (
                <th style={{ width: 72 }}>{t("agentWorkbench.colUpdate")}</th>
              )}
              {!isDep && !isKnowledge && (
                <th style={{ width: 72 }}>
                  {isMcpOrSkill ? t("agentWorkbench.colActions") : t("agentWorkbench.colDisable")}
                </th>
              )}
              {!isDep && !isChannel && !isMcpOrSkill && !isKnowledge && (
                <th style={{ width: 72 }}>{t("agentWorkbench.colUninstall")}</th>
              )}
              {isDep && <th style={{ width: 100 }}>{t("agentWorkbench.colVuln")}</th>}
              {isSkills && <th style={{ width: 72 }}>{t("agentWorkbench.colSkillScope")}</th>}
              {isSkills && <th style={{ width: 88 }}>{t("agentWorkbench.colThreats")}</th>}
              {!isDep && <th style={{ width: 28 }} />}
            </tr>
          </thead>
          <tbody>
            {listedAssets.map((a) => {
              const st = statusInfo(a, t);
              const active =
                highlightAssetId === a.id ||
                (isDep ? depModal?.id === a.id : detailAsset?.id === a.id);
              const cveRow = snapshot
                ? cveItemsForDep(snapshot, agentId, a.name, a.version).length
                : 0;
              const skillThreats =
                isSkills && snapshot ? exposureFindingsForSkill(snapshot, agentId, a) : [];
              const skillThreatActive = skillThreats.filter(
                (f) => !snapshot || !isThreatIgnored(snapshot, f)
              );
              return (
                <tr
                  key={a.id}
                  className={`asset-tab-row${active ? " active" : ""}`}
                  onClick={() => (isDep ? openDepModal(a) : setDetailAsset(a))}
                >
                  <td>
                    <div style={{ fontWeight: 600, fontSize: 14 }}>{a.name}</div>
                    <div className="dim" style={{ fontSize: 11.5, marginTop: 2 }}>
                      {(() => {
                        const purposeText = a.purpose
                          ? layer.assetPurpose(a.purpose)
                          : assetSubTabLabel(typeLabel as (typeof ASSET_SUB_TABS)[number], t);
                        return purposeText.length > 48 ? `${purposeText.slice(0, 48)}…` : purposeText;
                      })()}
                    </div>
                  </td>
                  <td>
                    <span className="row" style={{ gap: 6, color: st.color, fontSize: 13 }}>
                      <span style={{ width: 7, height: 7, borderRadius: 4, background: st.color }} />
                      {st.label}
                    </span>
                  </td>
                  {!isKnowledge && <td className="muted mono">{a.version || "—"}</td>}
                  {!isDep && !isChannel && !isMcpOrSkill && !isKnowledge && (
                    <td onClick={(e) => e.stopPropagation()}>
                      {a.can_update ? (
                        <span
                          className="update-pill"
                          onClick={() => doOp("update", a.id, settings.confirmUpdate)}
                        >
                          {t("agentWorkbench.hasUpdate")}
                        </span>
                      ) : (
                        <span className="dim">—</span>
                      )}
                    </td>
                  )}
                  {!isDep && !isKnowledge && (
                    <td onClick={(e) => e.stopPropagation()}>
                      {a.status === "disabled" ? (
                        <span
                          className="act-link act-enable"
                          onClick={() => doOp("enable", a.id, settings.confirmDisable)}
                        >
                          {t("common.action.enable")}
                        </span>
                      ) : a.can_disable ? (
                        <span
                          className="act-link act-disable"
                          onClick={() => doOp("disable", a.id, settings.confirmDisable)}
                        >
                          {t("common.action.disable")}
                        </span>
                      ) : (
                        <span className="dim">—</span>
                      )}
                    </td>
                  )}
                  {isSkills && (
                    <td>
                      <span
                        className={`tag${a.skill_scope === "global" ? " tag-muted" : ""}`}
                        style={
                          a.skill_scope === "user"
                            ? { background: "rgba(139,92,246,0.12)", color: "var(--purple-2)" }
                            : undefined
                        }
                      >
                        {skillScopeLabel(a.skill_scope, t)}
                      </span>
                    </td>
                  )}
                  {!isDep && !isChannel && !isMcpOrSkill && !isKnowledge && (
                    <td onClick={(e) => e.stopPropagation()}>
                      {a.can_uninstall ? (
                        <span
                          className="act-link act-uninstall"
                          onClick={() => doOp("uninstall", a.id, settings.confirmUninstall)}
                        >
                          {t("agentWorkbench.colUninstall")}
                        </span>
                      ) : (
                        <span className="dim" title={t("agentWorkbench.manualOnly")}>
                          —
                        </span>
                      )}
                    </td>
                  )}
                  {isDep && (
                    <td onClick={(e) => e.stopPropagation()}>
                      {cveRow > 0 ? (
                        <span className="act-link act-cve" onClick={() => openDepModal(a)}>
                          {cveRow} CVE
                        </span>
                      ) : (
                        <span className="dim">{t("common.none")}</span>
                      )}
                    </td>
                  )}
                  {isSkills && (
                    <td onClick={(e) => e.stopPropagation()}>
                      {skillThreatActive.length > 0 ? (
                        <span
                          className="act-link act-threat"
                          onClick={() =>
                            onGoThreat(exposureFindingKey(skillThreatActive[0]))
                          }
                        >
                          {t("agentWorkbench.skillThreatCount", {
                            count: skillThreatActive.length,
                          })}
                        </span>
                      ) : (
                        <span className="dim">{t("common.none")}</span>
                      )}
                    </td>
                  )}
                  {!isDep && (
                    <td className="dim">
                      <IconChevron
                        size={14}
                        style={{
                          transform: active ? "rotate(90deg)" : undefined,
                          transition: "transform 0.15s",
                        }}
                      />
                    </td>
                  )}
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {detailAsset && (
        <div className="modal-mask" onClick={() => setDetailAsset(null)}>
          <div
            className="modal modal-lg cve-detail-modal asset-detail-modal"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="modal-head">
              <div className="row" style={{ gap: 10, minWidth: 0 }}>
                <div className="modal-title" style={{ minWidth: 0 }}>
                  {detailAsset.name}
                  <span className="dim" style={{ fontSize: 13, fontWeight: 500, marginLeft: 8 }}>
                    {detailAsset.version || "—"}
                  </span>
                </div>
                <span className="tag">{assetSubTabLabel(typeLabel as (typeof ASSET_SUB_TABS)[number], t)}</span>
              </div>
              <button type="button" className="modal-close" onClick={() => setDetailAsset(null)}>
                ×
              </button>
            </div>
            <AssetDetailPanel asset={detailAsset} typeLabel={typeLabel} t={t} />
          </div>
        </div>
      )}

      {depModal && snapshot && (
        <DepDetailModal
          asset={depModal}
          snapshot={snapshot}
          agentId={agentId}
          onClose={() => setDepModal(null)}
        />
      )}

      {confirm && (
        <ConfirmModal
          title={
            confirm.kind === "uninstall"
              ? t("agentWorkbench.confirmUninstallTitle")
              : confirm.kind === "update"
                ? t("agentWorkbench.confirmUpdateTitle")
                : confirm.kind === "enable"
                  ? t("agentWorkbench.confirmEnableTitle")
                  : t("agentWorkbench.confirmDisableTitle")
          }
          message={
            confirm.kind === "uninstall"
              ? t("agentWorkbench.confirmUninstallMsg")
              : confirm.kind === "update"
                ? t("agentWorkbench.confirmUpdateMsg")
                : confirm.kind === "enable"
                  ? t("agentWorkbench.confirmEnableMsg")
                  : t("agentWorkbench.confirmDisableMsg")
          }
          confirmLabel={confirm.kind === "uninstall" ? t("agentWorkbench.confirmUninstallAction") : t("common.action.confirm")}
          danger={confirm.kind === "uninstall"}
          onConfirm={() => {
            runOp(confirm.kind, confirm.id);
            setConfirm(null);
          }}
          onCancel={() => setConfirm(null)}
        />
      )}
    </div>
  );
}

function cveItemsForDep(
  snapshot: ScanSnapshot,
  agentId: string,
  name: string,
  version: string | null
): CVEItem[] {
  const seen = new Set<string>();
  const items: CVEItem[] = [];
  for (const f of snapshot.cve_findings) {
    if (f.component !== name) continue;
    if (!f.agent_ids.includes(agentId)) continue;
    if (version && f.current_version !== version) continue;
    for (const c of f.cves) {
      if (seen.has(c.cve_id)) continue;
      seen.add(c.cve_id);
      items.push(c);
    }
  }
  return items.sort((a, b) => b.cvss - a.cvss);
}

function depUpgradeAdvice(
  snapshot: ScanSnapshot,
  agentId: string,
  name: string,
  version: string | null
): string | null {
  for (const f of snapshot.cve_findings) {
    if (f.component !== name) continue;
    if (!f.agent_ids.includes(agentId)) continue;
    if (version && f.current_version !== version) continue;
    if (f.upgrade_advice) return f.upgrade_advice;
  }
  return null;
}

function DepDetailModal({
  asset,
  snapshot,
  agentId,
  onClose,
}: {
  asset: Asset;
  snapshot: ScanSnapshot;
  agentId: string;
  onClose: () => void;
}) {
  const { t, layer } = useApp();
  const { label: sevLabel } = useSeverityLabels();
  const [selCve, setSelCve] = useState<string | null>(null);
  const st = statusInfo(asset, t);
  const cves = cveItemsForDep(snapshot, agentId, asset.name, asset.version);
  const advice = depUpgradeAdvice(snapshot, agentId, asset.name, asset.version);
  const selected = selCve ? cves.find((c) => c.cve_id === selCve) : undefined;

  const toggleCve = (cveId: string) => {
    setSelCve((prev) => (prev === cveId ? null : cveId));
  };

  return (
    <div className="modal-mask" onClick={onClose}>
      <div
        className="modal cve-detail-modal dep-detail-modal"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="modal-head">
          <div className="row" style={{ gap: 10, minWidth: 0 }}>
            <IconDatabase size={20} style={{ color: "var(--purple-2)", flexShrink: 0 }} />
            <div className="modal-title" style={{ minWidth: 0 }}>
              {asset.name}
              <span className="dim" style={{ fontSize: 13, fontWeight: 500, marginLeft: 8 }}>
                {asset.version || "—"}
              </span>
            </div>
            <span className="tag">{t("agentWorkbench.tagDependency")}</span>
          </div>
          <button type="button" className="modal-close" onClick={onClose}>
            ×
          </button>
        </div>

        <div className="dep-modal-section">
          <div className="row dep-modal-meta" style={{ gap: 28, flexWrap: "wrap" }}>
            <DetailMeta label={t("common.table.status")} value={st.label} color={st.color} />
            <DetailMeta label={t("common.meta.source")} value={asset.source || "—"} />
            {asset.ecosystem && <DetailMeta label={t("common.meta.ecosystem")} value={asset.ecosystem} />}
            {asset.manager && <DetailMeta label={t("common.meta.packageManager")} value={asset.manager} />}
            <DetailMeta label={t("vulnList.detailCveCount")} value={String(cves.length)} />
          </div>
          {asset.purpose && (
            <div className="muted" style={{ marginTop: 12, lineHeight: 1.7, fontSize: 13.5 }}>
              {layer.assetPurpose(asset.purpose)}
            </div>
          )}
          {asset.install_path && (
            <div className="mono dim" style={{ marginTop: 10, fontSize: 12, wordBreak: "break-all" }}>
              {asset.install_path}
            </div>
          )}
        </div>

        {cves.length === 0 ? (
          <div className="dep-modal-empty">{t("agentWorkbench.noCve")}</div>
        ) : (
          <>
            <div className="cve-modal-body cve-modal-body-stack">
              <div className="cve-modal-list">
                <div className="cve-modal-list-head">{t("vulnList.cveList")}</div>
                <div className="cve-modal-cve-cols dim">
                  <span>{t("vulnList.colCveId")}</span>
                  <span>{t("common.table.riskLevel")}</span>
                  <span>{t("vulnList.cvss")}</span>
                  <span>{t("vulnList.colSummary")}</span>
                  <span />
                </div>
                <div className="cve-modal-cve-rows">
                  {cves.map((v) => (
                    <div
                      key={v.cve_id + (v.advisory_id || "")}
                      className={`cve-modal-cve-row${selCve === v.cve_id ? " active" : ""}`}
                      onClick={() => toggleCve(v.cve_id)}
                    >
                      <span className="cve-modal-cve-id">
                        <span className="mono" style={{ fontWeight: 600, fontSize: 13 }}>
                          {v.cve_id}
                        </span>
                        {!v.cve_id.startsWith("CVE-") && (
                          <span className="tag tag-muted cve-advisory-tag">{t("vulnList.advisoryLabel")}</span>
                        )}
                        {v.advisory_id && v.advisory_id !== v.cve_id && (
                          <span className="dim mono cve-advisory-sub">{v.advisory_id}</span>
                        )}
                      </span>
                      <SeverityPill sev={v.severity} />
                      <span style={{ fontWeight: 700, fontSize: 13 }}>{v.cvss > 0 ? v.cvss.toFixed(1) : "—"}</span>
                      <span
                        className="muted cve-modal-cve-summary"
                        title={layer.cveSummary(v.summary)}
                      >
                        {layer.cveSummary(v.summary) || "—"}
                      </span>
                      <IconChevron
                        size={14}
                        className="dim"
                        style={{
                          transform: selCve === v.cve_id ? "rotate(90deg)" : undefined,
                          transition: "transform 0.15s",
                        }}
                      />
                    </div>
                  ))}
                </div>
              </div>

              {selected && (
                <div className="cve-modal-detail cve-modal-detail-stack">
                  <div className="cve-modal-list-head">{t("vulnList.vulnDetail")}</div>
                  <div className="cve-modal-detail-body">
                    <div className="row" style={{ gap: 10, marginBottom: 12, flexWrap: "wrap" }}>
                      <span className="mono" style={{ fontSize: 16, fontWeight: 700 }}>
                        {selected.cve_id}
                      </span>
                      <SeverityPill sev={selected.severity} />
                    </div>
                    <div className="row" style={{ gap: 24, marginBottom: 16, flexWrap: "wrap" }}>
                      <DetailMeta label={t("vulnList.cvss")} value={selected.cvss > 0 ? selected.cvss.toFixed(1) : "—"} />
                      <DetailMeta
                        label={t("vulnList.threatLevel")}
                        value={sevLabel(selected.severity)}
                      />
                      {selected.advisory_id && selected.advisory_id !== selected.cve_id && (
                        <DetailMeta label={t("vulnList.advisoryLabel")} value={selected.advisory_id} />
                      )}
                    </div>
                    <div className="dim" style={{ fontSize: 12, marginBottom: 6 }}>
                      {t("vulnList.summary")}
                    </div>
                    <div className="muted cve-detail-summary" style={{ lineHeight: 1.75, fontSize: 13.5 }}>
                      {selected.summary
                        ? layer.cveSummary(selected.summary)
                        : t("common.empty.noDescription")}
                    </div>
                  </div>
                </div>
              )}
            </div>

            {advice && (
              <div className="cve-modal-advice">
                <div className="dim" style={{ fontSize: 12, marginBottom: 6 }}>
                  {t("agentWorkbench.fixAdvice")}
                </div>
                <div className="muted" style={{ lineHeight: 1.7, fontSize: 13.5 }}>
                  {layer.upgradeAdvice(advice, undefined)}
                </div>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}

function AssetDetailPanel({
  asset,
  typeLabel,
  t,
}: {
  asset: Asset;
  typeLabel: string;
  t: TFn;
}) {
  const { layer } = useApp();
  const st = statusInfo(asset, t);
  const typeIcon =
    typeLabel === "MCP" ? (
      <IconCube size={20} />
    ) : typeLabel === "Skills" ? (
      <IconBolt size={20} />
    ) : typeLabel === "知识库" ? (
      <IconBook size={20} />
    ) : typeLabel === "通道" ? (
      <IconGlobe size={20} />
    ) : (
      <IconDatabase size={20} />
    );
  const isChannel = typeLabel === "通道";

  return (
    <>
      <div className="row" style={{ gap: 10 }}>
        <span style={{ color: "var(--purple-2)" }}>{typeIcon}</span>
        <span style={{ fontSize: 18, fontWeight: 700, minWidth: 0 }}>{asset.name}</span>
        <span className="tag">{assetSubTabLabel(typeLabel as (typeof ASSET_SUB_TABS)[number], t)}</span>
      </div>

      <div className="row" style={{ gap: 20, marginTop: 16, flexWrap: "wrap" }}>
        <DetailMeta label={t("common.table.status")} value={st.label} color={st.color} />
        {typeLabel === "Skills" && asset.skill_scope && (
          <DetailMeta label={t("agentWorkbench.colSkillScope")} value={skillScopeLabel(asset.skill_scope, t)} />
        )}
        <DetailMeta
          label={isChannel ? t("agentWorkbench.colAccess") : t("common.table.version")}
          value={asset.version || "—"}
        />
        <DetailMeta label={t("common.meta.source")} value={asset.source || "—"} />
        {asset.ecosystem && <DetailMeta label={t("common.meta.ecosystem")} value={asset.ecosystem} />}
        {isChannel && asset.config_key && (
          <DetailMeta label={t("agentWorkbench.configKey")} value={asset.config_key} />
        )}
      </div>

      {(typeLabel === "MCP" || typeLabel === "Skills" || typeLabel === "知识库") && (
        <AssetPermissionsSection permissions={asset.permissions} t={t} />
      )}

      {isChannel && asset.permissions.length > 0 && (
        <AssetPermissionsSection permissions={asset.permissions} t={t} />
      )}

      <div className="detail-block" style={{ marginTop: 18 }}>
        <div className="dim" style={{ fontSize: 12.5, marginBottom: 6 }}>
          {t("agentWorkbench.description")}
        </div>
        <div className="muted" style={{ lineHeight: 1.7 }}>
          {layer.assetPurpose(asset.purpose) || "—"}
        </div>
      </div>

      {isChannel && asset.path && (
        <div style={{ marginTop: 14 }}>
          <div className="dim" style={{ fontSize: 12.5, marginBottom: 6 }}>
            {t("agentWorkbench.configPath")}
          </div>
          <div className="muted mono" style={{ fontSize: 12, wordBreak: "break-all" }}>
            {asset.path}
          </div>
        </div>
      )}

      {asset.install_path && (
        <div style={{ marginTop: 14 }}>
          <div className="dim" style={{ fontSize: 12.5, marginBottom: 6 }}>
            {t("agentWorkbench.installPath")}
          </div>
          <div className="muted mono" style={{ fontSize: 12, wordBreak: "break-all" }}>
            {asset.install_path}
          </div>
        </div>
      )}
    </>
  );
}

function AssetPermissionsSection({
  permissions,
  t,
}: {
  permissions: PermissionEntry[];
  t: TFn;
}) {
  const { layer } = useApp();
  return (
    <div className="asset-detail-perms">
      <div className="asset-detail-perms-head">{t("agentWorkbench.permissions")}</div>
      {permissions.length === 0 ? (
        <div className="asset-detail-perms-empty muted">{t("agentWorkbench.noPermissions")}</div>
      ) : (
        permissions.map((p) => (
          <div key={p.id} className="row asset-perm-row">
            <span className="asset-perm-icon">{permIcon(p.category)}</span>
            <div className="asset-perm-body">
              <div className="asset-perm-name">{layer.permissionName(p.name)}</div>
              <div className="asset-perm-cat dim">{layer.permissionCategory(p.category)}</div>
            </div>
            <SeverityPill sev={p.severity} />
          </div>
        ))
      )}
    </div>
  );
}

function DetailMeta({
  label,
  value,
  color,
}: {
  label: string;
  value: string;
  color?: string;
}) {
  return (
    <div>
      <div className="dim" style={{ fontSize: 12 }}>
        {label}
      </div>
      <div style={{ fontSize: 14, fontWeight: 600, marginTop: 3, color }}>{value}</div>
    </div>
  );
}
