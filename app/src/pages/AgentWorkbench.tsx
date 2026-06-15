import React, { useCallback, useEffect, useMemo, useState } from "react";
import { useApp } from "../store";
import { ThreatList } from "./ThreatList";
import { VulnList } from "./VulnList";
import {
  agentOptimizationSuggestions,
  agentSecurityScore,
  assetsByAgent,
  cveForAgent,
  exposureForAgent,
} from "../selectors";
import { Radar, RadarAxis } from "../components/Radar";
import { SeverityPill, ConfirmModal, SEV_LABEL } from "../components/common";
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
  IconRefresh,
  IconShield,
  IconSettings,
} from "../components/Icons";

const SEV_W: Record<Severity, number> = { high: 3, medium: 2, low: 1, info: 0, safe: 0 };
const RADAR_CATS = ["文件", "Shell", "网络", "工具", "知识库"];
const MAIN_TABS = ["概览", "资产管理", "威胁管理", "漏洞管理"] as const;
const ASSET_SUB_TABS = ["MCP", "Skills", "知识库", "依赖"] as const;
const ASSET_TAB_TYPE: Record<(typeof ASSET_SUB_TABS)[number], string> = {
  MCP: "mcp",
  Skills: "skill",
  知识库: "knowledge",
  依赖: "dependency",
};

function resolveInitialTab(initialTab?: string): {
  main: (typeof MAIN_TABS)[number];
  assetSub: (typeof ASSET_SUB_TABS)[number];
} {
  if (initialTab === "风险管理") initialTab = "威胁管理";
  if (
    initialTab === "资产管理" ||
    initialTab === "威胁管理" ||
    initialTab === "漏洞管理" ||
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
  const { snapshot, navigate, refreshAgentAssets } = useApp();
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

  const agent = snapshot?.agents.find((a) => a.id === agentId);
  if (!snapshot || !agent) {
    return (
      <main className="main">
        <div className="muted">未找到该 Agent。</div>
      </main>
    );
  }

  const assets = assetsByAgent(snapshot, agentId);
  const exposure = exposureForAgent(snapshot, agentId);
  const hue = agent.kind === "openclaw" ? "#60a5fa" : "#a855f7";

  const goAssets = (sub: (typeof ASSET_SUB_TABS)[number] = "MCP") => {
    setAssetSubTab(sub);
    setTab("资产管理");
  };

  return (
    <main className="main flush">
      <div className="row" style={{ gap: 8 }}>
        <span className="link" onClick={() => navigate({ name: "agent-list" })}>
          <IconArrowLeft size={18} /> 返回
        </span>
        {focusSource && tab !== "概览" && (
          <span className="dim" style={{ fontSize: 12, marginLeft: 8 }}>
            来自概览 › {focusSource}
          </span>
        )}
      </div>

      <div className="row agent-workbench-head" style={{ gap: 14, marginTop: 12 }}>
        <IconHexAgent size={42} hue={hue} />
        <span style={{ fontSize: 24, fontWeight: 800 }}>{agent.name}</span>
        <span className="ver-badge">{agent.version || "—"}</span>
        <span className="row muted" style={{ gap: 5, fontSize: 13 }}>
          <span style={{ width: 8, height: 8, borderRadius: 4, background: "var(--safe)" }} />
          {agent.enabled ? "已启用" : "已禁用"}
        </span>
        <span className="spacer" />
        <button
          type="button"
          className="btn btn-ghost agent-refresh-btn"
          disabled={refreshing}
          title="重新扫描该 Agent 资产"
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
            刷新资产
          </span>
        </button>
      </div>

      <div className="tabs">
        {MAIN_TABS.map((t) => (
          <div
            key={t}
            className={`tab ${tab === t ? "active" : ""}`}
            onClick={() => setTab(t)}
          >
            {t}
          </div>
        ))}
      </div>

      {tab === "概览" && (
        <Overview
          agent={agent}
          agentId={agentId}
          snapshot={snapshot}
          assets={assets}
          exposure={exposure}
          onGoAssets={() => goAssets("MCP")}
          onGoThreat={() => {
            setThreatFindingId(undefined);
            setTab("威胁管理");
          }}
          onGoVuln={() => setTab("漏洞管理")}
          onSelectFinding={(findingId) => {
            setThreatFindingId(findingId);
            setTab("威胁管理");
          }}
          onCheckUpdate={async () => {
            setRefreshing(true);
            try {
              await refreshAgentAssets(agentId);
            } finally {
              setRefreshing(false);
            }
          }}
          updating={refreshing}
        />
      )}
      {tab === "资产管理" && (
        <AssetManagementView
          agentId={agentId}
          assets={assets}
          subTab={assetSubTab}
          onSubTabChange={setAssetSubTab}
        />
      )}
      {tab === "威胁管理" && (
        <ThreatList agentId={agentId} findingId={threatFindingId} embedded />
      )}
      {tab === "漏洞管理" && <VulnList agentId={agentId} embedded />}
    </main>
  );
}

/* ---------- 概览 ---------- */
function Overview({
  agent,
  agentId,
  snapshot,
  assets,
  exposure,
  onGoAssets,
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
  exposure: ExposureFinding[];
  onGoAssets: () => void;
  onGoThreat: () => void;
  onGoVuln: () => void;
  onSelectFinding: (findingId: string) => void;
  onCheckUpdate: () => void;
  updating: boolean;
}) {
  const perms: PermissionEntry[] = [
    ...agent.permissions,
    ...assets.flatMap((a) => a.permissions),
  ];
  const radarAxes: RadarAxis[] = RADAR_CATS.map((cat) => {
    const inCat = perms.filter((p) => p.category === cat);
    const max = inCat.reduce((m, p) => Math.max(m, SEV_W[p.severity]), 0);
    return { label: cat, score: max / 3 };
  });

  const mcp = assets.filter((a) => a.type === "mcp").length;
  const skills = assets.filter((a) => a.type === "skill").length;
  const knowledge = assets.filter((a) => a.type === "knowledge").length;

  const vulnComponents = cveForAgent(snapshot, agentId).length;

  const ports = agent.listen_ports?.length ? agent.listen_ports.join(", ") : "—";
  const latestVer = agent.latest_version || agent.version || "—";
  const versionUpToDate =
    !agent.latest_version || agent.latest_version === agent.version;
  const score = agentSecurityScore(snapshot, agentId);
  const suggestions = agentOptimizationSuggestions(snapshot, agentId);

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
              {versionUpToDate ? "已是最新版本" : "检查并更新"}
            </span>
          </button>
          <MetaCell label="当前版本" value={agent.version || "—"} />
          <MetaCell label="最新版本" value={latestVer} highlight={!versionUpToDate} />
          <MetaCell label="监听端口" value={ports} mono />
        </div>
      </div>

      <div className="overview-row-score">
        <SecurityScoreCard score={score} onViewDetail={onGoThreat} />
        <div className="card overview-risk-line-card">
          <div style={{ fontWeight: 700, marginBottom: 12 }}>安全摘要</div>
          <div className="overview-risk-line">
            <button type="button" className="overview-risk-chip" onClick={onGoThreat}>
              <span className="overview-risk-chip-label">威胁</span>
              <span className="overview-risk-chip-value">{exposure.length}</span>
              <span className="overview-risk-chip-go">查看 →</span>
            </button>
            <button type="button" className="overview-risk-chip" onClick={onGoVuln}>
              <span className="overview-risk-chip-label">漏洞</span>
              <span className="overview-risk-chip-value">{vulnComponents}</span>
              <span className="overview-risk-chip-go">查看 →</span>
            </button>
          </div>
        </div>
      </div>

      <div className="overview-row-mid">
        <div className="card overview-radar-card">
          <div style={{ fontWeight: 700, marginBottom: 4 }}>权限分布</div>
          <div className="overview-radar-body">
            <Radar axes={radarAxes} size={292} />
          </div>
        </div>
        <div className="card overview-asset-card">
          <div style={{ fontWeight: 700 }}>资产统计</div>
          <div className="overview-asset-stats">
            <div className="row" style={{ gap: 12, alignItems: "stretch", width: "100%" }}>
              <StatBox icon={<IconCube size={20} />} label="MCP" value={mcp} />
              <StatBox icon={<IconBolt size={20} />} label="Skills" value={skills} />
              <StatBox icon={<IconBook size={20} />} label="知识库" value={knowledge} />
            </div>
          </div>
          <div className="overview-asset-foot">
            <button type="button" className="btn btn-ghost overview-goto-assets" onClick={onGoAssets}>
              进入资产管理 →
            </button>
          </div>
        </div>
      </div>

      <div className="overview-row-bottom">
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

function SecurityScoreCard({
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
  const ringColor = score >= 80 ? "var(--purple-2)" : score >= 60 ? "#34d399" : score >= 40 ? "var(--med)" : "var(--high)";
  const pct = score / 100;
  const r = 54;
  const c = 2 * Math.PI * r;
  const desc =
    score >= 80
      ? "未发现高风险行为，请继续保持良好使用习惯。"
      : score >= 60
        ? "存在少量中低风险项，建议查看威胁管理详情。"
        : "发现需关注的风险项，请尽快处理。";

  return (
    <div className="card security-score-card">
      <div style={{ fontWeight: 700, marginBottom: 14 }}>整体安全评分</div>
      <div className="security-score-body">
        <div className="security-score-gauge">
          <svg viewBox="0 0 120 120">
            <circle cx="60" cy="60" r={r} fill="none" stroke="rgba(255,255,255,0.08)" strokeWidth="10" />
            <circle
              cx="60"
              cy="60"
              r={r}
              fill="none"
              stroke={ringColor}
              strokeWidth="10"
              strokeLinecap="round"
              strokeDasharray={`${c * pct} ${c}`}
            />
          </svg>
          <div className="security-score-value">
            <div className="security-score-num">{score}</div>
            <div className="security-score-denom">/ 100</div>
          </div>
        </div>
        <div className="security-score-info">
          <div className="security-score-label" style={{ color: labelColor }}>
            <IconShield size={16} />
            {label}
          </div>
          <div className="security-score-desc">{desc}</div>
          <button type="button" className="btn btn-primary security-score-detail-btn" onClick={onViewDetail}>
            查看详情
          </button>
        </div>
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
  return (
    <div className="card" style={{ padding: "16px 18px" }}>
      <div style={{ fontWeight: 700, marginBottom: 12 }}>优化建议</div>
      {items.length === 0 ? (
        <div className="muted" style={{ fontSize: 13, padding: "24px 0", textAlign: "center" }}>
          暂无优化建议，当前状态良好
        </div>
      ) : (
        <div className="opt-suggest-list">
          {items.map((item) => (
            <div
              key={item.id}
              className="opt-suggest-row"
              onClick={() => {
                if (item.findingId) onSelectFinding(item.findingId);
                else onGoThreat();
              }}
            >
              <SeverityPill sev={item.severity} label={SEV_LABEL[item.severity]} />
              <span className="opt-suggest-title">{item.title}</span>
              <span className="opt-suggest-link">查看</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function AssetManagementView({
  agentId,
  assets,
  subTab,
  onSubTabChange,
}: {
  agentId: string;
  assets: Asset[];
  subTab: (typeof ASSET_SUB_TABS)[number];
  onSubTabChange: (t: (typeof ASSET_SUB_TABS)[number]) => void;
}) {
  const filtered = assets.filter((a) => a.type === ASSET_TAB_TYPE[subTab]);
  return (
    <div>
      <div className="sub-tabs-pill">
        {ASSET_SUB_TABS.map((t) => (
          <div
            key={t}
            className={`sub-tab-pill ${subTab === t ? "active" : ""}`}
            onClick={() => onSubTabChange(t)}
          >
            {t}
          </div>
        ))}
      </div>
      <AssetTab agentId={agentId} assets={filtered} typeLabel={subTab} />
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
  const { fetchAgentRuntime } = useApp();
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
    <div className="card runtime-panel">
      <div className="row runtime-panel-head">
        <div style={{ fontWeight: 700 }}>资源占用</div>
        <span className="spacer" />
        <button
          type="button"
          className="btn btn-ghost runtime-refresh-btn"
          disabled={loading}
          title="刷新资源占用"
          onClick={load}
        >
          <span className="row" style={{ gap: 5, fontSize: 12.5 }}>
            <IconRefresh size={14} className={loading ? "spin" : undefined} />
            刷新
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
        />
        <RuntimeMetric
          label="内存"
          value={r ? formatMemoryTotal(r.memory_mb, r.memory_percent) : "—"}
          percent={r?.memory_percent ?? 0}
          max={100}
          history={r?.memory_history ?? []}
          color="#60a5fa"
        />
        <RuntimeMetric
          label="磁盘"
          value={r ? formatDiskTotal(r.disk_mb, r.disk_percent) : "—"}
          percent={r?.disk_percent ?? 0}
          max={100}
          history={r?.disk_history ?? []}
          color="#34d399"
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
}: {
  label: string;
  value: string;
  percent: number;
  max: number;
  history: number[];
  color: string;
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
      <div className="runtime-bar-track">
        <div
          className="runtime-bar-fill"
          style={{ width: `${barPct}%`, background: color }}
        />
      </div>
      {history.length > 0 && (
        <Sparkline data={history} color={color} max={max} />
      )}
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
  const w = 120;
  const h = 28;
  const pts = data.map((v, i) => {
    const x = (i / Math.max(data.length - 1, 1)) * w;
    const y = h - (Math.min(v, max) / max) * h;
    return `${x},${y}`;
  });
  return (
    <svg className="runtime-sparkline" viewBox={`0 0 ${w} ${h}`} preserveAspectRatio="none">
      <polyline
        fill="none"
        stroke={color}
        strokeWidth="1.5"
        strokeLinejoin="round"
        points={pts.join(" ")}
      />
    </svg>
  );
}

function StatBox({ icon, label, value }: { icon: React.ReactNode; label: string; value: number }) {
  return (
    <div className="stat-box">
      <div className="row" style={{ justifyContent: "space-between" }}>
        <span style={{ color: "var(--purple-2)" }}>{icon}</span>
        <span className="muted" style={{ fontSize: 12 }}>
          {label}
        </span>
      </div>
      <div style={{ fontSize: 26, fontWeight: 800, marginTop: 10 }}>{value}</div>
    </div>
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

function statusInfo(a: Asset): { label: string; color: string } {
  if (a.status === "updatable") return { label: "可更新", color: "var(--med)" };
  if (a.status === "disabled") return { label: "已禁用", color: "var(--high)" };
  return { label: "已启用", color: "var(--safe)" };
}

function AssetTab({
  agentId,
  assets,
  typeLabel,
}: {
  agentId: string;
  assets: Asset[];
  typeLabel: string;
}) {
  const { updateAsset, disableAsset, enableAsset, uninstallAsset, settings, snapshot } =
    useApp();
  const [sel, setSel] = useState("");
  const [depModal, setDepModal] = useState<Asset | null>(null);
  const [confirm, setConfirm] = useState<{ kind: string; id: string } | null>(null);

  useEffect(() => {
    setSel("");
    setDepModal(null);
  }, [typeLabel, assets.length]);

  const isDep = typeLabel === "依赖";
  const current = !isDep && sel ? assets.find((a) => a.id === sel) : undefined;
  const split = !!current;

  if (assets.length === 0) {
    return (
      <div className="card" style={{ padding: 30 }}>
        <span className="muted">该 Agent 暂无{typeLabel}。</span>
      </div>
    );
  }

  const toggleSel = (id: string) => {
    setSel((prev) => (prev === id ? "" : id));
  };

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
    <div className={`asset-tab${split ? " asset-tab-split" : ""}`}>
      <div className="card asset-tab-list">
        <table className="data-table">
          <thead>
            <tr>
              <th>名称</th>
              <th style={{ width: 110 }}>状态</th>
              <th style={{ width: 100 }}>版本</th>
              {!isDep && <th style={{ width: 72 }}>配置</th>}
              {!isDep && <th style={{ width: 72 }}>更新</th>}
              {!isDep && <th style={{ width: 72 }}>禁用</th>}
              {!isDep && <th style={{ width: 72 }}>卸载</th>}
              {isDep && <th style={{ width: 100 }}>漏洞</th>}
              {!isDep && <th style={{ width: 28 }} />}
            </tr>
          </thead>
          <tbody>
            {assets.map((a) => {
              const st = statusInfo(a);
              const active = isDep ? depModal?.id === a.id : sel === a.id;
              const cveRow = snapshot
                ? cveItemsForDep(snapshot, agentId, a.name, a.version).length
                : 0;
              return (
                <tr
                  key={a.id}
                  className={`asset-tab-row${active ? " active" : ""}`}
                  onClick={() => (isDep ? openDepModal(a) : toggleSel(a.id))}
                >
                  <td>
                    <div style={{ fontWeight: 600, fontSize: 14 }}>{a.name}</div>
                    <div className="dim" style={{ fontSize: 11.5, marginTop: 2 }}>
                      {a.purpose ? a.purpose.slice(0, 48) + (a.purpose.length > 48 ? "…" : "") : typeLabel}
                    </div>
                  </td>
                  <td>
                    <span className="row" style={{ gap: 6, color: st.color, fontSize: 13 }}>
                      <span style={{ width: 7, height: 7, borderRadius: 4, background: st.color }} />
                      {st.label}
                    </span>
                  </td>
                  <td className="muted mono">{a.version || "—"}</td>
                  {!isDep && (
                    <td onClick={(e) => e.stopPropagation()}>
                      <button type="button" className="asset-config-btn" title="配置">
                        <IconSettings size={16} />
                      </button>
                    </td>
                  )}
                  {!isDep && (
                    <td onClick={(e) => e.stopPropagation()}>
                      {a.can_update ? (
                        <span
                          className="update-pill"
                          onClick={() => doOp("update", a.id, settings.confirmUpdate)}
                        >
                          有可用更新
                        </span>
                      ) : (
                        <span className="dim">—</span>
                      )}
                    </td>
                  )}
                  {!isDep && (
                    <td onClick={(e) => e.stopPropagation()}>
                      {a.status === "disabled" ? (
                        <span
                          className="act-link act-enable"
                          onClick={() => doOp("enable", a.id, settings.confirmDisable)}
                        >
                          启用
                        </span>
                      ) : a.can_disable ? (
                        <span
                          className="act-link act-disable"
                          onClick={() => doOp("disable", a.id, settings.confirmDisable)}
                        >
                          禁用
                        </span>
                      ) : (
                        <span className="dim">—</span>
                      )}
                    </td>
                  )}
                  {!isDep && (
                    <td onClick={(e) => e.stopPropagation()}>
                      {a.can_uninstall ? (
                        <span
                          className="act-link act-uninstall"
                          onClick={() => doOp("uninstall", a.id, settings.confirmUninstall)}
                        >
                          卸载
                        </span>
                      ) : (
                        <span className="dim" title="需在 Agent 配置中手动处理">
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
                        <span className="dim">无</span>
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

      {current && (
        <div className="card asset-tab-detail">
          <AssetDetailPanel asset={current} typeLabel={typeLabel} />
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
              ? "卸载确认"
              : confirm.kind === "update"
                ? "更新确认"
                : confirm.kind === "enable"
                  ? "启用确认"
                  : "禁用确认"
          }
          message={
            confirm.kind === "uninstall"
              ? "卸载后该组件将从该 Agent 移除，确定继续吗？"
              : confirm.kind === "update"
                ? "确定更新到最新版本吗？"
                : confirm.kind === "enable"
                  ? "确定启用该组件吗？"
                  : "禁用后该组件将停止生效，确定继续吗？"
          }
          confirmLabel={confirm.kind === "uninstall" ? "确定卸载" : "确定"}
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
  const [selCve, setSelCve] = useState<string | null>(null);
  const st = statusInfo(asset);
  const cves = cveItemsForDep(snapshot, agentId, asset.name, asset.version);
  const advice = depUpgradeAdvice(snapshot, agentId, asset.name, asset.version);
  const selected = selCve ? cves.find((c) => c.cve_id === selCve) : undefined;
  const split = !!selected;

  const toggleCve = (cveId: string) => {
    setSelCve((prev) => (prev === cveId ? null : cveId));
  };

  return (
    <div className="modal-mask" onClick={onClose}>
      <div
        className={`modal cve-detail-modal dep-detail-modal${split ? " cve-detail-modal-split" : ""}`}
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
            <span className="tag">依赖</span>
          </div>
          <button type="button" className="modal-close" onClick={onClose}>
            ×
          </button>
        </div>

        <div className="dep-modal-section">
          <div className="row dep-modal-meta" style={{ gap: 28, flexWrap: "wrap" }}>
            <DetailMeta label="状态" value={st.label} color={st.color} />
            <DetailMeta label="来源" value={asset.source || "—"} />
            {asset.ecosystem && <DetailMeta label="生态" value={asset.ecosystem} />}
            {asset.manager && <DetailMeta label="包管理" value={asset.manager} />}
            <DetailMeta label="CVE 数量" value={String(cves.length)} />
          </div>
          {asset.purpose && (
            <div className="muted" style={{ marginTop: 12, lineHeight: 1.7, fontSize: 13.5 }}>
              {asset.purpose}
            </div>
          )}
          {asset.install_path && (
            <div className="mono dim" style={{ marginTop: 10, fontSize: 12, wordBreak: "break-all" }}>
              {asset.install_path}
            </div>
          )}
        </div>

        {cves.length === 0 ? (
          <div className="dep-modal-empty">未发现已知 CVE 漏洞</div>
        ) : (
          <>
            <div className={`cve-modal-body${split ? " is-split" : ""}`}>
              <div className="cve-modal-list">
                <div className="cve-modal-list-head">CVE 列表</div>
                <div className="cve-modal-cve-rows">
                  {cves.map((v) => (
                    <div
                      key={v.cve_id}
                      className={`cve-modal-cve-row${selCve === v.cve_id ? " active" : ""}`}
                      onClick={() => toggleCve(v.cve_id)}
                    >
                      <span className="mono" style={{ fontWeight: 600, fontSize: 13 }}>
                        {v.cve_id}
                      </span>
                      <SeverityPill sev={v.severity} />
                      <span style={{ fontWeight: 700, fontSize: 13 }}>{v.cvss.toFixed(1)}</span>
                      {!split && (
                        <span className="muted cve-modal-cve-summary">{v.summary}</span>
                      )}
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

              {split && selected && (
                <div className="cve-modal-detail">
                  <div className="cve-modal-list-head">漏洞详情</div>
                  <div className="cve-modal-detail-body">
                    <div className="row" style={{ gap: 10, marginBottom: 12 }}>
                      <span className="mono" style={{ fontSize: 16, fontWeight: 700 }}>
                        {selected.cve_id}
                      </span>
                      <SeverityPill sev={selected.severity} />
                    </div>
                    <div className="row" style={{ gap: 24, marginBottom: 16 }}>
                      <DetailMeta label="CVSS 评分" value={selected.cvss.toFixed(1)} />
                      <DetailMeta
                        label="威胁级别"
                        value={
                          selected.severity === "high"
                            ? "高危"
                            : selected.severity === "medium"
                              ? "中危"
                              : "低危"
                        }
                      />
                    </div>
                    <div className="dim" style={{ fontSize: 12, marginBottom: 6 }}>
                      简要描述
                    </div>
                    <div className="muted" style={{ lineHeight: 1.75, fontSize: 13.5 }}>
                      {selected.summary || "暂无描述"}
                    </div>
                  </div>
                </div>
              )}
            </div>

            {advice && (
              <div className="cve-modal-advice">
                <div className="dim" style={{ fontSize: 12, marginBottom: 6 }}>
                  修复建议
                </div>
                <div className="muted" style={{ lineHeight: 1.7, fontSize: 13.5 }}>
                  {advice}
                </div>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}

function AssetDetailPanel({ asset, typeLabel }: { asset: Asset; typeLabel: string }) {
  const st = statusInfo(asset);
  const typeIcon =
    typeLabel === "MCP" ? (
      <IconCube size={20} />
    ) : typeLabel === "Skills" ? (
      <IconBolt size={20} />
    ) : typeLabel === "知识库" ? (
      <IconBook size={20} />
    ) : (
      <IconDatabase size={20} />
    );

  return (
    <>
      <div className="row" style={{ gap: 10 }}>
        <span style={{ color: "var(--purple-2)" }}>{typeIcon}</span>
        <span style={{ fontSize: 18, fontWeight: 700, minWidth: 0 }}>{asset.name}</span>
        <span className="tag">{typeLabel}</span>
      </div>

      <div className="row" style={{ gap: 20, marginTop: 16, flexWrap: "wrap" }}>
        <DetailMeta label="状态" value={st.label} color={st.color} />
        <DetailMeta label="版本" value={asset.version || "—"} />
        <DetailMeta label="来源" value={asset.source || "—"} />
        {asset.ecosystem && <DetailMeta label="生态" value={asset.ecosystem} />}
      </div>

      {(typeLabel === "MCP" || typeLabel === "Skills" || typeLabel === "知识库") && (
        <AssetPermissionsSection permissions={asset.permissions} />
      )}

      <div className="detail-block" style={{ marginTop: 18 }}>
        <div className="dim" style={{ fontSize: 12.5, marginBottom: 6 }}>
          描述
        </div>
        <div className="muted" style={{ lineHeight: 1.7 }}>
          {asset.purpose || "—"}
        </div>
      </div>

      {asset.install_path && (
        <div style={{ marginTop: 14 }}>
          <div className="dim" style={{ fontSize: 12.5, marginBottom: 6 }}>
            安装路径
          </div>
          <div className="muted mono" style={{ fontSize: 12, wordBreak: "break-all" }}>
            {asset.install_path}
          </div>
        </div>
      )}
    </>
  );
}

function AssetPermissionsSection({ permissions }: { permissions: PermissionEntry[] }) {
  return (
    <div className="asset-detail-perms">
      <div className="asset-detail-perms-head">权限</div>
      {permissions.length === 0 ? (
        <div className="asset-detail-perms-empty muted">未检测到已声明权限</div>
      ) : (
        permissions.map((p) => (
          <div key={p.id} className="row asset-perm-row">
            <span className="asset-perm-icon">{permIcon(p.category)}</span>
            <div className="asset-perm-body">
              <div className="asset-perm-name">{p.name}</div>
              <div className="asset-perm-cat dim">{p.category}</div>
            </div>
            <SeverityPill sev={p.severity} label={SEV_LABEL[p.severity]} />
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
