import React, { useState } from "react";
import { useApp } from "../store";
import { assetsByAgent, exposureForAgent } from "../selectors";
import { Radar, RadarAxis } from "../components/Radar";
import { SeverityPill, ConfirmModal, SEV_RISK_LABEL } from "../components/common";
import type { Asset, PermissionEntry, Severity } from "../types";
import {
  IconAlert,
  IconArrowLeft,
  IconBolt,
  IconBook,
  IconCheck,
  IconCube,
  IconFile,
  IconGlobe,
  IconLayers,
  IconTerminal,
  IconDatabase,
  IconHexAgent,
  IconChevron,
} from "../components/Icons";

const SEV_W: Record<Severity, number> = { high: 3, medium: 2, low: 1, info: 0, safe: 0 };
const RADAR_CATS = ["文件", "Shell", "网络", "工具", "知识库"];
const TABS = ["概览", "MCP", "Skills", "知识库", "依赖"];
const TAB_TYPE: Record<string, string> = {
  MCP: "mcp",
  Skills: "skill",
  知识库: "knowledge",
  依赖: "dependency",
};

export function AgentWorkbench({
  agentId,
  initialTab,
  focusSource,
}: {
  agentId: string;
  initialTab?: string;
  focusSource?: string;
}) {
  const { snapshot, navigate } = useApp();
  const [tab, setTab] = useState(initialTab || "概览");
  const [showPerm, setShowPerm] = useState(false);

  const agent = snapshot?.agents.find((a) => a.id === agentId);
  if (!snapshot || !agent) {
    return (
      <main className="main">
        <div className="muted">未找到该 Agent。</div>
      </main>
    );
  }

  const assets = assetsByAgent(snapshot, agentId);
  const allPerms: PermissionEntry[] = [
    ...agent.permissions,
    ...assets.flatMap((a) => a.permissions),
  ];

  const hue = agent.kind === "openclaw" ? "#60a5fa" : "#a855f7";

  return (
    <main className="main flush">
      {/* 顶栏 */}
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

      <div className="row" style={{ gap: 14, marginTop: 12 }}>
        <IconHexAgent size={42} hue={hue} />
        <span style={{ fontSize: 24, fontWeight: 800 }}>{agent.name}</span>
        <span className="ver-badge">{agent.version}</span>
        <span className="row muted" style={{ gap: 5, fontSize: 13 }}>
          <span style={{ width: 8, height: 8, borderRadius: 4, background: "var(--safe)" }} />
          {agent.enabled ? "已启用" : "已禁用"}
        </span>
      </div>

      {/* Tabs */}
      <div className="tabs">
        {TABS.map((t) => (
          <div
            key={t}
            className={`tab ${tab === t ? "active" : ""}`}
            onClick={() => setTab(t)}
          >
            {t}
          </div>
        ))}
      </div>

      {tab === "概览" ? (
        <Overview
          assets={assets}
          perms={allPerms}
          exposureHigh={exposureForAgent(snapshot, agentId)}
          onOpenPerm={() => setShowPerm(true)}
        />
      ) : (
        <AssetTab
          assets={assets.filter((a) => a.type === TAB_TYPE[tab])}
          typeLabel={tab}
        />
      )}

      {showPerm && (
        <PermissionModal
          perms={allPerms}
          onClose={() => setShowPerm(false)}
          onLocate={(p) => {
            setShowPerm(false);
            const tabMap: Record<string, string> = {
              mcp: "MCP",
              skill: "Skills",
              knowledge: "知识库",
              agent_config: "概览",
            };
            const target = tabMap[p.source] || "概览";
            navigate({
              name: "agent-workbench",
              agentId,
              tab: target,
              focusSource: `${p.category}权限`,
            });
          }}
        />
      )}
    </main>
  );
}

/* ---------- 概览四宫格 ---------- */
function Overview({
  assets,
  perms,
  exposureHigh,
  onOpenPerm,
}: {
  assets: Asset[];
  perms: PermissionEntry[];
  exposureHigh: ReturnType<typeof exposureForAgent>;
  onOpenPerm: () => void;
}) {
  const radarAxes: RadarAxis[] = RADAR_CATS.map((cat) => {
    const inCat = perms.filter((p) => p.category === cat);
    const max = inCat.reduce((m, p) => Math.max(m, SEV_W[p.severity]), 0);
    return { label: cat, score: max / 3 };
  });

  const mcp = assets.filter((a) => a.type === "mcp").length;
  const skills = assets.filter((a) => a.type === "skill").length;
  const knowledge = assets.filter((a) => a.type === "knowledge").length;

  const high = exposureHigh.filter((f) => f.severity === "high").length;
  const med = exposureHigh.filter((f) => f.severity === "medium").length;
  const low = exposureHigh.filter((f) => f.severity === "low").length;
  const safe = assets.filter(
    (a) =>
      a.type !== "dependency" &&
      a.permissions.every((p) => SEV_W[p.severity] <= 1)
  ).length;

  const updatable = assets.filter((a) => a.status === "updatable");

  return (
    <div className="quad">
      {/* 权限分布 */}
      <div className="card" style={{ padding: 18, position: "relative" }}>
        <div style={{ fontWeight: 700, marginBottom: 6 }}>权限分布</div>
        <div className="row" style={{ justifyContent: "center", height: "calc(100% - 24px)" }}>
          <Radar axes={radarAxes} size={250} />
        </div>
        {/* 极小隐蔽入口 */}
        <button
          title="查看权限详情"
          onClick={onOpenPerm}
          style={{
            position: "absolute",
            right: 16,
            bottom: 16,
            background: "rgba(255,255,255,0.06)",
            border: "none",
            borderRadius: 8,
            padding: 7,
            cursor: "pointer",
            color: "var(--text-2)",
          }}
        >
          <IconLayers size={18} />
        </button>
      </div>

      {/* 资产统计 */}
      <div className="card" style={{ padding: 18 }}>
        <div style={{ fontWeight: 700, marginBottom: 16 }}>资产统计</div>
        <div className="row" style={{ gap: 14, alignItems: "stretch" }}>
          <StatBox icon={<IconCube size={20} />} label="MCP" value={mcp} />
          <StatBox icon={<IconBolt size={20} />} label="Skills" value={skills} />
          <StatBox icon={<IconBook size={20} />} label="知识库" value={knowledge} />
        </div>
      </div>

      {/* 风险摘要 */}
      <div className="card" style={{ padding: 18 }}>
        <div style={{ fontWeight: 700, marginBottom: 16 }}>风险摘要</div>
        <div className="row" style={{ gap: 12 }}>
          <RiskBox label="高风险" value={high} color="var(--high)" bg="var(--high-bg)" icon={<IconAlert size={16} />} />
          <RiskBox label="中风险" value={med} color="var(--med)" bg="var(--med-bg)" icon={<IconAlert size={16} />} />
          <RiskBox label="低风险" value={low} color="var(--low)" bg="var(--low-bg)" icon={<IconAlert size={16} />} />
          <RiskBox label="安全" value={safe} color="var(--safe)" bg="var(--safe-bg)" icon={<IconCheck size={16} />} />
        </div>
      </div>

      {/* 可更新 */}
      <div className="card" style={{ padding: 18, overflow: "auto" }}>
        <div style={{ fontWeight: 700, marginBottom: 12 }}>可更新</div>
        {updatable.length === 0 && (
          <div className="dim" style={{ fontSize: 13 }}>当前没有可更新项</div>
        )}
        {updatable.map((a) => (
          <div key={a.id} className="row" style={{ gap: 10, padding: "9px 0" }}>
            <span style={{ color: "var(--purple-2)" }}>
              {a.type === "mcp" ? <IconCube size={18} /> : a.type === "skill" ? <IconBolt size={18} /> : <IconBook size={18} />}
            </span>
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ fontSize: 13, fontWeight: 600 }}>{a.name}</div>
              <div className="dim" style={{ fontSize: 11.5 }}>
                当前版本 {a.version} → 最新版本 {a.latest_version}
              </div>
            </div>
            <UpdateButton assetId={a.id} />
          </div>
        ))}
      </div>
    </div>
  );
}

function UpdateButton({ assetId }: { assetId: string }) {
  const { updateAsset, settings } = useApp();
  const [confirm, setConfirm] = useState(false);
  const go = () => (settings.confirmUpdate ? setConfirm(true) : updateAsset(assetId));
  return (
    <>
      <span className="sev sev-high" style={{ cursor: "pointer", background: "var(--purple-soft)", color: "var(--purple-2)" }} onClick={go}>
        可更新
      </span>
      {confirm && (
        <ConfirmModal
          title="更新确认"
          message="确定要将该组件更新到最新版本吗？更新过程经由对应包管理器执行。"
          confirmLabel="确定更新"
          onConfirm={() => {
            setConfirm(false);
            updateAsset(assetId);
          }}
          onCancel={() => setConfirm(false)}
        />
      )}
    </>
  );
}

function StatBox({ icon, label, value }: { icon: React.ReactNode; label: string; value: number }) {
  return (
    <div className="stat-box">
      <div className="row" style={{ justifyContent: "space-between" }}>
        <span style={{ color: "var(--purple-2)" }}>{icon}</span>
        <span className="muted" style={{ fontSize: 12 }}>{label}</span>
      </div>
      <div style={{ fontSize: 30, fontWeight: 800, marginTop: 10 }}>{value}</div>
    </div>
  );
}

function RiskBox({
  label,
  value,
  color,
  bg,
  icon,
}: {
  label: string;
  value: number;
  color: string;
  bg: string;
  icon: React.ReactNode;
}) {
  return (
    <div style={{ flex: 1, background: bg, borderRadius: 12, padding: "14px 10px", textAlign: "center" }}>
      <div className="row" style={{ gap: 5, justifyContent: "center", color, fontSize: 12.5, fontWeight: 600 }}>
        {icon} {label}
      </div>
      <div style={{ fontSize: 26, fontWeight: 800, color, marginTop: 8 }}>{value}</div>
    </div>
  );
}

/* ---------- 权限详情弹窗 ---------- */
function permIcon(cat: string) {
  if (cat === "文件") return <IconFile size={17} />;
  if (cat === "Shell") return <IconTerminal size={17} />;
  if (cat === "网络") return <IconGlobe size={17} />;
  if (cat === "知识库") return <IconBook size={17} />;
  return <IconDatabase size={17} />;
}

const GROUPS: { key: string; label: string }[] = [
  { key: "agent_config", label: "Agent 配置" },
  { key: "mcp", label: "MCP" },
  { key: "skill", label: "Skill" },
  { key: "knowledge", label: "知识库" },
];

function PermissionModal({
  perms,
  onClose,
  onLocate,
}: {
  perms: PermissionEntry[];
  onClose: () => void;
  onLocate: (p: PermissionEntry) => void;
}) {
  return (
    <div className="modal-mask" onClick={onClose}>
      <div
        className="modal"
        style={{ width: 520, maxHeight: "78vh", overflow: "auto" }}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="modal-head">
          <div className="modal-title">权限详情</div>
          <button className="modal-close" onClick={onClose}>×</button>
        </div>

        {GROUPS.map((g) => {
          const rows = perms.filter((p) => p.source === g.key);
          if (rows.length === 0) return null;
          return (
            <div key={g.key} style={{ marginBottom: 18 }}>
              <div className="dim" style={{ fontSize: 12.5, margin: "4px 0 8px" }}>
                {g.label}
              </div>
              {rows.map((p) => (
                <div
                  key={p.id}
                  className="row perm-row"
                  onClick={() => onLocate(p)}
                  title="定位来源"
                >
                  <span style={{ color: "var(--purple-2)" }}>{permIcon(p.category)}</span>
                  <span style={{ flex: 1, fontSize: 13.5 }}>{p.name}</span>
                  <span className="tag">{p.source_label}</span>
                  <SeverityPill sev={p.severity} label={SEV_RISK_LABEL[p.severity]} />
                </div>
              ))}
            </div>
          );
        })}
      </div>
    </div>
  );
}

/* ---------- 资产 Tab（列表 + 详情 + 管理） ---------- */
function statusInfo(a: Asset): { label: string; color: string } {
  if (a.status === "updatable") return { label: "可更新", color: "var(--med)" };
  if (a.status === "disabled") return { label: "已禁用", color: "var(--high)" };
  return { label: "已启用", color: "var(--safe)" };
}

function AssetTab({ assets, typeLabel }: { assets: Asset[]; typeLabel: string }) {
  const { updateAsset, disableAsset, enableAsset, uninstallAsset, settings, navigate, snapshot } =
    useApp();
  const [sel, setSel] = useState<string>(assets[0]?.id || "");
  const [confirm, setConfirm] = useState<{ kind: string; id: string } | null>(null);
  const current = assets.find((a) => a.id === sel) || assets[0];

  if (assets.length === 0) {
    return <div className="card" style={{ padding: 30 }} ><span className="muted">该 Agent 暂无{typeLabel}。</span></div>;
  }

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

  const isDep = typeLabel === "依赖";

  return (
    <div className="split" style={{ gridTemplateColumns: "1fr 360px" }}>
      {/* 列表（表格） */}
      <div className="split-list card" style={{ padding: 16 }}>
        <table className="data-table">
          <thead>
            <tr>
              <th>名称</th>
              <th style={{ width: 90 }}>状态</th>
              <th style={{ width: 70 }}>版本</th>
              {!isDep && <th style={{ width: 60 }}>操作</th>}
              {!isDep && <th style={{ width: 60 }}>更新</th>}
              {!isDep && <th style={{ width: 60 }}>禁用</th>}
              {!isDep && <th style={{ width: 60 }}>卸载</th>}
              {isDep && <th style={{ width: 90 }}>漏洞</th>}
            </tr>
          </thead>
          <tbody>
            {assets.map((a) => {
              const st = statusInfo(a);
              const active = current?.id === a.id;
              const cveCount =
                snapshot?.cve_findings.find((c) => c.component === a.name)?.cves.length ?? 0;
              return (
                <tr
                  key={a.id}
                  onClick={() => setSel(a.id)}
                  style={{
                    cursor: "pointer",
                    background: active ? "var(--purple-soft)" : undefined,
                  }}
                >
                  <td>
                    <div style={{ fontWeight: 600 }}>{a.name}</div>
                    <div className="dim" style={{ fontSize: 11 }}>{typeLabel}</div>
                  </td>
                  <td>
                    <span className="row" style={{ gap: 6, color: st.color, fontSize: 13 }}>
                      <span style={{ width: 7, height: 7, borderRadius: 4, background: st.color }} />
                      {st.label}
                    </span>
                  </td>
                  <td className="muted">{a.version}</td>
                  {!isDep && (
                    <td><span className="link" style={{ fontSize: 13 }}>配置</span></td>
                  )}
                  {!isDep && (
                    <td onClick={(e) => e.stopPropagation()}>
                      {a.can_update ? (
                        <span className="link" style={{ fontSize: 13 }} onClick={() => doOp("update", a.id, settings.confirmUpdate)}>更新</span>
                      ) : (
                        <span className="dim">—</span>
                      )}
                    </td>
                  )}
                  {!isDep && (
                    <td onClick={(e) => e.stopPropagation()}>
                      {a.status === "disabled" ? (
                        <span className="link" style={{ fontSize: 13 }} onClick={() => doOp("enable", a.id, settings.confirmDisable)}>启用</span>
                      ) : (
                        <span className="link" style={{ fontSize: 13 }} onClick={() => doOp("disable", a.id, settings.confirmDisable)}>禁用</span>
                      )}
                    </td>
                  )}
                  {!isDep && (
                    <td onClick={(e) => e.stopPropagation()}>
                      {a.can_uninstall ? (
                        <span className="link btn-danger" style={{ fontSize: 13 }} onClick={() => doOp("uninstall", a.id, settings.confirmUninstall)}>卸载</span>
                      ) : (
                        <span className="dim" title="需在 Agent 配置中手动处理">—</span>
                      )}
                    </td>
                  )}
                  {isDep && (
                    <td onClick={(e) => e.stopPropagation()}>
                      {cveCount > 0 ? (
                        <span className="link" style={{ fontSize: 13 }} onClick={() => navigate({ name: "cve-detail", componentId: "cve-" + a.name })}>
                          {cveCount} 个 CVE
                        </span>
                      ) : (
                        <span className="dim">无</span>
                      )}
                    </td>
                  )}
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {/* 详情 */}
      <div className="split-detail card" style={{ padding: 20 }}>
        {current && (
          <>
            <div className="row" style={{ gap: 10 }}>
              <span style={{ color: "var(--purple-2)" }}>
                {typeLabel === "MCP" ? <IconCube size={20} /> : typeLabel === "Skills" ? <IconBolt size={20} /> : typeLabel === "知识库" ? <IconBook size={20} /> : <IconDatabase size={20} />}
              </span>
              <span style={{ fontSize: 18, fontWeight: 700 }}>{current.name}</span>
              <span className="tag">{typeLabel}</span>
            </div>

            {current.permissions.length > 0 && (
              <div style={{ marginTop: 18 }}>
                <div className="dim" style={{ fontSize: 12.5, marginBottom: 9 }}>权限</div>
                {current.permissions.map((p) => (
                  <div key={p.id} className="row" style={{ gap: 10, padding: "10px 12px", background: "var(--bg-inset)", borderRadius: 10, marginBottom: 8 }}>
                    <span style={{ color: "var(--purple-2)" }}>{permIcon(p.category)}</span>
                    <span style={{ flex: 1, fontSize: 13.5 }}>{p.category}</span>
                    <span className="dim" style={{ fontSize: 12 }}>{p.name}</span>
                  </div>
                ))}
              </div>
            )}

            <div className="detail-block" style={{ marginTop: 18 }}>
              <div className="dim" style={{ fontSize: 12.5, marginBottom: 6 }}>描述</div>
              <div className="muted" style={{ lineHeight: 1.7 }}>{current.purpose || "—"}</div>
            </div>
            <div>
              <div className="dim" style={{ fontSize: 12.5, marginBottom: 6 }}>来源</div>
              <div className="muted">{current.source || "—"}</div>
            </div>
          </>
        )}
      </div>

      {confirm && (
        <ConfirmModal
          title={confirm.kind === "uninstall" ? "卸载确认" : confirm.kind === "update" ? "更新确认" : confirm.kind === "enable" ? "启用确认" : "禁用确认"}
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
