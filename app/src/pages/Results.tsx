import React from "react";
import { useApp } from "../store";
import {
  assetCounts,
  cveCounts,
  exposureCounts,
  topItems,
} from "../selectors";
import { SeverityDot, SeverityPill } from "../components/common";
import {
  IconChevron,
  IconClock,
  IconCube,
  IconLayers,
  IconMonitor,
  IconRefresh,
  IconShield,
  IconCheck,
} from "../components/Icons";

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
  const top = topItems(snapshot, 3);
  const cveUnavailable = snapshot.meta.cve_status === "unavailable";

  return (
    <main className="main">
      {/* 顶栏 */}
      <div className="card" style={{ padding: "16px 20px", marginBottom: 16 }}>
        <div className="row" style={{ gap: 18 }}>
          <div className="row" style={{ gap: 10, fontWeight: 700, fontSize: 17 }}>
            <IconCheck size={20} style={{ color: "var(--safe)" }} /> 扫描完成
          </div>
          <span className="muted row" style={{ gap: 6, fontSize: 13 }}>
            <IconClock size={15} /> {snapshot.meta.duration_seconds}秒
          </span>
          <span className="muted row" style={{ gap: 6, fontSize: 13 }}>
            <IconMonitor size={15} /> {snapshot.meta.scope}
          </span>
          <div className="spacer" />
          <button
            className="btn btn-primary btn-sm"
            onClick={() => startScan(snapshot.meta.scope)}
          >
            <span className="row" style={{ gap: 6 }}>
              <IconRefresh size={14} /> 重新扫描
            </span>
          </button>
        </div>
      </div>

      {/* 三卡片 */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 16 }}>
        <KpiCard
          icon={<IconShield size={18} />}
          title="暴露面与基线"
          onClick={() => navigate({ name: "exposure-detail" })}
        >
          <div className="row" style={{ gap: 26 }}>
            <Kpi value={exp.high} label="高危" color="var(--high)" />
            <Kpi value={exp.medium} label="中危" color="var(--med)" />
            <Kpi value={exp.low} label="低危" color="var(--low)" />
          </div>
        </KpiCard>

        <KpiCard
          icon={<IconCube size={18} />}
          title="组件漏洞"
          onClick={() => navigate({ name: "cve-detail" })}
        >
          {cveUnavailable ? (
            <div className="muted" style={{ fontSize: 13, padding: "8px 0" }}>
              CVE 检测不可用（联网失败）
            </div>
          ) : (
            <div className="row" style={{ gap: 22 }}>
              <Kpi value={cve.high} label="高危 (CVE)" color="var(--high)" />
              <Kpi value={cve.medium} label="中危" color="var(--med)" />
              <Kpi value={cve.affected} label="受影响组件" color="var(--text-1)" />
            </div>
          )}
        </KpiCard>

        <KpiCard
          icon={<IconLayers size={18} />}
          title="Agent 资产"
          onClick={() => navigate({ name: "agent-list" })}
        >
          <div className="row" style={{ gap: 30 }}>
            <Kpi value={ac.agents} label="Agents" color="var(--purple-2)" sub />
            <Kpi value={ac.mcp} label="MCP" color="var(--purple-2)" sub />
            <Kpi value={ac.skills} label="Skills" color="var(--purple-2)" sub />
          </div>
        </KpiCard>
      </div>

      {/* Top3 */}
      <div className="card" style={{ marginTop: 16, padding: 18 }}>
        <div style={{ fontWeight: 700, marginBottom: 12 }}>优先处理 Top3</div>
        <table className="data-table">
          <thead>
            <tr>
              <th>风险项</th>
              <th style={{ width: 110 }}>风险类型</th>
              <th style={{ width: 110 }}>影响范围</th>
              <th style={{ width: 110 }}>严重等级</th>
              <th style={{ width: 160 }}>发现时间</th>
              <th style={{ width: 30 }} />
            </tr>
          </thead>
          <tbody>
            {top.map((t) => (
              <tr key={t.key}>
                <td>
                  <span className="row" style={{ gap: 8 }}>
                    <SeverityDot sev={t.severity} />
                    {t.title}
                  </span>
                </td>
                <td>
                  <span className="tag">{t.riskType}</span>
                </td>
                <td className="muted">{t.impact}</td>
                <td>
                  <SeverityPill
                    sev={t.severity}
                    label={t.isCve ? `${sevLabel(t.severity)} (CVE)` : undefined}
                  />
                </td>
                <td className="dim">{t.when}</td>
                <td className="dim">···</td>
              </tr>
            ))}
          </tbody>
        </table>
        <div style={{ textAlign: "center", marginTop: 12 }}>
          <span
            className="link"
            onClick={() => navigate({ name: "exposure-detail" })}
          >
            查看全部结果 <IconChevron size={13} />
          </span>
        </div>
      </div>
    </main>
  );
}

function sevLabel(s: string) {
  return s === "high" ? "高危" : s === "medium" ? "中危" : "低危";
}

function KpiCard({
  icon,
  title,
  children,
  onClick,
}: {
  icon: React.ReactNode;
  title: string;
  children: React.ReactNode;
  onClick: () => void;
}) {
  return (
    <div className="card kpi-card" style={{ padding: 18 }}>
      <div className="row" style={{ gap: 9, marginBottom: 16 }}>
        <span style={{ color: "var(--purple-2)" }}>{icon}</span>
        <span style={{ fontWeight: 700 }}>{title}</span>
      </div>
      <div style={{ minHeight: 48 }}>{children}</div>
      <div className="link" style={{ marginTop: 14 }} onClick={onClick}>
        查看详情 <IconChevron size={13} />
      </div>
    </div>
  );
}

function Kpi({
  value,
  label,
  color,
  sub,
}: {
  value: number;
  label: string;
  color: string;
  sub?: boolean;
}) {
  return (
    <div style={{ textAlign: sub ? "center" : "left" }}>
      <span style={{ fontSize: 30, fontWeight: 800, color }}>{value}</span>
      {sub ? (
        <div className="muted" style={{ fontSize: 12, marginTop: 2 }}>
          {label}
        </div>
      ) : (
        <span className="muted" style={{ fontSize: 13, marginLeft: 6 }}>
          {label}
        </span>
      )}
    </div>
  );
}
