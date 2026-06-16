import React, { useEffect, useMemo, useState } from "react";
import { useApp } from "../store";
import { vulnerableComponentRows, type VulnComponentRow } from "../selectors";
import { SeverityPill } from "../components/common";
import type { CVEItem, Severity } from "../types";
import {
  IconChevron,
  IconCube,
  IconExternal,
  IconShield,
} from "../components/Icons";

type SevFilter = "all" | Severity;

export interface VulnListProps {
  componentId?: string;
  agentId?: string;
  severity?: Severity;
  embedded?: boolean;
}

export function VulnList({
  componentId,
  agentId,
  severity,
  embedded,
}: VulnListProps) {
  const { snapshot } = useApp();
  const cveUnavailable = snapshot?.meta.cve_status === "unavailable";
  const scannedCount = snapshot?.meta.cve_scanned_count;

  const rows = useMemo(
    () => (snapshot ? vulnerableComponentRows(snapshot) : []),
    [snapshot]
  );

  const agents = useMemo(() => {
    const ids = new Map<string, string>();
    for (const r of rows) ids.set(r.agentId, r.agentName);
    return [...ids.entries()].map(([id, name]) => ({ id, name }));
  }, [rows]);

  const [sevFilter, setSevFilter] = useState<SevFilter>(severity ?? "all");
  const [agentFilter, setAgentFilter] = useState(agentId ?? "all");
  const [query, setQuery] = useState("");
  const [modalRow, setModalRow] = useState<VulnComponentRow | null>(null);
  const [selCve, setSelCve] = useState<string | null>(null);

  useEffect(() => {
    if (agentId) setAgentFilter(agentId);
  }, [agentId]);

  useEffect(() => {
    if (severity) setSevFilter(severity);
  }, [severity]);

  useEffect(() => {
    if (!componentId || rows.length === 0) return;
    const cid = componentId.startsWith("cve-") ? componentId.slice(4) : componentId;
    const hit = rows.find(
      (r) => r.key === componentId || r.component === cid || r.key.endsWith(`::${cid}`)
    );
    if (hit) {
      setModalRow(hit);
      setSelCve(null);
    }
  }, [componentId, rows]);

  const scopedRows = useMemo(() => {
    if (!agentId) return rows;
    return rows.filter((r) => r.agentId === agentId);
  }, [rows, agentId]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return scopedRows.filter((r) => {
      if (sevFilter !== "all" && r.severity !== sevFilter) return false;
      if (!agentId && agentFilter !== "all" && r.agentId !== agentFilter) return false;
      if (q) {
        const hay = `${r.component} ${r.versionLabel} ${r.agentName} ${r.ecosystem}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
  }, [scopedRows, sevFilter, agentFilter, agentId, query]);

  const openModal = (row: VulnComponentRow) => {
    setModalRow(row);
    setSelCve(null);
  };

  const toggleCve = (cveId: string) => {
    setSelCve((prev) => (prev === cveId ? null : cveId));
  };

  if (!snapshot) {
    return (
      <main className={embedded ? undefined : "main flush"}>
        <div className="muted">暂无扫描结果，请先在「安全扫描」发起扫描。</div>
      </main>
    );
  }

  if (cveUnavailable) {
    const unavailable = (
      <div className="card" style={{ padding: 40, textAlign: "center" }}>
        <div className="muted">CVE 检测不可用：组件漏洞检测需要联网，当前网络不可用。</div>
        <div className="dim" style={{ marginTop: 8, fontSize: 13 }}>
          威胁扫描结果不受影响。
        </div>
      </div>
    );
    if (embedded) return unavailable;
    return (
      <main className="main flush">
        <div className="page-title" style={{ fontSize: 20, marginBottom: 16 }}>
          漏洞管理
        </div>
        {unavailable}
      </main>
    );
  }

  const body = (
    <>
      {!embedded && (
        <div className="page-title" style={{ fontSize: 20, marginBottom: 16 }}>
          漏洞管理
        </div>
      )}
      {embedded && agentId && (
        <div className="dim" style={{ fontSize: 12.5, marginBottom: 12 }}>
          仅显示 {agents.find((a) => a.id === agentId)?.name || agentId} 的组件漏洞
        </div>
      )}

      <div className="dim" style={{ fontSize: 12.5, marginBottom: 14 }}>
        {scannedCount != null && <>已扫描 {scannedCount} 个组件 · </>}
        {scopedRows.length} 个组件存在已知 CVE
        {filtered.length !== scopedRows.length && <> · 当前筛选 {filtered.length} 项</>}
      </div>

      <div className="card cve-toolbar" style={{ padding: "14px 16px", marginBottom: 14 }}>
        <div className="row" style={{ gap: 10, flexWrap: "wrap" }}>
          <select
            className="select-input cve-filter"
            value={sevFilter}
            onChange={(e) => setSevFilter(e.target.value as SevFilter)}
          >
            <option value="all">全部风险</option>
            <option value="high">高危</option>
            <option value="medium">中危</option>
            <option value="low">低危</option>
          </select>
          {!agentId && (
            <select
              className="select-input cve-filter"
              value={agentFilter}
              onChange={(e) => setAgentFilter(e.target.value)}
            >
              <option value="all">全部 Agent</option>
              {agents.map((a) => (
                <option key={a.id} value={a.id}>
                  {a.name}
                </option>
              ))}
            </select>
          )}
          <input
            className="text-input cve-search"
            placeholder="搜索组件名称…"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
        </div>
      </div>

      <div className="card" style={{ padding: 0, overflow: "hidden" }}>
        {filtered.length === 0 ? (
          <div className="muted" style={{ padding: 48, textAlign: "center", fontSize: 13.5 }}>
            {scopedRows.length === 0
              ? "暂无存在已知 CVE 的组件。"
              : "没有符合筛选条件的组件。"}
          </div>
        ) : (
          <table className="data-table cve-list-table">
            <thead>
              <tr>
                <th>组件名称</th>
                <th style={{ width: 100 }}>风险等级</th>
                <th style={{ width: 80 }}>CVE 数</th>
                <th style={{ width: 120 }}>当前版本</th>
                <th style={{ width: 120 }}>建议版本</th>
                {!agentId && <th style={{ width: 130 }}>所属 Agent</th>}
                <th style={{ width: 72 }}>操作</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((r) => (
                <tr key={r.key} className="cve-list-row" onClick={() => openModal(r)}>
                  <td>
                    <span className="row" style={{ gap: 8 }}>
                      <IconCube size={16} style={{ color: "var(--purple-2)", flexShrink: 0 }} />
                      <span style={{ fontWeight: 600 }}>{r.component}</span>
                    </span>
                  </td>
                  <td>
                    <SeverityPill sev={r.severity} />
                  </td>
                  <td style={{ fontWeight: 700 }}>{r.cveCount}</td>
                  <td className="mono dim">{r.versionLabel}</td>
                  <td className="mono dim">{r.fixedVersion || "—"}</td>
                  {!agentId && <td className="muted">{r.agentName}</td>}
                  <td>
                    <span className="act-link">查看</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {modalRow && (
        <ComponentModal
          row={modalRow}
          selCve={selCve}
          onToggleCve={toggleCve}
          onClose={() => {
            setModalRow(null);
            setSelCve(null);
          }}
        />
      )}
    </>
  );

  if (embedded) return <div className="vuln-list-embedded">{body}</div>;
  return <main className="main flush">{body}</main>;
}

/** @deprecated 使用 VulnList + vuln-list 路由 */
export function ComponentDetail({ componentId }: { componentId?: string }) {
  return <VulnList componentId={componentId} />;
}

function ComponentModal({
  row,
  selCve,
  onToggleCve,
  onClose,
}: {
  row: VulnComponentRow;
  selCve: string | null;
  onToggleCve: (cveId: string) => void;
  onClose: () => void;
}) {
  const selected: CVEItem | undefined = selCve
    ? row.cves.find((c) => c.cve_id === selCve)
    : undefined;

  return (
    <div className="modal-mask" onClick={onClose}>
      <div
        className="modal cve-detail-modal"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="modal-head">
          <div className="row" style={{ gap: 10, minWidth: 0 }}>
            <IconCube size={20} style={{ color: "var(--purple-2)", flexShrink: 0 }} />
            <div className="modal-title" style={{ minWidth: 0 }}>
              {row.component}
              <span className="dim" style={{ fontSize: 13, fontWeight: 500, marginLeft: 8 }}>
                {row.versionLabel}
              </span>
            </div>
            <SeverityPill sev={row.severity} />
          </div>
          <button className="modal-close" onClick={onClose}>
            ×
          </button>
        </div>

        <div className="row cve-modal-meta" style={{ gap: 28, flexWrap: "wrap" }}>
          <Meta label="所属 Agent" value={row.agentName} />
          <Meta label="包生态" value={row.ecosystem} />
          <Meta label="CVE 数量" value={String(row.cveCount)} />
          <Meta label="修复版本" value={row.fixedVersion || "—"} />
        </div>

        <div className="cve-modal-body cve-modal-body-stack">
          <div className="cve-modal-list">
            <div className="cve-modal-list-head">CVE 列表</div>
            <div className="cve-modal-cve-rows">
              {row.cves.map((v) => (
                <div
                  key={v.cve_id}
                  className={`cve-modal-cve-row${selCve === v.cve_id ? " active" : ""}`}
                  onClick={() => onToggleCve(v.cve_id)}
                >
                  <span className="mono" style={{ fontWeight: 600, fontSize: 13 }}>
                    {v.cve_id}
                  </span>
                  <SeverityPill sev={v.severity} />
                  <span style={{ fontWeight: 700, fontSize: 13 }}>{v.cvss.toFixed(1)}</span>
                  <span className="muted cve-modal-cve-summary">{v.summary}</span>
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
              <div className="cve-modal-list-head">漏洞详情</div>
              <div className="cve-modal-detail-body">
                <div className="row" style={{ gap: 10, marginBottom: 12 }}>
                  <span className="mono" style={{ fontSize: 16, fontWeight: 700 }}>
                    {selected.cve_id}
                  </span>
                  <SeverityPill sev={selected.severity} />
                </div>
                <div className="row" style={{ gap: 24, marginBottom: 16 }}>
                  <Meta label="CVSS 评分" value={selected.cvss.toFixed(1)} />
                  <Meta
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

        <div className="cve-modal-advice">
          <div className="row" style={{ marginBottom: 8 }}>
            <span className="row" style={{ gap: 6, fontWeight: 600, fontSize: 13.5 }}>
              <IconShield size={15} style={{ color: "var(--purple-2)" }} />
              升级建议
            </span>
            <div className="spacer" />
            {row.fixedVersion && (
              <button className="btn btn-primary btn-sm" type="button">
                <span className="row" style={{ gap: 6 }}>
                  查看升级指南 <IconExternal size={13} />
                </span>
              </button>
            )}
          </div>
          <div className="muted" style={{ lineHeight: 1.75, fontSize: 13 }}>
            {row.upgradeAdvice}
          </div>
        </div>
      </div>
    </div>
  );
}

function Meta({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <div className="dim" style={{ fontSize: 12 }}>
        {label}
      </div>
      <div style={{ fontSize: 14, fontWeight: 600, marginTop: 3 }}>{value}</div>
    </div>
  );
}
