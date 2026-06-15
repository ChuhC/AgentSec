import React, { useEffect, useMemo, useState } from "react";
import { useApp } from "../store";
import { SeverityPill } from "../components/common";
import { exposureFindingKey, exposureForAgent } from "../selectors";
import type { ExposureFinding, Severity } from "../types";
import {
  IconAlert,
  IconExternal,
  IconFile,
  IconShield,
} from "../components/Icons";

type SevFilter = "all" | Severity;

const SOURCE_LABEL: Record<string, string> = {
  agent_config: "Agent 配置",
  mcp: "MCP",
  skill: "Skill",
  knowledge: "知识库",
  openclaw_audit: "OpenClaw 审计",
};

export interface ThreatListProps {
  findingId?: string;
  agentId?: string;
  severity?: Severity;
  category?: string;
  embedded?: boolean;
}

export function ThreatList({
  findingId,
  agentId,
  severity,
  category,
  embedded,
}: ThreatListProps) {
  const { snapshot } = useApp();

  const baseFindings = useMemo(() => {
    if (!snapshot) return [];
    return agentId ? exposureForAgent(snapshot, agentId) : snapshot.exposure_findings;
  }, [snapshot, agentId]);

  const agents = useMemo(() => {
    if (!snapshot) return [];
    const ids = new Map<string, string>();
    for (const f of baseFindings) {
      for (const id of f.agent_ids) {
        const name = snapshot.agents.find((a) => a.id === id)?.name || id;
        ids.set(id, name);
      }
    }
    return [...ids.entries()].map(([id, name]) => ({ id, name }));
  }, [baseFindings, snapshot]);

  const categories = useMemo(() => {
    const set = new Set<string>();
    for (const f of baseFindings) {
      if (f.category) set.add(f.category);
    }
    return [...set].sort();
  }, [baseFindings]);

  const [sevFilter, setSevFilter] = useState<SevFilter>(severity ?? "all");
  const [catFilter, setCatFilter] = useState(category ?? "all");
  const [agentFilter, setAgentFilter] = useState(agentId ?? "all");
  const [query, setQuery] = useState("");
  const [modalFinding, setModalFinding] = useState<ExposureFinding | null>(null);

  useEffect(() => {
    if (agentId) setAgentFilter(agentId);
  }, [agentId]);

  useEffect(() => {
    if (severity) setSevFilter(severity);
  }, [severity]);

  useEffect(() => {
    if (category) setCatFilter(category);
  }, [category]);

  useEffect(() => {
    if (!findingId || baseFindings.length === 0) return;
    const hit = baseFindings.find(
      (f) => exposureFindingKey(f) === findingId || f.id === findingId
    );
    if (hit) setModalFinding(hit);
  }, [findingId, baseFindings]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return baseFindings.filter((f) => {
      if (sevFilter !== "all" && f.severity !== sevFilter) return false;
      if (catFilter !== "all" && f.category !== catFilter) return false;
      if (!agentId && agentFilter !== "all" && !f.agent_ids.includes(agentFilter)) return false;
      if (q) {
        const hay = `${f.title} ${f.category} ${f.source} ${SOURCE_LABEL[f.source] || ""}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
  }, [baseFindings, sevFilter, catFilter, agentFilter, agentId, query]);

  const agentName = (id: string) =>
    snapshot?.agents.find((a) => a.id === id)?.name || id;

  const agentsLabel = (f: ExposureFinding) =>
    f.agent_ids.map((id) => agentName(id)).join("、");

  const openModal = (f: ExposureFinding) => setModalFinding(f);

  if (!snapshot) {
    return (
      <main className={embedded ? undefined : "main flush"}>
        <div className="muted" style={{ padding: embedded ? "24px 0" : undefined }}>
          暂无扫描结果，请先在「安全扫描」发起扫描。
        </div>
      </main>
    );
  }

  const body = (
    <>
      {!embedded && (
        <div className="page-title" style={{ fontSize: 20, marginBottom: 16 }}>
          威胁管理
        </div>
      )}
      {embedded && agentId && (
        <div className="dim" style={{ fontSize: 12.5, marginBottom: 12 }}>
          仅显示 {agentName(agentId)} 的威胁事件
        </div>
      )}

      <div className="dim" style={{ fontSize: 12.5, marginBottom: 14 }}>
        共 {baseFindings.length} 项威胁事件
        {filtered.length !== baseFindings.length && <> · 当前筛选 {filtered.length} 项</>}
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
          <select
            className="select-input cve-filter"
            value={catFilter}
            onChange={(e) => setCatFilter(e.target.value)}
          >
            <option value="all">全部类别</option>
            {categories.map((c) => (
              <option key={c} value={c}>
                {c}
              </option>
            ))}
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
            placeholder="搜索威胁标题、类别…"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
        </div>
      </div>

      <div className="card" style={{ padding: 0, overflow: "hidden" }}>
        {filtered.length === 0 ? (
          <div className="muted" style={{ padding: 48, textAlign: "center", fontSize: 13.5 }}>
            {baseFindings.length === 0 ? "暂无威胁事件。" : "没有符合筛选条件的威胁事件。"}
          </div>
        ) : (
          <table className="data-table cve-list-table">
            <thead>
              <tr>
                <th>威胁事件</th>
                <th style={{ width: 100 }}>风险等级</th>
                <th style={{ width: 120 }}>类别</th>
                <th style={{ width: 110 }}>来源</th>
                {!agentId && <th style={{ width: 130 }}>所属 Agent</th>}
                <th style={{ width: 72 }}>操作</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((f) => (
                <tr
                  key={exposureFindingKey(f)}
                  className="cve-list-row"
                  onClick={() => openModal(f)}
                >
                  <td>
                    <span className="row" style={{ gap: 8 }}>
                      <IconShield size={16} style={{ color: "var(--purple-2)", flexShrink: 0 }} />
                      <span style={{ fontWeight: 600 }}>{f.title}</span>
                    </span>
                  </td>
                  <td>
                    <SeverityPill sev={f.severity} />
                  </td>
                  <td className="muted">{f.category}</td>
                  <td className="dim" style={{ fontSize: 12.5 }}>
                    {SOURCE_LABEL[f.source] || f.source}
                  </td>
                  {!agentId && <td className="muted">{agentsLabel(f)}</td>}
                  <td>
                    <span className="act-link">查看</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {modalFinding && (
        <ThreatDetailModal
          finding={modalFinding}
          agentName={agentName}
          onClose={() => setModalFinding(null)}
        />
      )}
    </>
  );

  if (embedded) return <div className="threat-list-embedded">{body}</div>;
  return <main className="main flush">{body}</main>;
}

/** @deprecated 使用 ThreatList + threat-list 路由 */
export function ExposureDetail({ findingId }: { findingId?: string }) {
  return <ThreatList findingId={findingId} />;
}

function ThreatDetailModal({
  finding,
  agentName,
  onClose,
}: {
  finding: ExposureFinding;
  agentName: (id: string) => string;
  onClose: () => void;
}) {
  const locations =
    finding.locations?.length ? finding.locations : finding.location ? [finding.location] : [];

  return (
    <div className="modal-mask" onClick={onClose}>
      <div className="modal cve-detail-modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-head">
          <div className="row" style={{ gap: 10, minWidth: 0 }}>
            <IconShield size={20} style={{ color: "var(--purple-2)", flexShrink: 0 }} />
            <div className="modal-title" style={{ minWidth: 0 }}>
              {finding.title}
            </div>
            <SeverityPill sev={finding.severity} />
          </div>
          <button className="modal-close" type="button" onClick={onClose}>
            ×
          </button>
        </div>

        <div className="row cve-modal-meta" style={{ gap: 28, flexWrap: "wrap" }}>
          <Meta label="类别" value={finding.category} />
          <Meta label="来源" value={SOURCE_LABEL[finding.source] || finding.source} />
          <Meta
            label="受影响 Agent"
            value={finding.agent_ids.map((id) => agentName(id)).join("、") || "—"}
          />
        </div>

        <div className="cve-modal-body">
          <div className="detail-block" style={{ marginTop: 0 }}>
            <div className="h">
              <IconAlert className="ic" size={16} /> 影响
            </div>
            <div className="muted" style={{ lineHeight: 1.8 }}>
              {finding.impact}
            </div>
          </div>

          <div className="detail-block">
            <div className="h">
              <IconFile className="ic" size={16} /> 证据
            </div>
            {locations.length > 1 && (
              <div style={{ marginBottom: 10 }}>
                <div className="dim" style={{ fontSize: 12, marginBottom: 6 }}>
                  命中位置（{locations.length}）
                </div>
                <ul style={{ margin: 0, paddingLeft: 18, lineHeight: 1.7 }}>
                  {locations.map((loc) => (
                    <li key={loc} className="mono" style={{ fontSize: 12.5 }}>
                      {loc}
                    </li>
                  ))}
                </ul>
              </div>
            )}
            <div className="evidence mono">{finding.evidence}</div>
          </div>

          <div className="detail-block">
            <div className="row">
              <div className="h" style={{ marginBottom: 0 }}>
                <IconShield className="ic" size={16} /> 推荐操作
              </div>
              <div className="spacer" />
              <button className="btn btn-primary btn-sm" type="button">
                <span className="row" style={{ gap: 6 }}>
                  查看修复指南 <IconExternal size={13} />
                </span>
              </button>
            </div>
            <div className="muted" style={{ lineHeight: 1.8, marginTop: 9 }}>
              {finding.recommendation}
            </div>
          </div>

          <div className="detail-block detail-block-plain">
            <div className="h">通俗说明（给普通用户）</div>
            <div className="plain-text">{finding.plain_explanation}</div>
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
