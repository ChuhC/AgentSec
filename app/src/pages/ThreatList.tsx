import React, { useEffect, useMemo, useState } from "react";
import { createPortal } from "react-dom";
import { useApp } from "../store";
import { ConfirmModal, SeverityPill } from "../components/common";
import {
  activeThreatCount,
  effectiveThreatSeverity,
  exposureFindingKey,
  exposureForAgent,
  isThreatIgnored,
  isThreatManuallyIgnored,
  isThreatPathWhitelisted,
  threatLocationPath,
} from "../selectors";
import type { ExposureFinding, ScanSnapshot, Severity } from "../types";
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
  const { snapshot, ignoreThreat, unignoreThreat, readFile, lastError, clearError } = useApp();

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
  const [confirmIgnore, setConfirmIgnore] = useState<ExposureFinding | null>(null);
  const [fileView, setFileView] = useState<{ path: string; content: string; truncated: boolean } | null>(null);
  const [fileLoading, setFileLoading] = useState(false);
  const [fileError, setFileError] = useState<string | null>(null);

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

  useEffect(() => {
    if (!modalFinding || !snapshot) return;
    const key = exposureFindingKey(modalFinding);
    const updated = baseFindings.find((f) => exposureFindingKey(f) === key);
    if (updated) setModalFinding(updated);
  }, [snapshot, baseFindings]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return baseFindings.filter((f) => {
      const sev = snapshot ? effectiveThreatSeverity(snapshot, f) : f.severity;
      if (sevFilter !== "all" && sev !== sevFilter) return false;
      if (catFilter !== "all" && f.category !== catFilter) return false;
      if (!agentId && agentFilter !== "all" && !f.agent_ids.includes(agentFilter)) return false;
      if (q) {
        const hay = `${f.title} ${f.category} ${f.source} ${SOURCE_LABEL[f.source] || ""}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
  }, [baseFindings, sevFilter, catFilter, agentFilter, agentId, query, snapshot]);

  const ignoredCount = useMemo(
    () => (snapshot ? baseFindings.filter((f) => isThreatIgnored(snapshot, f)).length : 0),
    [baseFindings, snapshot]
  );
  const whitelistedCount = useMemo(
    () => (snapshot ? baseFindings.filter((f) => isThreatPathWhitelisted(f)).length : 0),
    [baseFindings, snapshot]
  );

  const activeCount = snapshot ? activeThreatCount(snapshot, agentId) : baseFindings.length;

  const openFile = async (path: string) => {
    const filePath = threatLocationPath(path);
    setFileLoading(true);
    setFileError(null);
    setFileView(null);
    try {
      const res = await readFile(filePath);
      setFileView(res);
    } catch (e: any) {
      setFileError(e?.message || "无法读取文件");
    } finally {
      setFileLoading(false);
    }
  };

  const handleIgnore = async (f: ExposureFinding) => {
    await ignoreThreat(exposureFindingKey(f));
    setConfirmIgnore(null);
    if (modalFinding && exposureFindingKey(modalFinding) === exposureFindingKey(f)) {
      setModalFinding({ ...f });
    }
  };

  const handleUnignore = async (f: ExposureFinding) => {
    await unignoreThreat(exposureFindingKey(f));
  };

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
        共 {activeCount} 项待处理威胁
        {whitelistedCount > 0 && <> · {whitelistedCount} 项默认加白</>}
        {ignoredCount > whitelistedCount && <> · {ignoredCount - whitelistedCount} 项已忽略</>}
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
            <option value="safe">已忽略</option>
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
                <th style={{ width: 120 }}>操作</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((f) => {
                const key = exposureFindingKey(f);
                const pathWhitelisted = isThreatPathWhitelisted(f);
                const ignored = snapshot ? isThreatIgnored(snapshot, f) : false;
                const manuallyIgnored = snapshot ? isThreatManuallyIgnored(snapshot, f) : false;
                const sev = snapshot ? effectiveThreatSeverity(snapshot, f) : f.severity;
                return (
                <tr
                  key={key}
                  className="cve-list-row"
                  onClick={() => openModal(f)}
                >
                  <td>
                    <span className="row" style={{ gap: 8 }}>
                      <IconShield size={16} style={{ color: "var(--purple-2)", flexShrink: 0 }} />
                      <span style={{ fontWeight: 600 }}>{f.title}</span>
                      {pathWhitelisted && <span className="tag tag-muted">默认加白</span>}
                      {!pathWhitelisted && ignored && <span className="tag tag-muted">已忽略</span>}
                    </span>
                  </td>
                  <td>
                    <SeverityPill sev={sev} />
                  </td>
                  <td className="muted">{f.category}</td>
                  <td className="dim" style={{ fontSize: 12.5 }}>
                    {SOURCE_LABEL[f.source] || f.source}
                  </td>
                  {!agentId && <td className="muted">{agentsLabel(f)}</td>}
                  <td onClick={(e) => e.stopPropagation()}>
                    <span className="act-link" onClick={() => openModal(f)}>查看</span>
                    {!ignored ? (
                      <>
                        <span className="dim" style={{ margin: "0 6px" }}>|</span>
                        <span className="act-link dim" onClick={() => setConfirmIgnore(f)}>忽略</span>
                      </>
                    ) : manuallyIgnored ? (
                      <>
                        <span className="dim" style={{ margin: "0 6px" }}>|</span>
                        <span className="act-link" onClick={() => handleUnignore(f)}>恢复</span>
                      </>
                    ) : null}
                  </td>
                </tr>
              );})}
            </tbody>
          </table>
        )}
      </div>

      {modalFinding && snapshot && (
        <ThreatDetailModal
          finding={modalFinding}
          snapshot={snapshot}
          agentName={agentName}
          onClose={() => setModalFinding(null)}
          onIgnore={() => {
            setConfirmIgnore(modalFinding);
            setModalFinding(null);
          }}
          onUnignore={() => handleUnignore(modalFinding)}
          onOpenFile={openFile}
        />
      )}

      {confirmIgnore &&
        createPortal(
          <ConfirmModal
            title="忽略此威胁"
            message={`将「${confirmIgnore.title}」加入忽略列表，风险等级将标记为安全，概览统计会同步更新。`}
            confirmLabel="确认忽略"
            danger
            onConfirm={() => handleIgnore(confirmIgnore)}
            onCancel={() => setConfirmIgnore(null)}
          />,
          document.body
        )}

      {(fileView || fileLoading || fileError) && (
        <FileContentModal
          path={fileView?.path}
          content={fileView?.content}
          truncated={fileView?.truncated}
          loading={fileLoading}
          error={fileError || lastError}
          onClose={() => {
            setFileView(null);
            setFileError(null);
            clearError();
          }}
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
  snapshot,
  agentName,
  onClose,
  onIgnore,
  onUnignore,
  onOpenFile,
}: {
  finding: ExposureFinding;
  snapshot: ScanSnapshot;
  agentName: (id: string) => string;
  onClose: () => void;
  onIgnore: () => void;
  onUnignore: () => void;
  onOpenFile: (path: string) => void;
}) {
  const locations =
    finding.locations?.length ? finding.locations : finding.location ? [finding.location] : [];
  const pathWhitelisted = isThreatPathWhitelisted(finding);
  const ignored = isThreatIgnored(snapshot, finding);
  const manuallyIgnored = isThreatManuallyIgnored(snapshot, finding);
  const sev = effectiveThreatSeverity(snapshot, finding);

  return (
    <div className="modal-mask" onClick={onClose}>
      <div className="modal cve-detail-modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-head">
          <div className="row" style={{ gap: 10, minWidth: 0 }}>
            <IconShield size={20} style={{ color: "var(--purple-2)", flexShrink: 0 }} />
            <div className="modal-title" style={{ minWidth: 0 }}>
              {finding.title}
            </div>
            <SeverityPill sev={sev} />
            {pathWhitelisted && <span className="tag tag-muted">默认加白</span>}
            {!pathWhitelisted && ignored && <span className="tag tag-muted">已忽略</span>}
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
            {locations.length > 0 && (
              <div style={{ marginBottom: 10 }}>
                <div className="dim" style={{ fontSize: 12, marginBottom: 6 }}>
                  命中位置{locations.length > 1 ? `（${locations.length}）` : ""}
                </div>
                <ul className="threat-location-list">
                  {locations.map((loc) => (
                    <li key={loc}>
                      <button
                        type="button"
                        className="threat-location-link mono"
                        onClick={() => onOpenFile(loc)}
                        title="查看原文"
                      >
                        {loc}
                        <IconExternal size={12} />
                      </button>
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

        <div className="modal-foot threat-modal-foot">
          {!ignored ? (
            <button type="button" className="btn btn-sm" onClick={onIgnore}>
              忽略此威胁
            </button>
          ) : manuallyIgnored ? (
            <button type="button" className="btn btn-sm" onClick={onUnignore}>
              取消忽略
            </button>
          ) : (
            <span className="dim" style={{ fontSize: 12.5 }}>
              位于 red-teaming 目录，已默认加白
            </span>
          )}
          <div className="spacer" />
          <button type="button" className="btn btn-primary btn-sm" onClick={onClose}>
            关闭
          </button>
        </div>
      </div>
    </div>
  );
}

function FileContentModal({
  path,
  content,
  truncated,
  loading,
  error,
  onClose,
}: {
  path?: string;
  content?: string;
  truncated?: boolean;
  loading: boolean;
  error?: string | null;
  onClose: () => void;
}) {
  return (
    <div className="modal-mask" style={{ zIndex: 60 }} onClick={onClose}>
      <div className="modal modal-lg file-content-modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-head">
          <div className="modal-title" style={{ fontSize: 15 }}>
            原文查看
          </div>
          <button className="modal-close" type="button" onClick={onClose}>
            ×
          </button>
        </div>
        {path && (
          <div className="dim mono file-content-path" style={{ fontSize: 12, marginBottom: 12 }}>
            {path}
          </div>
        )}
        {loading && <div className="muted" style={{ padding: "24px 0" }}>正在读取…</div>}
        {error && !loading && (
          <div className="muted" style={{ padding: "24px 0", color: "var(--high)" }}>{error}</div>
        )}
        {content != null && !loading && (
          <>
            {truncated && (
              <div className="dim" style={{ fontSize: 12, marginBottom: 8 }}>
                文件较大，仅显示前 256KB
              </div>
            )}
            <pre className="evidence mono file-content-body">{content}</pre>
          </>
        )}
        <div className="modal-foot">
          <button type="button" className="btn btn-primary btn-sm" onClick={onClose}>
            关闭
          </button>
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
