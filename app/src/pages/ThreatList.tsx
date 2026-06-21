import React, { useEffect, useMemo, useRef, useState } from "react";
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
  threatLocationLine,
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
  const { snapshot, ignoreThreat, unignoreThreat, readFile, lastError, clearError, t, layer } = useApp();

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
  const [fileView, setFileView] = useState<{
    path: string;
    content: string;
    truncated: boolean;
    highlightLine?: number;
  } | null>(null);
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
        const titleText = layer.threatTitle(f.id, f.title, f.category);
        const hay = `${titleText} ${f.title} ${f.category} ${layer.threatCategory(f.category)} ${f.source} ${layer.threatSource(f.source)}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
  }, [baseFindings, sevFilter, catFilter, agentFilter, agentId, query, snapshot, layer]);

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
    const highlightLine = threatLocationLine(path);
    setFileLoading(true);
    setFileError(null);
    setFileView(null);
    try {
      const res = await readFile(filePath);
      setFileView({ ...res, highlightLine });
    } catch (e: any) {
      setFileError(e?.message || t("threatList.fileReadError"));
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
          {t("common.empty.noScanResult")}
        </div>
      </main>
    );
  }

  const body = (
    <>
      {!embedded && (
        <div className="page-title" style={{ fontSize: 20, marginBottom: 16 }}>
          {t("threatList.title")}
        </div>
      )}
      {embedded && agentId && (
        <div className="dim" style={{ fontSize: 12.5, marginBottom: 12 }}>
          {t("threatList.agentScope", { name: agentName(agentId) })}
        </div>
      )}

      <div className="dim" style={{ fontSize: 12.5, marginBottom: 14 }}>
        {t("threatList.metaActive", { count: activeCount })}
        {whitelistedCount > 0 && <> · {t("threatList.metaWhitelisted", { count: whitelistedCount })}</>}
        {ignoredCount > whitelistedCount && <> · {t("threatList.metaIgnored", { count: ignoredCount - whitelistedCount })}</>}
        {filtered.length !== baseFindings.length && <> · {t("threatList.metaFiltered", { count: filtered.length })}</>}
      </div>

      <div className="card cve-toolbar" style={{ padding: "14px 16px", marginBottom: 14 }}>
        <div className="row" style={{ gap: 10, flexWrap: "wrap" }}>
          <select
            className="select-input cve-filter"
            value={sevFilter}
            onChange={(e) => setSevFilter(e.target.value as SevFilter)}
          >
            <option value="all">{t("common.filter.allRisk")}</option>
            <option value="high">{t("common.severity.high")}</option>
            <option value="medium">{t("common.severity.medium")}</option>
            <option value="low">{t("common.severity.low")}</option>
            <option value="safe">{t("common.filter.ignored")}</option>
          </select>
          <select
            className="select-input cve-filter"
            value={catFilter}
            onChange={(e) => setCatFilter(e.target.value)}
          >
            <option value="all">{t("common.filter.allCategory")}</option>
            {categories.map((c) => (
              <option key={c} value={c}>
                {layer.threatCategory(c)}
              </option>
            ))}
          </select>
          {!agentId && (
            <select
              className="select-input cve-filter"
              value={agentFilter}
              onChange={(e) => setAgentFilter(e.target.value)}
            >
              <option value="all">{t("common.filter.allAgent")}</option>
              {agents.map((a) => (
                <option key={a.id} value={a.id}>
                  {a.name}
                </option>
              ))}
            </select>
          )}
          <input
            className="text-input cve-search"
            placeholder={t("threatList.searchPlaceholder")}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
        </div>
      </div>

      <div className="card" style={{ padding: 0, overflow: "hidden" }}>
        {filtered.length === 0 ? (
          <div className="muted" style={{ padding: 48, textAlign: "center", fontSize: 13.5 }}>
            {baseFindings.length === 0 ? t("threatList.emptyNone") : t("threatList.emptyNoMatch")}
          </div>
        ) : (
          <table className="data-table cve-list-table">
            <thead>
              <tr>
                <th>{t("threatList.tableEvent")}</th>
                <th style={{ width: 100 }}>{t("common.table.riskLevel")}</th>
                <th style={{ width: 120 }}>{t("common.table.category")}</th>
                <th style={{ width: 110 }}>{t("common.table.source")}</th>
                {!agentId && <th style={{ width: 130 }}>{t("common.table.agent")}</th>}
                <th className="table-actions-col">{t("common.table.actions")}</th>
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
                      <span style={{ fontWeight: 600 }}>{layer.threatTitle(f.id, f.title, f.category)}</span>
                      {pathWhitelisted && <span className="tag tag-muted">{t("common.tag.whitelisted")}</span>}
                      {!pathWhitelisted && ignored && <span className="tag tag-muted">{t("common.tag.ignored")}</span>}
                    </span>
                  </td>
                  <td>
                    <SeverityPill sev={sev} />
                  </td>
                  <td className="muted">{layer.threatCategory(f.category)}</td>
                  <td className="dim" style={{ fontSize: 12.5 }}>
                    {layer.threatSource(f.source)}
                  </td>
                  {!agentId && <td className="muted">{agentsLabel(f)}</td>}
                  <td className="table-actions-cell" onClick={(e) => e.stopPropagation()}>
                    <div className="table-actions">
                      <span className="act-link act-view" onClick={() => openModal(f)}>
                        {t("common.action.view")}
                      </span>
                      {!ignored ? (
                        <span className="act-link act-ignore" onClick={() => setConfirmIgnore(f)}>
                          {t("common.action.ignore")}
                        </span>
                      ) : manuallyIgnored ? (
                        <span className="act-link act-restore" onClick={() => handleUnignore(f)}>
                          {t("common.action.restore")}
                        </span>
                      ) : null}
                    </div>
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
            title={t("threatList.ignoreTitle")}
            message={t("threatList.ignoreMessage", {
              title: layer.threatTitle(confirmIgnore.id, confirmIgnore.title, confirmIgnore.category),
            })}
            confirmLabel={t("threatList.ignoreConfirm")}
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
          highlightLine={fileView?.highlightLine}
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
  const { t, layer } = useApp();
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
              {layer.threatTitle(finding.id, finding.title, finding.category)}
            </div>
            <SeverityPill sev={sev} />
            {pathWhitelisted && <span className="tag tag-muted">{t("common.tag.whitelisted")}</span>}
            {!pathWhitelisted && ignored && <span className="tag tag-muted">{t("common.tag.ignored")}</span>}
          </div>
          <button className="modal-close" type="button" onClick={onClose}>
            ×
          </button>
        </div>

        <div className="row cve-modal-meta" style={{ gap: 28, flexWrap: "wrap" }}>
          <Meta label={t("common.table.category")} value={layer.threatCategory(finding.category)} />
          <Meta label={t("common.table.source")} value={layer.threatSource(finding.source)} />
          <Meta
            label={t("threatList.affectedAgents")}
            value={finding.agent_ids.map((id) => agentName(id)).join(layer.listSeparator()) || "—"}
          />
        </div>

        <div className="cve-modal-body">
          <div className="detail-block" style={{ marginTop: 0 }}>
            <div className="h">
              <IconAlert className="ic" size={16} /> {t("threatList.impact")}
            </div>
            <div className="muted" style={{ lineHeight: 1.8 }}>
              {layer.threatImpact(finding.category, finding.impact)}
            </div>
          </div>

          <div className="detail-block">
            <div className="h">
              <IconFile className="ic" size={16} /> {t("threatList.evidence")}
            </div>
            {locations.length > 0 && (
              <div style={{ marginBottom: 10 }}>
                <div className="dim" style={{ fontSize: 12, marginBottom: 6 }}>
                  {locations.length > 1
                    ? t("threatList.hitLocationCount", { count: locations.length })
                    : t("threatList.hitLocation")}
                </div>
                <ul className="threat-location-list">
                  {locations.map((loc) => (
                    <li key={loc}>
                      <button
                        type="button"
                        className="threat-location-link mono"
                        onClick={() => onOpenFile(loc)}
                        title={t("threatList.viewOriginal")}
                      >
                        {loc}
                        <IconExternal size={12} />
                      </button>
                    </li>
                  ))}
                </ul>
              </div>
            )}
            <div className="evidence mono">{layer.threatEvidence(finding.evidence)}</div>
          </div>

          <div className="detail-block">
            <div className="h">
              <IconShield className="ic" size={16} /> {t("threatList.recommendation")}
            </div>
            <div className="muted" style={{ lineHeight: 1.8, marginTop: 9 }}>
              {layer.threatRecommendation(finding.category, finding.recommendation)}
            </div>
          </div>

        </div>

        <div className="modal-foot threat-modal-foot">
          {!ignored ? (
            <button type="button" className="btn btn-sm btn-danger" onClick={onIgnore}>
              {t("threatList.ignoreThreat")}
            </button>
          ) : manuallyIgnored ? (
            <button type="button" className="btn btn-sm btn-success" onClick={onUnignore}>
              {t("threatList.unignore")}
            </button>
          ) : (
            <span className="dim" style={{ fontSize: 12.5 }}>
              {t("threatList.autoWhitelisted")}
            </span>
          )}
          <div className="spacer" />
          <button type="button" className="btn btn-primary btn-sm" onClick={onClose}>
            {t("common.action.close")}
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
  highlightLine,
  loading,
  error,
  onClose,
}: {
  path?: string;
  content?: string;
  truncated?: boolean;
  highlightLine?: number;
  loading: boolean;
  error?: string | null;
  onClose: () => void;
}) {
  const { t } = useApp();
  const bodyRef = useRef<HTMLDivElement>(null);
  const lines = useMemo(() => (content != null ? content.split("\n") : []), [content]);

  useEffect(() => {
    if (!highlightLine || !bodyRef.current) return;
    const row = bodyRef.current.querySelector(`[data-line="${highlightLine}"]`);
    row?.scrollIntoView({ block: "center" });
  }, [content, highlightLine]);

  return (
    <div className="modal-mask" style={{ zIndex: 60 }} onClick={onClose}>
      <div className="modal modal-lg file-content-modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-head">
          <div className="modal-title" style={{ fontSize: 15 }}>
            {t("threatList.fileTitle")}
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
        {loading && <div className="muted" style={{ padding: "24px 0" }}>{t("threatList.fileLoading")}</div>}
        {error && !loading && (
          <div className="muted" style={{ padding: "24px 0", color: "var(--high)" }}>{error}</div>
        )}
        {content != null && !loading && (
          <>
            {truncated && (
              <div className="dim" style={{ fontSize: 12, marginBottom: 8 }}>
                {t("threatList.fileTruncated")}
              </div>
            )}
            <div ref={bodyRef} className="evidence mono file-content-body file-content-lines">
              {lines.map((line, i) => {
                const lineNum = i + 1;
                const highlighted = highlightLine === lineNum;
                return (
                  <div
                    key={lineNum}
                    className={`file-content-line${highlighted ? " is-highlight" : ""}`}
                    data-line={lineNum}
                  >
                    <span className="file-content-ln">{lineNum}</span>
                    <span className="file-content-text">{line || " "}</span>
                  </div>
                );
              })}
            </div>
          </>
        )}
        <div className="modal-foot">
          <button type="button" className="btn btn-primary btn-sm" onClick={onClose}>
            {t("common.action.close")}
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
