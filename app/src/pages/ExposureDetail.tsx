import React, { useState } from "react";
import { useApp } from "../store";
import { SeverityPill } from "../components/common";
import type { ExposureFinding } from "../types";
import {
  IconAlert,
  IconArrowLeft,
  IconExternal,
  IconFile,
  IconShield,
} from "../components/Icons";

export function ExposureDetail({ findingId }: { findingId?: string }) {
  const { snapshot, navigate } = useApp();
  const findings = snapshot?.exposure_findings ?? [];
  const [sel, setSel] = useState<string>(
    findingId || findings[0]?.id || ""
  );
  const current: ExposureFinding | undefined =
    findings.find((f) => f.id === sel) || findings[0];

  const agentName = (id: string) =>
    snapshot?.agents.find((a) => a.id === id)?.name || id;
  const agentVer = (id: string) =>
    snapshot?.agents.find((a) => a.id === id)?.version || "";

  return (
    <main className="main flush">
      <div className="row" style={{ gap: 10, marginBottom: 16 }}>
        <span className="link" onClick={() => navigate({ name: "results" })}>
          <IconArrowLeft size={18} />
        </span>
        <span className="page-title" style={{ fontSize: 20 }}>
          暴露面与基线
        </span>
      </div>

      <div className="split">
        <div className="split-list card" style={{ padding: 14 }}>
          <div className="dim" style={{ fontSize: 12.5, marginBottom: 10, paddingLeft: 4 }}>
            基线检查项（{findings.length}）
          </div>
          {findings.map((f) => (
            <div
              key={f.id}
              className={`list-row ${current?.id === f.id ? "active" : ""}`}
              onClick={() => setSel(f.id)}
            >
              <SeverityPill sev={f.severity} />
              <div style={{ minWidth: 0 }}>
                <div style={{ fontSize: 13.5, fontWeight: 600 }}>{f.title}</div>
                <div className="dim" style={{ fontSize: 12 }}>
                  {f.category}
                </div>
              </div>
            </div>
          ))}
        </div>

        <div className="split-detail card" style={{ padding: 24 }}>
          {current && (
            <>
              <div className="row" style={{ gap: 10 }}>
                <span style={{ fontSize: 20, fontWeight: 700 }}>{current.title}</span>
                <SeverityPill sev={current.severity} />
              </div>
              <div className="muted" style={{ marginTop: 8, lineHeight: 1.7 }}>
                {current.impact}
              </div>

              <div className="detail-block" style={{ marginTop: 22 }}>
                <div className="h">
                  <IconAlert className="ic" size={16} /> 影响
                </div>
                <div className="muted" style={{ lineHeight: 1.8 }}>
                  {current.impact}
                </div>
              </div>

              <div className="detail-block">
                <div className="h">
                  <IconFile className="ic" size={16} /> 证据
                </div>
                <div className="evidence mono">{current.evidence}</div>
              </div>

              <div className="detail-block">
                <div className="h">
                  <IconShield className="ic" size={16} /> 受影响的 Agent
                </div>
                <div className="row" style={{ gap: 10, flexWrap: "wrap" }}>
                  {current.agent_ids.map((id) => (
                    <span key={id} className="row" style={{ gap: 7 }}>
                      <span
                        style={{
                          padding: "5px 12px",
                          borderRadius: 9,
                          background: "var(--bg-inset)",
                          fontSize: 13,
                        }}
                      >
                        {agentName(id)}
                        <span className="ver-badge" style={{ marginLeft: 8 }}>
                          {agentVer(id)}
                        </span>
                      </span>
                    </span>
                  ))}
                </div>
              </div>

              <div className="detail-block">
                <div className="row">
                  <div className="h" style={{ marginBottom: 0 }}>
                    <IconShield className="ic" size={16} /> 推荐操作
                  </div>
                  <div className="spacer" />
                  <button className="btn btn-primary btn-sm">
                    <span className="row" style={{ gap: 6 }}>
                      查看修复指南 <IconExternal size={13} />
                    </span>
                  </button>
                </div>
                <div className="muted" style={{ lineHeight: 1.8, marginTop: 9 }}>
                  {current.recommendation}
                </div>
              </div>

              <div
                className="detail-block"
                style={{
                  background: "var(--purple-soft)",
                  borderRadius: 12,
                  padding: 16,
                }}
              >
                <div className="h">通俗说明（给普通用户）</div>
                <div style={{ lineHeight: 1.8, color: "#d8d2ee" }}>
                  {current.plain_explanation}
                </div>
              </div>
            </>
          )}
        </div>
      </div>
    </main>
  );
}
