import React, { useState } from "react";
import { useApp } from "../store";
import { SeverityPill } from "../components/common";
import type { CVEFinding } from "../types";
import {
  IconArrowLeft,
  IconChevron,
  IconCube,
  IconExternal,
  IconShield,
} from "../components/Icons";

export function ComponentDetail({ componentId }: { componentId?: string }) {
  const { snapshot, navigate } = useApp();
  const comps = snapshot?.cve_findings ?? [];
  const cveUnavailable = snapshot?.meta.cve_status === "unavailable";
  const [sel, setSel] = useState<string>(componentId || comps[0]?.id || "");
  const current: CVEFinding | undefined =
    comps.find((c) => c.id === sel) || comps[0];

  if (cveUnavailable) {
    return (
      <main className="main flush">
        <Header onBack={() => navigate({ name: "results" })} />
        <div className="card" style={{ padding: 40, textAlign: "center" }}>
          <div className="muted">CVE 检测不可用：组件漏洞检测需要联网，当前网络不可用。</div>
          <div className="dim" style={{ marginTop: 8, fontSize: 13 }}>
            暴露面与基线结果不受影响。
          </div>
        </div>
      </main>
    );
  }

  return (
    <main className="main flush">
      <Header onBack={() => navigate({ name: "results" })} />
      <div className="split">
        <div className="split-list card" style={{ padding: 14 }}>
          <div className="dim" style={{ fontSize: 12.5, margin: "2px 4px 10px" }}>
            组件名称 · 共 {comps.length} 项
          </div>
          {comps.map((c) => (
            <div
              key={c.id}
              className={`list-row ${current?.id === c.id ? "active" : ""}`}
              onClick={() => setSel(c.id)}
            >
              <span style={{ color: "var(--purple-2)" }}>
                <IconCube size={18} />
              </span>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ fontSize: 13.5, fontWeight: 600 }}>{c.component}</div>
              </div>
              <SeverityPill sev={c.severity} />
              <span className="dim" style={{ width: 22, textAlign: "right" }}>
                {c.cves.length}
              </span>
              <IconChevron size={14} className="dim" />
            </div>
          ))}
        </div>

        <div className="split-detail card" style={{ padding: 24 }}>
          {current && (
            <>
              <div className="row" style={{ gap: 10 }}>
                <span style={{ color: "var(--purple-2)" }}>
                  <IconCube size={22} />
                </span>
                <span style={{ fontSize: 20, fontWeight: 700 }}>{current.component}</span>
                <SeverityPill sev={current.severity} />
              </div>

              <div
                className="row"
                style={{ gap: 40, marginTop: 18, flexWrap: "wrap" }}
              >
                <Meta label="当前版本" value={current.current_version} />
                <Meta label="最新安全版本" value={current.fixed_version || "—"} />
                <Meta label="组件类型" value={current.component_type} />
                <Meta label="首次发现" value={current.first_seen} />
              </div>

              <div style={{ fontWeight: 700, margin: "26px 0 8px" }}>
                CVE 漏洞列表（{current.cves.length}）
              </div>
              <table className="data-table">
                <thead>
                  <tr>
                    <th style={{ width: 160 }}>CVE 编号</th>
                    <th style={{ width: 90 }}>风险等级</th>
                    <th style={{ width: 90 }}>CVSS 评分</th>
                    <th>简要描述</th>
                  </tr>
                </thead>
                <tbody>
                  {current.cves.map((v) => (
                    <tr key={v.cve_id}>
                      <td className="mono">{v.cve_id}</td>
                      <td>
                        <SeverityPill sev={v.severity} />
                      </td>
                      <td style={{ fontWeight: 700 }}>{v.cvss.toFixed(1)}</td>
                      <td className="muted">{v.summary}</td>
                    </tr>
                  ))}
                  {current.cves.length === 0 && (
                    <tr>
                      <td colSpan={4} className="dim" style={{ textAlign: "center" }}>
                        暂无已知漏洞
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>

              <div
                className="detail-block"
                style={{
                  marginTop: 24,
                  background: "var(--bg-inset)",
                  borderRadius: 12,
                  padding: 16,
                }}
              >
                <div className="row">
                  <div className="h" style={{ marginBottom: 0 }}>
                    <IconShield className="ic" size={16} /> 升级建议
                  </div>
                  <div className="spacer" />
                  {current.fixed_version && (
                    <button className="btn btn-primary btn-sm">
                      <span className="row" style={{ gap: 6 }}>
                        查看升级指南 <IconExternal size={13} />
                      </span>
                    </button>
                  )}
                </div>
                <div className="muted" style={{ marginTop: 9, lineHeight: 1.8 }}>
                  {current.upgrade_advice}
                </div>
              </div>
            </>
          )}
        </div>
      </div>
    </main>
  );
}

function Header({ onBack }: { onBack: () => void }) {
  return (
    <div className="row" style={{ gap: 10, marginBottom: 16 }}>
      <span className="link" onClick={onBack}>
        <IconArrowLeft size={18} />
      </span>
      <span className="page-title" style={{ fontSize: 20 }}>
        组件漏洞
      </span>
    </div>
  );
}

function Meta({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <div className="dim" style={{ fontSize: 12 }}>
        {label}
      </div>
      <div style={{ fontSize: 15, fontWeight: 600, marginTop: 3 }}>{value}</div>
    </div>
  );
}
