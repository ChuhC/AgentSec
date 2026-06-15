import React, { useState } from "react";
import { useApp } from "../store";
import {
  IconCube,
  IconFolder,
  IconLayers,
  IconMonitor,
  IconScan,
  LogoMark,
  IconChevron,
} from "../components/Icons";

function ScanPathModal({
  onClose,
  onConfirm,
}: {
  onClose: () => void;
  onConfirm: (scope: string, path?: string) => void;
}) {
  const [mode, setMode] = useState<"all" | "custom">("all");
  const [path, setPath] = useState("");
  return (
    <div className="modal-mask" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-head">
          <div className="modal-title">扫描路径</div>
          <button className="modal-close" onClick={onClose}>
            ×
          </button>
        </div>
        <span className="tag" style={{ marginBottom: 16, display: "inline-block" }}>
          Step 1
        </span>
        <label className="radio-row" onClick={() => setMode("all")}>
          <span className={`radio ${mode === "all" ? "on" : ""}`} />
          本机全部
        </label>
        <label className="radio-row" onClick={() => setMode("custom")}>
          <span className={`radio ${mode === "custom" ? "on" : ""}`} />
          自定义路径
        </label>
        <div className="row" style={{ gap: 10, marginTop: 12 }}>
          <input
            className="text-input"
            placeholder="请选择扫描路径"
            value={path}
            disabled={mode === "all"}
            onChange={(e) => setPath(e.target.value)}
          />
          <button
            className="btn btn-sm"
            disabled={mode === "all"}
            onClick={() => setPath("/Users/me/agents")}
          >
            选择文件夹
          </button>
        </div>
        <div className="modal-foot">
          <button className="btn" onClick={onClose}>
            取消
          </button>
          <button
            className="btn btn-primary"
            onClick={() =>
              onConfirm(mode === "all" ? "本机全部" : "自定义路径", mode === "custom" ? path : undefined)
            }
          >
            确定
          </button>
        </div>
      </div>
    </div>
  );
}

export function ScanHome() {
  const { startScan, snapshot } = useApp();
  const [modal, setModal] = useState(false);
  const last = snapshot?.meta.finished_at || "-";

  return (
    <main className="main">
      <div
        className="glow-panel"
        style={{
          height: "100%",
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          justifyContent: "center",
          padding: 32,
        }}
      >
        <LogoMark size={92} />
        <div style={{ fontSize: 34, fontWeight: 700, marginTop: 6 }}>AgentSec</div>
        <h1 style={{ fontSize: 30, fontWeight: 800, marginTop: 22 }}>
          一键检查 Agent 安全风险
        </h1>

        <div className="row" style={{ gap: 48, marginTop: 40 }}>
          <ScopeTag
            icon={<IconMonitor size={22} />}
            title="基线配置"
            sub="检查系统配置与安全基线"
          />
          <ScopeTag
            icon={<IconCube size={22} />}
            title="组件漏洞"
            sub="检测 Agent 组件漏洞"
          />
          <ScopeTag
            icon={<IconLayers size={22} />}
            title="Agent 资产识别"
            sub="识别 Agent 及依赖资产"
          />
        </div>

        <div
          className="row"
          style={{ marginTop: 56, width: "100%", maxWidth: 760, gap: 24 }}
        >
          <span className="link" onClick={() => setModal(true)}>
            <IconFolder size={16} /> 扫描路径 <IconChevron size={14} />
          </span>
          <div className="spacer" />
          <button
            className="btn btn-primary"
            style={{ padding: "16px 48px", fontSize: 16, borderRadius: 14 }}
            onClick={() => startScan("本机全部")}
          >
            <span className="row" style={{ gap: 8 }}>
              <IconScan size={18} /> 开始扫描
            </span>
          </button>
          <div className="spacer" />
          <div style={{ textAlign: "right" }}>
            <div className="dim" style={{ fontSize: 12 }}>
              上次扫描
            </div>
            <div className="muted" style={{ fontSize: 13 }}>
              {last}
            </div>
          </div>
        </div>
      </div>

      {modal && (
        <ScanPathModal
          onClose={() => setModal(false)}
          onConfirm={(scope, path) => {
            setModal(false);
            startScan(scope, path);
          }}
        />
      )}
    </main>
  );
}

function ScopeTag({
  icon,
  title,
  sub,
}: {
  icon: React.ReactNode;
  title: string;
  sub: string;
}) {
  return (
    <div className="row" style={{ gap: 14 }}>
      <div
        className="row"
        style={{
          width: 46,
          height: 46,
          borderRadius: 12,
          background: "var(--purple-soft)",
          color: "var(--purple-2)",
          justifyContent: "center",
        }}
      >
        {icon}
      </div>
      <div>
        <div style={{ fontWeight: 700, fontSize: 15 }}>{title}</div>
        <div className="muted" style={{ fontSize: 12, marginTop: 3 }}>
          {sub}
        </div>
      </div>
    </div>
  );
}
