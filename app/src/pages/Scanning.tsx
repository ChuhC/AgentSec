import React from "react";
import { useApp } from "../store";
import { IconFile, IconScan, IconShield } from "../components/Icons";

function Ring({ percent }: { percent: number }) {
  const r = 92;
  const c = 2 * Math.PI * r;
  const done = percent >= 100;
  const shown = Math.min(100, Math.max(0, Math.round(percent)));
  const off = done ? 0 : c * (1 - shown / 100);
  return (
    <svg width="220" height="220" viewBox="0 0 220 220">
      <circle cx="110" cy="110" r={r} fill="none" stroke="rgba(255,255,255,0.07)" strokeWidth="12" />
      <circle
        cx="110"
        cy="110"
        r={r}
        fill="none"
        stroke="url(#pg)"
        strokeWidth="12"
        strokeLinecap={done ? "butt" : "round"}
        strokeDasharray={done ? undefined : c}
        strokeDashoffset={done ? undefined : off}
        transform="rotate(-90 110 110)"
        style={{ transition: "stroke-dashoffset 0.4s ease" }}
      />
      <defs>
        <linearGradient id="pg" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stopColor="#8b5cf6" />
          <stop offset="1" stopColor="#c084fc" />
        </linearGradient>
      </defs>
      <text x="110" y="104" textAnchor="middle" fontSize="46" fontWeight="800" fill="#fff">
        {shown}%
      </text>
      <text x="110" y="134" textAnchor="middle" fontSize="14" fill="#a59fc0">
        {done ? "完成" : shown > 0 ? "扫描中..." : "准备中..."}
      </text>
    </svg>
  );
}

export function Scanning() {
  const { progress, cancelScan, scanState } = useApp();
  const percent = progress?.percent ?? 0;
  const stage = progress?.stage ?? "";
  const hasProgress = progress != null;
  const cancelling = scanState === "cancelling";

  // 三阶段状态（无进度事件前全部等待，避免误显示「进行中」）
  const stageState = (key: string): "done" | "active" | "wait" => {
    if (!hasProgress) return "wait";
    const order = ["discovery", "exposure", "cve", "report", "done"];
    const cur = order.indexOf(stage);
    if (key === "discovery") return cur > 0 ? "done" : "active";
    if (key === "vuln") return cur > 2 ? "done" : cur >= 1 ? "active" : "wait";
    return cur >= 3 ? "active" : "wait";
  };

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
        <div style={{ fontSize: 24, fontWeight: 800 }}>正在扫描</div>
        <div style={{ margin: "18px 0 8px" }}>
          <Ring percent={percent} />
        </div>

        <div className="row" style={{ gap: 56, marginTop: 18 }}>
          <StageNode
            icon={<IconScan size={20} />}
            title="资产发现"
            state={stageState("discovery")}
          />
          <Dashes />
          <StageNode
            icon={<IconShield size={20} />}
            title="威胁检测"
            state={stageState("vuln")}
          />
          <Dashes />
          <StageNode
            icon={<IconFile size={20} />}
            title="结果分析"
            state={stageState("report")}
          />
        </div>

        <button
          className="btn btn-ghost"
          style={{ marginTop: 44, padding: "12px 40px" }}
          disabled={cancelling}
          onClick={cancelScan}
        >
          {cancelling ? "正在取消…" : "取消扫描"}
        </button>
      </div>
    </main>
  );
}

function Dashes() {
  return (
    <div
      style={{
        width: 90,
        borderTop: "2px dashed rgba(168,85,247,0.4)",
        marginBottom: 28,
      }}
    />
  );
}

function StageNode({
  icon,
  title,
  state,
}: {
  icon: React.ReactNode;
  title: string;
  state: "done" | "active" | "wait";
}) {
  const color =
    state === "wait" ? "var(--text-3)" : "var(--purple-2)";
  const label =
    state === "done" ? "已完成" : state === "active" ? "进行中" : "等待中";
  return (
    <div style={{ textAlign: "center" }}>
      <div
        className="row"
        style={{
          width: 56,
          height: 56,
          borderRadius: "50%",
          justifyContent: "center",
          margin: "0 auto",
          color,
          background: state === "wait" ? "rgba(255,255,255,0.04)" : "var(--purple-soft)",
          boxShadow: state === "active" ? "0 0 0 4px rgba(139,92,246,0.15)" : "none",
        }}
      >
        {icon}
      </div>
      <div style={{ marginTop: 10, fontWeight: 700, fontSize: 14 }}>{title}</div>
      <div
        style={{
          fontSize: 12,
          marginTop: 3,
          color: state === "active" ? "var(--purple-2)" : "var(--text-3)",
        }}
      >
        {label}
      </div>
    </div>
  );
}
