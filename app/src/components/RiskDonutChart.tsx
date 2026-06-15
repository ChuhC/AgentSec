import React from "react";
import type { RiskCategoryRow } from "../selectors";
import type { Severity } from "../types";

const SEV_COLOR: Record<Severity, string> = {
  high: "var(--high)",
  medium: "var(--med)",
  low: "var(--low)",
  info: "#60a5fa",
  safe: "var(--safe)",
};

const FALLBACK_COLORS = ["#a855f7", "#60a5fa", "#34d399", "#f59e0b", "#f472b6", "#94a3b8"];

export function RiskDonutChart({ rows }: { rows: RiskCategoryRow[] }) {
  if (rows.length === 0) {
    return (
      <div className="muted" style={{ fontSize: 13, padding: "24px 0", textAlign: "center" }}>
        暂无暴露面风险类别
      </div>
    );
  }

  const total = rows.reduce((s, r) => s + r.count, 0);
  const cx = 80;
  const cy = 80;
  const outerR = 68;
  const innerR = 44;
  let angle = -Math.PI / 2;

  const segments = rows.map((row, i) => {
    const slice = (row.count / total) * Math.PI * 2;
    const x1o = cx + outerR * Math.cos(angle);
    const y1o = cy + outerR * Math.sin(angle);
    const x2o = cx + outerR * Math.cos(angle + slice);
    const y2o = cy + outerR * Math.sin(angle + slice);
    const x1i = cx + innerR * Math.cos(angle + slice);
    const y1i = cy + innerR * Math.sin(angle + slice);
    const x2i = cx + innerR * Math.cos(angle);
    const y2i = cy + innerR * Math.sin(angle);
    const large = slice > Math.PI ? 1 : 0;
    const d = [
      `M ${x1o} ${y1o}`,
      `A ${outerR} ${outerR} 0 ${large} 1 ${x2o} ${y2o}`,
      `L ${x1i} ${y1i}`,
      `A ${innerR} ${innerR} 0 ${large} 0 ${x2i} ${y2i}`,
      "Z",
    ].join(" ");
    const color = SEV_COLOR[row.maxSeverity] || FALLBACK_COLORS[i % FALLBACK_COLORS.length];
    angle += slice;
    return { row, d, color };
  });

  return (
    <div className="risk-donut-wrap">
      <div className="risk-donut-chart">
        <svg viewBox="0 0 160 160" width={160} height={160}>
          {segments.map((seg) => (
            <path key={seg.row.category} d={seg.d} fill={seg.color} opacity={0.92} />
          ))}
          <text x={cx} y={cy - 6} textAnchor="middle" fontSize="22" fontWeight="800" fill="#fff">
            {total}
          </text>
          <text x={cx} y={cy + 14} textAnchor="middle" fontSize="11" fill="#a59fc0">
            风险项
          </text>
        </svg>
      </div>
      <div className="risk-donut-legend">
        {rows.map((row, i) => (
          <div key={row.category} className="risk-donut-legend-row">
            <span
              className="risk-donut-legend-dot"
              style={{
                background: SEV_COLOR[row.maxSeverity] || FALLBACK_COLORS[i % FALLBACK_COLORS.length],
              }}
            />
            <span className="risk-donut-legend-label" title={row.category}>
              {row.category}
            </span>
            <span className="risk-donut-legend-count">{row.count}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
