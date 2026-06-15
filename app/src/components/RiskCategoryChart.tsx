import React from "react";
import type { RiskCategoryRow } from "../selectors";

const SEV_COLOR: Record<string, string> = {
  high: "var(--high)",
  medium: "var(--med)",
  low: "var(--low)",
};

export function RiskCategoryChart({ rows }: { rows: RiskCategoryRow[] }) {
  if (rows.length === 0) {
    return (
      <div className="muted" style={{ fontSize: 13, padding: "24px 0", textAlign: "center" }}>
        暂无暴露面风险类别
      </div>
    );
  }

  const max = Math.max(...rows.map((r) => r.count), 1);

  return (
    <div className="risk-chart">
      {rows.map((row) => (
        <div key={row.category} className="risk-chart-row">
          <div className="risk-chart-label" title={row.category}>
            {row.category}
          </div>
          <div className="risk-chart-bar-wrap">
            <div
              className="risk-chart-bar"
              style={{
                width: `${(row.count / max) * 100}%`,
                background: SEV_COLOR[row.maxSeverity] || "var(--purple-2)",
              }}
            />
          </div>
          <div className="risk-chart-count">{row.count}</div>
        </div>
      ))}
    </div>
  );
}
