import React from "react";
import { useApp } from "../store";
import type { RiskCategoryRow } from "../selectors";

const SEV_COLOR: Record<string, string> = {
  high: "var(--high)",
  medium: "var(--med)",
  low: "var(--low)",
};

export function RiskCategoryChart({ rows }: { rows: RiskCategoryRow[] }) {
  const { t, layer } = useApp();

  if (rows.length === 0) {
    return (
      <div className="muted" style={{ fontSize: 13, padding: "24px 0", textAlign: "center" }}>
        {t("data.riskChartEmpty")}
      </div>
    );
  }

  const max = Math.max(...rows.map((r) => r.count), 1);

  return (
    <div className="risk-chart">
      {rows.map((row) => {
        const label = layer.threatCategory(row.category);
        return (
          <div key={row.category} className="risk-chart-row">
            <div className="risk-chart-label" title={label}>
              {label}
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
        );
      })}
    </div>
  );
}
