import React from "react";
import type { Severity } from "../types";
import { useApp } from "../store";
import { IconAlert, IconCheck } from "./Icons";

/** @deprecated Use useSeverityLabels() — kept as non-React fallback */
export const SEV_LABEL: Record<Severity, string> = {
  high: "高危",
  medium: "中危",
  low: "低危",
  safe: "安全",
  info: "信息",
};

/** @deprecated Use useSeverityLabels() — kept as non-React fallback */
export const SEV_RISK_LABEL: Record<Severity, string> = {
  high: "高风险",
  medium: "中风险",
  low: "低风险",
  safe: "安全",
  info: "信息",
};

export function useSeverityLabels() {
  const { t } = useApp();
  return {
    label: (sev: Severity) => t(`common.severity.${sev}`),
    risk: (sev: Severity) => t(`common.risk.${sev}`),
  };
}

export function SeverityPill({
  sev,
  label,
}: {
  sev: Severity;
  label?: string;
}) {
  const { label: sevLabel } = useSeverityLabels();
  return <span className={`sev sev-${sev}`}>{label ?? sevLabel(sev)}</span>;
}

export function SeverityDot({ sev }: { sev: Severity }) {
  const color =
    sev === "high"
      ? "var(--high)"
      : sev === "medium"
      ? "var(--med)"
      : sev === "low"
      ? "var(--low)"
      : "var(--safe)";
  if (sev === "safe")
    return <IconCheck size={16} style={{ color }} />;
  return <IconAlert size={16} style={{ color }} />;
}

export function Section({
  title,
  right,
  children,
  style,
}: {
  title: string;
  right?: React.ReactNode;
  children: React.ReactNode;
  style?: React.CSSProperties;
}) {
  return (
    <div className="card" style={{ padding: 18, ...style }}>
      <div className="row" style={{ marginBottom: 14 }}>
        <div style={{ fontSize: 15, fontWeight: 700 }}>{title}</div>
        <div className="spacer" />
        {right}
      </div>
      {children}
    </div>
  );
}

export function ConfirmModal({
  title,
  message,
  confirmLabel,
  danger,
  onConfirm,
  onCancel,
}: {
  title: string;
  message: string;
  confirmLabel: string;
  danger?: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}) {
  const { t } = useApp();
  return (
    <div className="modal-mask confirm-modal-mask" onClick={onCancel}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-head">
          <div className="modal-title">{title}</div>
          <button className="modal-close" onClick={onCancel}>
            ×
          </button>
        </div>
        <div className="muted" style={{ fontSize: 13.5, lineHeight: 1.7 }}>
          {message}
        </div>
        <div className="modal-foot">
          <button className="btn" onClick={onCancel}>
            {t("common.action.cancel")}
          </button>
          <button
            className={danger ? "btn btn-primary" : "btn btn-primary"}
            style={danger ? { background: "linear-gradient(135deg,#f0506e,#b91c4a)", boxShadow: "0 6px 24px rgba(240,80,110,0.35)" } : undefined}
            onClick={onConfirm}
          >
            {confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
}
