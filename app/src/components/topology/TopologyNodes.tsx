import React from "react";
import { Handle, Position, type NodeProps } from "reactflow";
import { useApp } from "../../store";
import type { TopoNode } from "./topologyBuilder";

function nodeBackground(hex?: string): string {
  const h = hex && /^#[0-9A-Fa-f]{6}$/.test(hex) ? hex : "#6366F1";
  const r = parseInt(h.slice(1, 3), 16);
  const g = parseInt(h.slice(3, 5), 16);
  const b = parseInt(h.slice(5, 7), 16);
  const baseR = 20, baseG = 22, baseB = 38;
  const mix = 0.22;
  const mr = Math.round(baseR + (r - baseR) * mix);
  const mg = Math.round(baseG + (g - baseG) * mix);
  const mb = Math.round(baseB + (b - baseB) * mix);
  return `rgb(${mr}, ${mg}, ${mb})`;
}

/** @deprecated 兼容旧引用，与 nodeBackground 相同 */
const hexToBg = nodeBackground;

/* Agent */
export const AgentNode = ({ id, data }: NodeProps<TopoNode>) => {
  const { label, color, icon } = data;
  return (
    <div data-topo-id={id} className="topo-node topo-agent" style={{ borderColor: color, background: nodeBackground(color), width: 184, height: 64 }}>
      <Handle type="target" position={Position.Top} id="top" className="topo-handle" />
      <Handle type="target" position={Position.Left} id="left" className="topo-handle" />
      <Handle type="target" position={Position.Right} id="target-right" className="topo-handle" />
      <Handle type="target" position={Position.Bottom} id="target-bottom" className="topo-handle" />
      <Handle type="source" position={Position.Right} id="right" className="topo-handle" />
      <Handle type="source" position={Position.Bottom} id="bottom" className="topo-handle" />
      {icon && <img src={icon} className="topo-node-icon" alt="" />}
      <span className="topo-label">{label}</span>
    </div>
  );
};

/* Category（含组件节点：用 category 类型注册以兼容 ReactFlow 点击事件） */
export const CategoryNode = ({ id, data }: NodeProps<TopoNode>) => {
  const { label, color, count, icon, type } = data;
  const isComponent = type === "component";
  const bg = nodeBackground(color);

  if (isComponent) {
    return (
      <div data-topo-id={id} className="topo-node topo-component" style={{ borderColor: color, background: bg, width: 164, height: 50 }}>
        <Handle type="target" position={Position.Top} id="top" className="topo-handle" />
        <Handle type="source" position={Position.Bottom} id="bottom" className="topo-handle" />
        <div className="topo-category-body">
          {icon && <img src={icon} className="topo-cat-icon" alt="" />}
          <div className="topo-comp-text">
            <span className="topo-label">{label}</span>
            {count != null && <span className="topo-count">×{count}</span>}
          </div>
        </div>
      </div>
    );
  }

  return (
    <div data-topo-id={id} className="topo-node topo-category" style={{ borderColor: color, background: bg, width: 164, height: 50 }}>
      <Handle type="source" position={Position.Top} id="top" className="topo-handle" />
      <Handle type="source" position={Position.Right} id="right" className="topo-handle" />
      <Handle type="source" position={Position.Bottom} id="bottom" className="topo-handle" />
      <Handle type="source" position={Position.Left} id="left" className="topo-handle" />
      <Handle type="target" position={Position.Top} id="target-top" className="topo-handle" />
      <Handle type="target" position={Position.Right} id="target-right" className="topo-handle" />
      <Handle type="target" position={Position.Bottom} id="target-bottom" className="topo-handle" />
      <Handle type="target" position={Position.Left} id="target-left" className="topo-handle" />
      <div className="topo-category-body">
        {icon && <img src={icon} className="topo-cat-icon" alt="" />}
        <span className="topo-label">{label}</span>
        {count != null && <span className="topo-count">×{count}</span>}
      </div>
    </div>
  );
};

/* Risk */
export const RiskNode = ({ id, data }: NodeProps<TopoNode>) => {
  const { t } = useApp();
  const { label, color, count, threatHigh, threatMed, icon } = data;
  return (
    <div data-topo-id={id} className="topo-node topo-risk" style={{ borderColor: color, background: nodeBackground(color), width: 172, height: 68 }}>
      <Handle type="target" position={Position.Top} id="top" className="topo-handle" />
      <Handle type="source" position={Position.Bottom} id="bottom" className="topo-handle" />
      <div className="topo-category-body">
        {icon && <img src={icon} className="topo-cat-icon" alt="" />}
        <span className="topo-label">{label}</span>
        {count != null && <span className="topo-count" style={{ color }}>×{count}</span>}
      </div>
      {(threatHigh != null || threatMed != null) && (
        <div className="topo-risk-tags">
          {threatHigh != null && threatHigh > 0 && (
            <span className="topo-risk-tag high">{threatHigh} {t("topology.severityHighShort")}</span>
          )}
          {threatMed != null && threatMed > 0 && (
            <span className="topo-risk-tag med">{threatMed} {t("topology.severityMedShort")}</span>
          )}
        </div>
      )}
    </div>
  );
};

/* Threat Item */
export const ThreatItemNode = ({ id, data }: NodeProps<TopoNode>) => {
  const { label, threatSeverity } = data;
  const sevColor = threatSeverity === "high" ? "#F87171" : threatSeverity === "medium" ? "#FB923C" : "#94A3B8";
  return (
    <div data-topo-id={id} className="topo-node topo-threat-item" style={{ borderColor: sevColor, width: 190, height: ITEM_H }}>
      <Handle type="target" position={Position.Top} id="top" className="topo-handle" />
      <span className="topo-threat-sev" style={{ color: sevColor }}>
        {threatSeverity === "high" ? "H" : threatSeverity === "medium" ? "M" : "L"}
      </span>
      <span className="topo-label topo-threat-label">{label}</span>
    </div>
  );
};

const ITEM_H = 32;

/* External */
export const ExternalNode = ({ id, data }: NodeProps<TopoNode>) => {
  const { label, color } = data;
  return (
    <div data-topo-id={id} className="topo-node topo-external" style={{ borderColor: color, background: `rgba(17,19,34,0.6)`, width: 160, height: 48 }}>
      <Handle type="target" position={Position.Top} id="top" className="topo-handle" />
      <span className="topo-label">{label}</span>
    </div>
  );
};

export const topoNodeTypes = {
  agent: AgentNode, category: CategoryNode,
  risk: RiskNode, threatItem: ThreatItemNode, external: ExternalNode,
};
