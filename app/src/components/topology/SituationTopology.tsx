import React, { useMemo, useCallback, useRef } from "react";
import ReactFlow, { type Edge, type Node, Controls } from "reactflow";
import "reactflow/dist/style.css";
import type { ScanSnapshot } from "../../types";
import { buildTopology, type TopoNode } from "./topologyBuilder";
import { topoNodeTypes } from "./TopologyNodes";
import "./topology.css";

interface LayoutPos { x: number; y: number; }

const LAYOUT: Record<string, LayoutPos> = {
  agent:               { x: 420, y: 340 },
  "cat:mcp":           { x: 130, y: 210 },
  "cat:skill":         { x: 130, y: 440 },
  "cat:knowledge":     { x: 420, y: 150 },
  "cat:channel":       { x: 710, y: 340 },
  "cat:hook":          { x: 130, y: 340 },
  "cat:dependency":    { x: 340, y: 620 },
  "risk:threat-mcp":   { x: 130, y: 290 },
  "risk:threat-skill": { x: 130, y: 530 },
  "risk:threat-agent": { x: 580, y: 530 },
  "risk:cve":          { x: 340, y: 720 },
  "cat:perm-agent":       { x: 620, y: 450 },
  "cat:perm-cat:mcp":     { x: -90, y: 210 },
  "cat:perm-cat:skill":   { x: -90, y: 440 },
  "cat:perm-cat:hook":    { x: -90, y: 340 },
  "cat:perm-cat:knowledge": { x: 620, y: 150 },
  "cat:perm-cat:channel": { x: 710, y: 440 },
};

type NavigateTarget = {
  tab: "权限管理" | "威胁管理" | "漏洞管理" | "资产管理";
  permSource?: string;
  assetSubTab?: string;
};

function centerToPos(cx: number, cy: number, w: number, h: number) {
  return { x: cx - w / 2, y: cy - h / 2 };
}

function nodeSize(n: TopoNode): { w: number; h: number } {
  switch (n.type) {
    case "agent":     return { w: 184, h: 64 };
    case "category":  return { w: 164, h: 50 };
    case "component": return { w: 164, h: 72 };
    case "risk":      return { w: 172, h: 68 };
    case "external":  return { w: 160, h: 48 };
    default:          return { w: 160, h: 48 };
  }
}

const PERM_NODE_TO_SOURCE: Record<string, string> = {
  agent: "agent_default",
  "cat:mcp": "mcp",
  "cat:skill": "skill",
  "cat:hook": "hook",
  "cat:knowledge": "knowledge",
  "cat:channel": "channel",
};

export function navigateTopoNode(id: string, onNavigate: (target: NavigateTarget) => void) {
  if (id === "cat:dependency") {
    onNavigate({ tab: "资产管理", assetSubTab: "依赖" });
    return;
  }
  if (id === "risk:cve") {
    onNavigate({ tab: "漏洞管理" });
    return;
  }
  if (id.startsWith("risk:threat-")) {
    onNavigate({ tab: "威胁管理" });
    return;
  }
  if (id.startsWith("cat:perm-")) {
    const raw = id.slice("cat:perm-".length);
    onNavigate({ tab: "权限管理", permSource: PERM_NODE_TO_SOURCE[raw] ?? "agent_default" });
    return;
  }
  const assetTabs: Record<string, string> = {
    "cat:mcp": "MCP", "cat:skill": "Skills", "cat:knowledge": "知识库",
    "cat:hook": "Hooks", "cat:channel": "通道",
  };
  if (assetTabs[id]) {
    onNavigate({ tab: "资产管理", assetSubTab: assetTabs[id] });
  }
}

interface SituationTopologyProps {
  agentId: string; agentLabel: string; snapshot: ScanSnapshot;
  onNavigate?: (target: NavigateTarget) => void;
}

export function SituationTopology({ agentId, agentLabel, snapshot, onNavigate }: SituationTopologyProps) {
  const topo = useMemo(() => buildTopology(snapshot, agentId, agentLabel), [snapshot, agentId, agentLabel]);

  const visibleNodeIds = useMemo(() => new Set(topo.nodes.map((n) => n.id)), [topo.nodes]);
  const visibleEdges = useMemo(() => {
    return topo.edges.filter((e) => visibleNodeIds.has(e.source) && visibleNodeIds.has(e.target));
  }, [topo.edges, visibleNodeIds]);

  const nodes = useMemo(() => {
    return topo.nodes.map((n) => {
      let cx: number, cy: number;
      if (n.id.startsWith("cat:perm-")) {
        cx = LAYOUT[n.id]?.x ?? 520;
        cy = LAYOUT[n.id]?.y ?? 440;
      } else {
        cx = LAYOUT[n.id]?.x ?? 520;
        cy = LAYOUT[n.id]?.y ?? 340;
      }
      const { w, h } = nodeSize(n);
      const rfType = n.type === "component" ? "category" : n.type;
      return {
        id: n.id,
        type: rfType,
        position: centerToPos(cx, cy, w, h),
        data: n,
        draggable: false,
        selectable: false,
        zIndex: n.id === "cat:dependency" ? 20 : 0,
      } as Node;
    });
  }, [topo.nodes]);

  const edges: Edge[] = useMemo(() => {
    return visibleEdges.map((e) => {
      const isRisk = e.risk;
      const c = isRisk ? "#FB7185" : "#818CF8";
      return {
        id: e.id, source: e.source, target: e.target,
        sourceHandle: e.sourceHandle ?? undefined, targetHandle: e.targetHandle ?? undefined,
        type: "smoothstep",
        animated: isRisk,
        interactionWidth: 0,
        style: {
          stroke: c,
          strokeWidth: isRisk ? 1.4 : 1.6,
          strokeDasharray: e.dashed ? "6 5" : undefined,
          opacity: isRisk ? 0.75 : 0.5,
          filter: isRisk ? "drop-shadow(0 0 4px rgba(251,113,133,0.35))" : "drop-shadow(0 0 3px rgba(129,140,248,0.18))",
        },
      };
    });
  }, [visibleEdges]);

  // 容器级点击委托：通过 data-topo-id 识别节点，避免 ReactFlow 内部层拦截
  const pointerDown = useRef<{ x: number; y: number } | null>(null);

  const handlePointerDown = useCallback((e: React.PointerEvent) => {
    pointerDown.current = { x: e.clientX, y: e.clientY };
  }, []);

  const handleContainerClick = useCallback((e: React.MouseEvent) => {
    if ((e.target as HTMLElement).closest(".react-flow__controls, .topo-toolbar")) return;
    if (pointerDown.current) {
      const dx = e.clientX - pointerDown.current.x;
      const dy = e.clientY - pointerDown.current.y;
      if (dx * dx + dy * dy > 25) return; // 移动超过 5px 视为拖拽，不跳转
    }
    const nodeEl = (e.target as HTMLElement).closest("[data-topo-id]");
    if (!nodeEl || !onNavigate) return;
    const id = nodeEl.getAttribute("data-topo-id");
    if (id) navigateTopoNode(id, onNavigate);
  }, [onNavigate]);

  return (
    <div className="topo-container" onPointerDown={handlePointerDown} onClick={handleContainerClick}>
      <div className="topo-toolbar">
        <span className="topo-toolbar-title">态势拓扑</span>
        <span className="topo-toolbar-sep" />
        <span className="topo-toolbar-agent">{agentLabel}</span>
        <span className="topo-toolbar-hint">拖拽平移 · 滚轮缩放 · 点击节点跳转</span>
      </div>
      <ReactFlow
        nodes={nodes}
        edges={edges}
        onNodesChange={() => {}}
        onEdgesChange={() => {}}
        nodeTypes={topoNodeTypes as any}
        fitView
        fitViewOptions={{ padding: 0.08, maxZoom: 1.6 }}
        minZoom={0.3}
        maxZoom={2.5}
        nodesDraggable={false}
        nodesConnectable={false}
        elementsSelectable={false}
        edgesFocusable={false}
        panOnDrag
        zoomOnScroll
        proOptions={{ hideAttribution: true }}
      >
        <Controls className="topo-controls" showInteractive={false} />
      </ReactFlow>
      <div className="topo-legend">
        <span className="topo-legend-item"><span className="topo-legend-line solid" />结构连接</span>
        <span className="topo-legend-item"><span className="topo-legend-line dashed risk" />风险路径</span>
      </div>
    </div>
  );
}
