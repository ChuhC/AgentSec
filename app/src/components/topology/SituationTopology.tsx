import React, { useMemo, useCallback, useRef } from "react";
import ReactFlow, { type Edge, type Node, Controls } from "reactflow";
import "reactflow/dist/style.css";
import type { ScanSnapshot } from "../../types";
import { useApp } from "../../store";
import { buildTopology, type TopoNode } from "./topologyBuilder";
import { computeTopologyLayout, edgeHandles, isOrthogonalAligned, touchesAgent } from "./topologyLayout";
import { topoNodeTypes } from "./TopologyNodes";
import "./topology.css";

function centerToPos(cx: number, cy: number, w: number, h: number) {
  return { x: cx - w / 2, y: cy - h / 2 };
}

function nodeSize(n: TopoNode): { w: number; h: number } {
  switch (n.type) {
    case "agent":     return { w: 184, h: 64 };
    case "category":  return { w: 164, h: 50 };
    case "component": return { w: 164, h: 50 };
    case "risk":      return { w: 172, h: 68 };
    case "external":  return { w: 160, h: 48 };
    default:          return { w: 160, h: 48 };
  }
}

type NavigateTarget = {
  tab: "权限管理" | "威胁管理" | "漏洞管理" | "资产管理";
  permSource?: string;
  assetSubTab?: string;
};

const PERM_NODE_TO_SOURCE: Record<string, string> = {
  agent: "agent_default",
  "cat:mcp": "mcp",
  "cat:skill": "skill",
  "cat:hook": "hook",
  "cat:plugin": "plugin",
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
    "cat:mcp": "MCP", "cat:skill": "Skills",
    "cat:plugin": "插件",
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
  const { t } = useApp();
  const topoLabels = useMemo(
    () => ({
      rules: t("topology.rules"),
      plugins: t("topology.plugins"),
      channel: t("topology.channel"),
      permissions: t("topology.permissions"),
      component: t("topology.component"),
      cveVuln: t("topology.cveVuln"),
      threat: t("topology.threat"),
    }),
    [t]
  );
  const topo = useMemo(
    () => buildTopology(snapshot, agentId, agentLabel, topoLabels),
    [snapshot, agentId, agentLabel, topoLabels]
  );

  const layout = useMemo(() => computeTopologyLayout(topo.nodes), [topo.nodes]);

  const visibleNodeIds = useMemo(() => new Set(topo.nodes.map((n) => n.id)), [topo.nodes]);
  const visibleEdges = useMemo(() => {
    return topo.edges.filter((e) => visibleNodeIds.has(e.source) && visibleNodeIds.has(e.target));
  }, [topo.edges, visibleNodeIds]);

  const nodes = useMemo(() => {
    return topo.nodes.map((n) => {
      const pos = layout.get(n.id);
      const cx = pos?.x ?? 500;
      const cy = pos?.y ?? 340;
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
  }, [topo.nodes, layout]);

  const edges: Edge[] = useMemo(() => {
    return visibleEdges.map((e) => {
      const isRisk = e.risk;
      const c = isRisk ? "#FB7185" : "#818CF8";
      const handles = edgeHandles(e.source, e.target, layout, topo.nodes);
      const agentEdge = touchesAgent(e.source, e.target);
      const aligned = isOrthogonalAligned(e.source, e.target, layout);
      return {
        id: e.id, source: e.source, target: e.target,
        sourceHandle: e.sourceHandle ?? handles.sourceHandle,
        targetHandle: e.targetHandle ?? handles.targetHandle,
        type: agentEdge && aligned ? "straight" : "step",
        ...(agentEdge && aligned ? {} : { pathOptions: { borderRadius: 0 } }),
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
  }, [visibleEdges, layout, topo.nodes]);

  // 容器级点击委托：通过 data-topo-id 识别节点，避免 ReactFlow 内部层拦截
  const pointerDown = useRef<{ x: number; y: number } | null>(null);

  const handlePointerDown = useCallback((e: React.PointerEvent) => {
    pointerDown.current = { x: e.clientX, y: e.clientY };
  }, []);

  const handleContainerClick = useCallback((e: React.MouseEvent) => {
    if ((e.target as HTMLElement).closest(".react-flow__controls")) return;
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
        <span className="topo-legend-item"><span className="topo-legend-line solid" />{t("topology.legendStructure")}</span>
        <span className="topo-legend-item"><span className="topo-legend-line dashed risk" />{t("topology.legendRiskPath")}</span>
      </div>
    </div>
  );
}
