import type { ScanSnapshot } from "../../types";
import {
  assetsByAgent,
  exposureForAgent,
  cveForAgent,
  isThreatIgnored,
} from "../../selectors";

export interface TopoNode {
  id: string;
  type: "agent" | "category" | "risk" | "component" | "external" | "threatItem";
  label: string;
  color: string;
  icon?: string;
  subLabel?: string;
  count?: number;
  threatHigh?: number;
  threatMed?: number;
  permHigh?: number;
  permMed?: number;
  cveCount?: number;
  status?: "risk" | "safe" | "neutral";
  parentId?: string;
  threatSeverity?: string;
  onClick?: () => void;
}

export interface TopoEdge {
  id: string;
  source: string;
  target: string;
  sourceHandle?: string;
  targetHandle?: string;
  dashed?: boolean;
  risk?: boolean;
}

export interface TopoGraph {
  nodes: TopoNode[];
  edges: TopoEdge[];
}

const C = {
  purple:  "#A855F7",
  blue:    "#3B82F6",
  green:   "#22C55E",
  cyan:    "#06B6D4",
  red:     "#EF4444",
  orange:  "#F97316",
  gray:    "#6B7280",
  yellow:  "#EAB308",
};
const ICONS = "/topo-icons";

function countHV(threats: any[]) {
  let h = 0, m = 0;
  for (const t of threats) {
    if (t.severity === "high") h++;
    else if (t.severity === "medium") m++;
  }
  return { h, m };
}

export function buildTopology(
  snapshot: ScanSnapshot,
  agentId: string,
  agentLabel: string
): TopoGraph {
  const assets = assetsByAgent(snapshot, agentId);
  const allThreats = exposureForAgent(snapshot, agentId).filter((t) => !isThreatIgnored(snapshot, t));
  const cveItems = cveForAgent(snapshot, agentId).filter((c) => c.cves.length > 0);
  const totalCve = cveItems.length;
  const agent = snapshot.agents.find((a) => a.id === agentId);

  const nodes: TopoNode[] = [];
  const edges: TopoEdge[] = [];

  // ---- Agent (center) ----
  nodes.push({
    id: "agent", type: "agent", label: agentLabel, color: C.purple, icon: `${ICONS}/agent.png`,
  });

  // ---- MCP ----
  const mcp = assets.filter((a) => a.type === "mcp");
  if (mcp.length) {
    nodes.push({ id: "cat:mcp", type: "category", label: "MCP", count: mcp.length, color: C.blue, icon: `${ICONS}/mcp.png` });
    edges.push({ id: "e:mcp-agent", source: "cat:mcp", target: "agent", sourceHandle: "right", targetHandle: "left" });
  }

  // ---- Skills ----
  const skills = assets.filter((a) => a.type === "skill");
  if (skills.length) {
    nodes.push({ id: "cat:skill", type: "category", label: "Skills", count: skills.length, color: C.green, icon: `${ICONS}/skills.png` });
    edges.push({ id: "e:skill-agent", source: "cat:skill", target: "agent", sourceHandle: "right", targetHandle: "left" });
  }

  // ---- Knowledge ----
  const know = assets.filter((a) => a.type === "knowledge");
  if (know.length) {
    nodes.push({ id: "cat:knowledge", type: "category", label: "知识库", count: know.length, color: "#14B8A6", icon: `${ICONS}/knowledge.png` });
    edges.push({ id: "e:know-agent", source: "cat:knowledge", target: "agent", sourceHandle: "bottom", targetHandle: "top" });
  }

  // ---- Channel ----
  const ch = assets.filter((a) => a.type === "channel");
  if (ch.length) {
    nodes.push({ id: "cat:channel", type: "category", label: "通道", count: ch.length, color: C.cyan, icon: `${ICONS}/channel.png` });
    edges.push({ id: "e:channel-agent", source: "cat:channel", target: "agent", sourceHandle: "left", targetHandle: "target-right" });
  }

  // ---- Hook ----
  const hooks = assets.filter((a) => a.type === "hook");
  if (hooks.length) {
    nodes.push({ id: "cat:hook", type: "category", label: "Hook", count: hooks.length, color: C.yellow, icon: `${ICONS}/hook.png` });
    edges.push({ id: "e:hook-agent", source: "cat:hook", target: "agent", sourceHandle: "top", targetHandle: "left" });
  }

  // ---- Permissions → 按来源拆分挂载到各分类节点 ----
  // Collect all permissions: agent own + each asset's permissions
  const allPerms: { entry: any; source: string }[] = [];
  if (agent?.permissions) {
    for (const p of agent.permissions) {
      allPerms.push({ entry: p, source: p.source || "agent_config" });
    }
  }
  for (const a of assets) {
    if (a.permissions) {
      for (const p of a.permissions) {
        allPerms.push({ entry: p, source: p.source || a.type });
      }
    }
  }

  // Group by source category
  const permByParent: Record<string, any[]> = {};
  for (const { entry, source } of allPerms) {
    // Map source → parent node id
    let parentId = "agent";
    if (source === "mcp" && mcp.length) parentId = "cat:mcp";
    else if (source === "skill" && skills.length) parentId = "cat:skill";
    else if (source === "knowledge" && know.length) parentId = "cat:knowledge";
    else if (source === "hook" && hooks.length) parentId = "cat:hook";
    else if (source === "channel" && ch.length) parentId = "cat:channel";
    (permByParent[parentId] ??= []).push(entry);
  }

  for (const [parentId, perms] of Object.entries(permByParent)) {
    if (!perms.length) continue;
    let pH = 0, pM = 0;
    for (const p of perms) {
      if (p.severity === "high") pH++;
      else if (p.severity === "medium") pM++;
    }
    const nodeId = `cat:perm-${parentId}`;
    nodes.push({
      id: nodeId, type: "category", label: "权限", count: perms.length,
      color: C.yellow, icon: `${ICONS}/perm.png`,
      permHigh: pH, permMed: pM,
    });
    // Position-aware handles — edges stay pure horizontal or vertical, no crossings
    let srcHandle = "bottom";
    let tgtHandle = "target-top";
    if (parentId === "cat:mcp" || parentId === "cat:skill" || parentId === "cat:hook") {
      srcHandle = "left";
      tgtHandle = "target-right";
    } else if (parentId === "cat:knowledge") {
      srcHandle = "right";
      tgtHandle = "target-left";
    }
    // agent & cat:channel → default bottom / target-top
    edges.push({
      id: `e:perm-${parentId}`,
      source: parentId, target: nodeId,
      sourceHandle: srcHandle, targetHandle: tgtHandle,
      dashed: true, risk: false,
    });
  }

  // ---- Dependency ----
  const deps = assets.filter((a) => a.type === "dependency");
  if (deps.length) {
    nodes.push({
      id: "cat:dependency", type: "component", label: "组件", count: deps.length,
      color: C.gray, icon: `${ICONS}/component.png`,
    });
    edges.push({ id: "e:agent-dep", source: "agent", target: "cat:dependency", sourceHandle: "bottom", targetHandle: "top" });
  }

  // ---- CVE ----
  if (totalCve > 0) {
    nodes.push({ id: "risk:cve", type: "risk", label: "CVE 漏洞", count: totalCve, color: C.orange, icon: `${ICONS}/cve.png`, status: "risk" });
    edges.push({ id: "e:cve", source: "cat:dependency", target: "risk:cve", sourceHandle: "bottom", targetHandle: "top", dashed: true, risk: true });
  }

  // ---- 威胁 → 按来源拆分 ----
  const threatMCP = allThreats.filter((t) => t.source === "mcp");
  const threatSkill = allThreats.filter((t) => t.source === "skill");
  const threatOther = allThreats.filter((t) => t.source !== "mcp" && t.source !== "skill");

  function addThreatNode(id: string, threats: any[], parent: string) {
    if (!threats.length) return;
    const { h, m: med } = countHV(threats);
    nodes.push({ id, type: "risk", label: "威胁", count: threats.length, color: C.red, icon: `${ICONS}/risk.png`, threatHigh: h, threatMed: med, status: "risk" });
    edges.push({ id: `e:threat-${id}`, source: parent, target: id, sourceHandle: "bottom", targetHandle: "top", dashed: true, risk: true });
  }

  if (mcp.length) addThreatNode("risk:threat-mcp", threatMCP, "cat:mcp");
  if (skills.length) addThreatNode("risk:threat-skill", threatSkill, "cat:skill");
  if (threatOther.length) addThreatNode("risk:threat-agent", threatOther, "agent");

  return { nodes, edges };
}
