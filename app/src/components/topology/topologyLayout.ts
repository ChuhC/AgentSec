import type { TopoNode } from "./topologyBuilder";

export interface LayoutPos {
  x: number;
  y: number;
  angle: number;
}

const CENTER = { x: 500, y: 340 };
const PAD = 22;
const AGENT_PERM_EXTRA = 72;
const ALIGN_EPS = 8;

const SIZE = {
  agent: { w: 184, h: 64 },
  category: { w: 164, h: 50 },
  component: { w: 164, h: 50 },
  risk: { w: 172, h: 68 },
  default: { w: 160, h: 48 },
};

type Side = "top" | "bottom" | "left" | "right";

interface Box {
  id: string;
  cx: number;
  cy: number;
  w: number;
  h: number;
}

function nodeSize(n: TopoNode): { w: number; h: number } {
  if (n.type === "agent") return SIZE.agent;
  if (n.type === "component") return SIZE.component;
  if (n.type === "risk") return SIZE.risk;
  if (n.type === "category") return SIZE.category;
  return SIZE.default;
}

function pos(x: number, y: number): LayoutPos {
  const rad = Math.atan2(y - CENTER.y, x - CENTER.x);
  return { x, y, angle: ((rad * 180) / Math.PI + 90 + 360) % 360 };
}

function boxOf(id: string, cx: number, cy: number, n: TopoNode): Box {
  const s = nodeSize(n);
  return { id, cx, cy, w: s.w, h: s.h };
}

function overlap(a: Box, b: Box, pad = PAD): boolean {
  return (
    a.cx - a.w / 2 - pad < b.cx + b.w / 2 + pad &&
    a.cx + a.w / 2 + pad > b.cx - b.w / 2 - pad &&
    a.cy - a.h / 2 - pad < b.cy + b.h / 2 + pad &&
    a.cy + a.h / 2 + pad > b.cy - b.h / 2 - pad
  );
}

/** Agent 四周主节点（直连 Agent 的资产类；权限/威胁由卫星布局外推） */
const AGENT_SIDES: Record<Side, string[]> = {
  top: ["cat:mcp"],
  bottom: ["cat:dependency", "cat:channel"],
  left: ["cat:skill", "cat:hook"],
  right: ["cat:plugin"],
};

/** 插件右侧权限链：Agent 默认权限 + 插件权限依次外推，避免叠在同一格 */
function placePluginRightPermChain(
  boxes: Map<string, Box>,
  agentBox: Box,
  byId: Map<string, TopoNode>
): string[] {
  const plugin = boxes.get("cat:plugin");
  const chainIds: string[] = [];
  if (byId.has("cat:perm-agent")) chainIds.push("cat:perm-agent");
  if (plugin && byId.has("cat:perm-cat:plugin")) chainIds.push("cat:perm-cat:plugin");
  if (!chainIds.length) return [];

  const anchor = plugin ?? agentBox;
  const extraLead = plugin ? 0 : AGENT_PERM_EXTRA;
  for (const b of packOnSide(anchor, "right", chainIds, byId, extraLead)) {
    boxes.set(b.id, b);
  }
  return chainIds;
}

/** 取右侧链上最靠外的节点，供威胁等卫星继续外推 */
function rightmostBox(boxes: Map<string, Box>, ids: string[]): Box | null {
  let best: Box | null = null;
  for (const id of ids) {
    const b = boxes.get(id);
    if (!b) continue;
    if (!best || b.cx > best.cx) best = b;
  }
  return best;
}

function satelliteParentId(node: TopoNode): string | null {
  if (node.id.startsWith("cat:perm-")) return node.id.slice("cat:perm-".length);
  if (node.id === "risk:threat-mcp") return "cat:mcp";
  if (node.id === "risk:threat-skill") return "cat:skill";
  if (node.id === "risk:threat-agent") return "agent";
  if (node.id === "risk:cve") return "cat:dependency";
  return null;
}

function outwardSide(parent: Box, agent: Box): Side {
  const dx = parent.cx - agent.cx;
  const dy = parent.cy - agent.cy;
  if (Math.abs(dx) > Math.abs(dy)) return dx > 0 ? "right" : "left";
  return dy > 0 ? "bottom" : "top";
}

function peerSide(primary: Side): Side {
  if (primary === "top" || primary === "bottom") return "right";
  return "bottom";
}

function gapBetweenBoxes(a: Box, b: Box, extra = 0): number {
  return Math.max(a.w, a.h) / 2 + Math.max(b.w, b.h) / 2 + PAD + extra;
}

/** 在 anchor 的某一侧，按顺序排开多个节点（用真实宽高算间距） */
function packOnSide(anchor: Box, side: Side, ids: string[], byId: Map<string, TopoNode>, extraLead = 0): Box[] {
  const items = ids.filter((id) => byId.has(id)).map((id) => {
    const s = nodeSize(byId.get(id)!);
    return { id, w: s.w, h: s.h };
  });
  if (!items.length) return [];

  const out: Box[] = [];

  if (side === "left" || side === "right") {
    const sign = side === "right" ? 1 : -1;
    let edge = sign > 0 ? anchor.cx + anchor.w / 2 : anchor.cx - anchor.w / 2;
    for (const item of items) {
      const lead = out.length === 0 ? extraLead : 0;
      const step = out.length === 0
        ? anchor.w / 2 + item.w / 2 + PAD + lead
        : out[out.length - 1].w / 2 + item.w / 2 + PAD;
      edge += sign * step;
      out.push(boxOf(item.id, edge, anchor.cy, byId.get(item.id)!));
    }
    return out;
  }

  const sign = side === "bottom" ? 1 : -1;
  let edge = sign > 0 ? anchor.cy + anchor.h / 2 : anchor.cy - anchor.h / 2;
  for (const item of items) {
    const lead = out.length === 0 ? extraLead : 0;
    const step = out.length === 0
      ? anchor.h / 2 + item.h / 2 + PAD + lead
      : out[out.length - 1].h / 2 + item.h / 2 + PAD;
    edge += sign * step;
    out.push(boxOf(item.id, anchor.cx, edge, byId.get(item.id)!));
  }
  return out;
}

/** 相对父节点放置单个子节点 */
function placeChild(parent: Box, child: TopoNode, side: Side, extra = 0): Box {
  const s = nodeSize(child);
  const g = gapBetweenBoxes(parent, boxOf(child.id, parent.cx, parent.cy, child), extra);
  switch (side) {
    case "top":
      return boxOf(child.id, parent.cx, parent.cy - g, child);
    case "bottom":
      return boxOf(child.id, parent.cx, parent.cy + g, child);
    case "left":
      return boxOf(child.id, parent.cx - g, parent.cy, child);
    case "right":
      return boxOf(child.id, parent.cx + g, parent.cy, child);
  }
}

/** 全局 AABB 碰撞推开（对所有节点生效，通用防重叠） */
function resolveOverlaps(boxes: Map<string, Box>, maxPass = 40) {
  const ids = [...boxes.keys()];
  for (let pass = 0; pass < maxPass; pass++) {
    let moved = false;
    for (let i = 0; i < ids.length; i++) {
      for (let j = i + 1; j < ids.length; j++) {
        const a = boxes.get(ids[i])!;
        const b = boxes.get(ids[j])!;
        if (!overlap(a, b)) continue;
        const dx = b.cx - a.cx || 1;
        const dy = b.cy - a.cy || 1;
        const len = Math.hypot(dx, dy);
        const push = 10;
        boxes.set(a.id, { ...a, cx: a.cx - (dx / len) * push, cy: a.cy - (dy / len) * push });
        boxes.set(b.id, { ...b, cx: b.cx + (dx / len) * push, cy: b.cy + (dy / len) * push });
        moved = true;
      }
    }
    if (!moved) break;
  }
}

/** 与 Agent 直连的节点锁定正交（同行或同列） */
function snapAgentOrthogonal(boxes: Map<string, Box>, nodeIds: Set<string>) {
  const agent = boxes.get("agent");
  if (!agent) return;

  const colIds = ["cat:mcp", "cat:channel", "cat:dependency", "risk:cve"];
  for (const id of colIds) {
    if (!nodeIds.has(id)) continue;
    const b = boxes.get(id);
    if (b) boxes.set(id, { ...b, cx: agent.cx });
  }

  const rowIds = [
    "cat:skill",
    "cat:hook",
    "cat:plugin",
    "cat:perm-agent",
    "cat:perm-cat:plugin",
  ];
  for (const id of rowIds) {
    if (!nodeIds.has(id)) continue;
    const b = boxes.get(id);
    if (b) boxes.set(id, { ...b, cy: agent.cy });
  }

  const mcp = boxes.get("cat:mcp");
  if (mcp) {
    for (const id of ["cat:perm-cat:mcp"]) {
      if (!nodeIds.has(id)) continue;
      const b = boxes.get(id);
      if (b) boxes.set(id, { ...b, cx: mcp.cx });
    }
  }
}

export function computeTopologyLayout(nodes: TopoNode[]): Map<string, LayoutPos> {
  const byId = new Map(nodes.map((n) => [n.id, n]));
  const boxes = new Map<string, Box>();

  const agentNode = byId.get("agent");
  if (!agentNode) return new Map();

  boxes.set("agent", boxOf("agent", CENTER.x, CENTER.y, agentNode));

  const agentBox = boxes.get("agent")!;

  for (const side of ["top", "bottom", "left", "right"] as Side[]) {
    for (const b of packOnSide(agentBox, side, AGENT_SIDES[side], byId, 0)) {
      boxes.set(b.id, b);
    }
  }

  const rightPermChain = placePluginRightPermChain(boxes, agentBox, byId);
  const rightPermChainSet = new Set(rightPermChain);

  const placed = new Set(boxes.keys());
  const rank = (id: string) =>
    id.startsWith("cat:perm-") ? 0 : id.startsWith("risk:threat-") ? 1 : 2;
  const satellites = nodes
    .filter((n) => !placed.has(n.id))
    .sort((a, b) => rank(a.id) - rank(b.id));

  for (const node of satellites) {
    const parentId = satelliteParentId(node);
    if (!parentId) continue;
    const parent = boxes.get(parentId);
    if (!parent) continue;

    if (node.id.startsWith("cat:perm-")) {
      if (rightPermChainSet.has(node.id)) continue;
      const side = parentId === "agent" ? "right" : outwardSide(parent, agentBox);
      const extra = parentId === "agent" ? AGENT_PERM_EXTRA : 0;
      boxes.set(node.id, placeChild(parent, node, side, extra));
      continue;
    }

    if (node.id.startsWith("risk:threat-")) {
      const permId = `cat:perm-${parentId}`;
      const perm = boxes.get(permId);
      if (perm) {
        const primary = parentId === "agent" ? "right" : outwardSide(parent, agentBox);
        boxes.set(node.id, placeChild(perm, node, peerSide(primary)));
      } else if (parentId === "agent") {
        const anchor =
          rightmostBox(boxes, rightPermChain) ??
          boxes.get("cat:plugin") ??
          parent;
        boxes.set(node.id, placeChild(anchor, node, "right"));
      } else {
        boxes.set(node.id, placeChild(parent, node, outwardSide(parent, agentBox)));
      }
      continue;
    }

    if (node.id === "risk:cve") {
      boxes.set(node.id, placeChild(parent, node, "bottom"));
    }
  }

  resolveOverlaps(boxes);
  snapAgentOrthogonal(boxes, new Set(nodes.map((n) => n.id)));
  resolveOverlaps(boxes);

  const positions = new Map<string, LayoutPos>();
  for (const [id, b] of boxes) {
    positions.set(id, pos(b.cx, b.cy));
  }
  return positions;
}

export function touchesAgent(sourceId: string, targetId: string): boolean {
  return sourceId === "agent" || targetId === "agent";
}

export function isOrthogonalAligned(
  sourceId: string,
  targetId: string,
  layout: Map<string, LayoutPos>
): boolean {
  const src = layout.get(sourceId);
  const tgt = layout.get(targetId);
  if (!src || !tgt) return false;
  return Math.abs(src.x - tgt.x) < ALIGN_EPS || Math.abs(src.y - tgt.y) < ALIGN_EPS;
}

type HandleSide = "top" | "right" | "bottom" | "left";
type NodeProfile = "agent" | "category" | "component" | "risk";

function nodeProfile(id: string, byId: Map<string, TopoNode>): NodeProfile {
  if (id === "agent") return "agent";
  const n = byId.get(id);
  if (!n) return "category";
  if (n.type === "component") return "component";
  if (n.type === "risk") return "risk";
  return "category";
}

function categoryTargetHandle(side: HandleSide): string {
  if (side === "right") return "target-right";
  if (side === "left") return "target-left";
  if (side === "bottom") return "target-bottom";
  return "target-top";
}

function agentSourceHandle(side: HandleSide): string {
  if (side === "top") return "source-top";
  if (side === "left") return "source-left";
  return side;
}

function agentTargetHandle(side: HandleSide): string {
  if (side === "right") return "target-right";
  if (side === "bottom") return "target-bottom";
  return side;
}

function pickSide(profile: NodeProfile, side: HandleSide, io: "source" | "target"): string {
  if (io === "source") {
    if (profile === "agent") return agentSourceHandle(side);
    return side;
  }
  if (profile === "agent") return agentTargetHandle(side);
  return categoryTargetHandle(side);
}

function orthogonalHandles(
  srcProfile: NodeProfile,
  tgtProfile: NodeProfile,
  dx: number,
  dy: number
): { sourceHandle: string; targetHandle: string } {
  const sameX = Math.abs(dx) < ALIGN_EPS;
  const sameY = Math.abs(dy) < ALIGN_EPS;

  if (sameX) {
    if (dy > 0) {
      return {
        sourceHandle: pickSide(srcProfile, "bottom", "source"),
        targetHandle: pickSide(tgtProfile, "top", "target"),
      };
    }
    return {
      sourceHandle: pickSide(srcProfile, "top", "source"),
      targetHandle: pickSide(tgtProfile, "bottom", "target"),
    };
  }

  if (sameY) {
    if (dx > 0) {
      return {
        sourceHandle: pickSide(srcProfile, "right", "source"),
        targetHandle: pickSide(tgtProfile, "left", "target"),
      };
    }
    return {
      sourceHandle: pickSide(srcProfile, "left", "source"),
      targetHandle: pickSide(tgtProfile, "right", "target"),
    };
  }

  if (Math.abs(dx) >= Math.abs(dy)) {
    if (dx > 0) {
      return {
        sourceHandle: pickSide(srcProfile, "right", "source"),
        targetHandle: pickSide(tgtProfile, "left", "target"),
      };
    }
    return {
      sourceHandle: pickSide(srcProfile, "left", "source"),
      targetHandle: pickSide(tgtProfile, "right", "target"),
    };
  }

  if (dy > 0) {
    return {
      sourceHandle: pickSide(srcProfile, "bottom", "source"),
      targetHandle: pickSide(tgtProfile, "top", "target"),
    };
  }
  return {
    sourceHandle: pickSide(srcProfile, "top", "source"),
    targetHandle: pickSide(tgtProfile, "bottom", "target"),
  };
}

export function edgeHandles(
  sourceId: string,
  targetId: string,
  layout: Map<string, LayoutPos>,
  nodes: TopoNode[]
): { sourceHandle: string; targetHandle: string } {
  const src = layout.get(sourceId);
  const tgt = layout.get(targetId);
  if (!src || !tgt) return { sourceHandle: "bottom", targetHandle: "target-top" };

  const byId = new Map(nodes.map((n) => [n.id, n]));
  return orthogonalHandles(
    nodeProfile(sourceId, byId),
    nodeProfile(targetId, byId),
    tgt.x - src.x,
    tgt.y - src.y
  );
}

export { CENTER as TOPO_CENTER };
