import type { Locale } from "./messages";
import type { LocaleDataLayer, LocaleLayerFactory, TFn } from "./types";

/** UI 枚举/产品文案映射；扫描结果与用户文件内容不在此翻译，原样展示。 */

const THREAT_CATEGORY_KEY: Record<string, string> = {
  "Prompt 注入": "data.threatCategory.promptInjection",
  "Agent 操纵": "data.threatCategory.agentManipulation",
  "工具投毒": "data.threatCategory.toolPoisoning",
  "上下文外泄": "data.threatCategory.contextExfiltration",
  "Skill 风险": "data.threatCategory.skillCompromise",
  "权限提升": "data.threatCategory.privilegeEscalation",
  "过度自治": "data.threatCategory.excessiveAutonomy",
  "模型滥用": "data.threatCategory.modelAbuse",
  "数据投毒": "data.threatCategory.dataPoisoning",
  "模型安全": "data.threatCategory.modelSecurity",
  "暴露面": "data.threatCategory.exposure",
  "其他": "data.threatCategory.other",
};

const THREAT_SOURCE_KEY: Record<string, string> = {
  agent_config: "threatList.sourceAgentConfig",
  knowledge: "threatList.sourceKnowledge",
  openclaw_audit: "threatList.sourceOpenclawAudit",
};

const PERM_CATEGORY_KEY: Record<string, string> = {
  "文件": "common.permCategory.file",
  Shell: "common.permCategory.shell",
  "网络": "common.permCategory.network",
  "工具": "common.permCategory.tool",
  "知识库": "common.permCategory.knowledge",
};

function lookup(t: TFn, map: Record<string, string>, value: string): string | undefined {
  const key = map[value];
  return key ? t(key) : undefined;
}

export const createLocaleLayer: LocaleLayerFactory = (locale: Locale, t: TFn): LocaleDataLayer => {
  const isEn = locale === "en";

  return {
    locale,
    t,

    scopeLabel(scope: string) {
      if (scope === "all" || scope === "本机全部") return t("common.scope.all");
      if (scope === "custom" || scope === "自定义路径") return t("common.scope.custom");
      return scope;
    },

    listSeparator() {
      return isEn ? ", " : "、";
    },

    threatCategory(category: string) {
      return lookup(t, THREAT_CATEGORY_KEY, category) ?? category;
    },

    threatSource(source: string) {
      return lookup(t, THREAT_SOURCE_KEY, source) ?? source;
    },

    threatImpact(_category: string, fallback: string) {
      return fallback;
    },

    threatPlainExplanation(_category: string, fallback: string) {
      return fallback;
    },

    threatRecommendation(_category: string, fallback: string) {
      return fallback;
    },

    threatEvidence(evidence: string) {
      return evidence;
    },

    agentDescription(description: string) {
      return description;
    },

    assetPurpose(purpose: string) {
      return purpose;
    },

    permissionCategory(category: string) {
      return lookup(t, PERM_CATEGORY_KEY, category) ?? category;
    },

    permissionName(name: string) {
      return name;
    },

    permissionSourceLabel(label: string) {
      return label;
    },

    upgradeAdvice(advice: string, _fixedVersion?: string | null) {
      return advice;
    },

    cveSummary(summary: string) {
      return summary;
    },

    pendingActionLabel(id: string) {
      const map: Record<string, string> = {
        "threat-high": "data.pending.threatHigh.label",
        "threat-medium": "data.pending.threatMedium.label",
        "cve-vuln": "data.pending.cveVuln.label",
        updatable: "data.pending.updatable.label",
        "disabled-skills": "data.pending.disabledSkills.label",
        "disabled-mcp": "data.pending.disabledMcp.label",
      };
      const key = map[id];
      return key ? t(key) : id;
    },

    pendingActionDetail(id: string, count: number) {
      switch (id) {
        case "threat-high":
          return t("data.pending.threatHigh.detail");
        case "threat-medium":
          return t("data.pending.threatMedium.detail");
        case "cve-vuln":
          return t("data.pending.cveVuln.detail", { count });
        case "updatable":
          return t("data.pending.updatable.detail");
        case "disabled-skills":
          return t("data.pending.disabledSkills.detail");
        case "disabled-mcp":
          return t("data.pending.disabledMcp.detail");
        default:
          return "";
      }
    },

    optimizationTitle(item: { id: string; title: string }) {
      if (item.id === "opt-shell") return t("data.optimization.shellPermission");
      if (item.id === "opt-disabled-mcp") {
        const m = item.title.match(/^(\d+) 个 MCP 服务已禁用$/);
        if (m) return t("data.optimization.disabledMcp", { count: m[1] });
      }
      return item.title;
    },
  };
};

let layerFactory: LocaleLayerFactory = createLocaleLayer;

export function setLocaleLayerFactory(factory: LocaleLayerFactory): void {
  layerFactory = factory;
}

export function getLocaleLayerFactory(): LocaleLayerFactory {
  return layerFactory;
}
