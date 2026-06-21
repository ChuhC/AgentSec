import type { Locale } from "./messages";
import type { LocaleDataLayer, LocaleLayerFactory, TFn } from "./types";
import { lookupAtrRuleTitle } from "./atrRuleTitles";

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
  "网络暴露": "data.threatCategory.exposure",
  "OpenClaw 基线": "data.threatCategory.exposure",
  "权限与访问控制": "data.threatCategory.privilegeEscalation",
  "输入校验": "data.threatCategory.promptInjection",
  "日志与审计": "data.threatCategory.modelSecurity",
  "数据安全": "data.threatCategory.contextExfiltration",
  "容器安全": "data.threatCategory.exposure",
  "资源与配额": "data.threatCategory.excessiveAutonomy",
  "审计与合规": "data.threatCategory.exposure",
};

/** 引擎 category（中文键）→ messages.data 子键 */
const THREAT_DATA_KEY: Record<string, string> = {
  "Prompt 注入": "promptInjection",
  "Agent 操纵": "agentManipulation",
  "工具投毒": "toolPoisoning",
  "上下文外泄": "contextExfiltration",
  "Skill 风险": "skillCompromise",
  "权限提升": "privilegeEscalation",
  "过度自治": "excessiveAutonomy",
  "模型滥用": "modelAbuse",
  "数据投毒": "dataPoisoning",
  "模型安全": "modelSecurity",
  "暴露面": "exposure",
  "其他": "other",
  "网络暴露": "exposure",
  "OpenClaw 基线": "exposure",
  "权限与访问控制": "privilegeEscalation",
  "输入校验": "promptInjection",
  "日志与审计": "modelSecurity",
  "数据安全": "contextExfiltration",
  "容器安全": "exposure",
  "资源与配额": "excessiveAutonomy",
  "审计与合规": "exposure",
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

function threatDataKey(category: string): string | undefined {
  return THREAT_DATA_KEY[category];
}

function localizedThreatText(
  t: TFn,
  field: "threatPlain" | "threatReco" | "threatImpact",
  category: string,
  fallback: string,
): string {
  const dk = threatDataKey(category);
  if (dk) {
    const localized = t(`data.${field}.${dk}`);
    if (localized !== `data.${field}.${dk}`) return localized;
  }
  return fallback;
}

function hasCjk(text: string): boolean {
  return /[\u3400-\u9fff]/.test(text);
}

/** fixture / 引擎中文摘要 → messages.data.cveSummary 键 */
const CVE_SUMMARY_ZH_TO_KEY: Record<string, string> = {
  "反序列化漏洞，攻击者可通过构造恶意数据绕过安全限制，执行任意代码。": "deserializationRce",
  "权限绕过漏洞，攻击者可绕过认证访问受限资源。": "authBypass",
  "信息泄露漏洞，攻击者可获取敏感信息。": "infoLeak",
  "目录遍历漏洞，攻击者可访问任意系统文件。": "pathTraversal",
  "路径遍历漏洞，攻击者可读取服务端任意文件。": "pathTraversal",
  "拒绝服务漏洞，攻击者可通过特定请求导致服务异常。": "dos",
  "跨站脚本漏洞。": "xss",
  "信息暴露。": "exposure",
  "Log4Shell 远程代码执行。": "log4shellRce",
  "RCE / 拒绝服务。": "rceDos",
  "拒绝服务。": "dosShort",
  "JDBC Appender RCE。": "jdbcRce",
  "证书校验不当。": "certValidation",
  "autoType 绕过反序列化。": "fastjsonAutotype",
  "信息泄露。": "infoLeakShort",
  "DoS：上传过多分片。": "dos",
  "反序列化 RCE。": "deserializationRce",
  "嵌套对象 DoS。": "dos",
  "本地临时文件信息泄露。": "infoLeak",
};

function parseMcpPurposeToken(purpose: string): Record<string, string> | null {
  if (!purpose.startsWith("__mcp__|")) return null;
  const fields: Record<string, string> = {};
  for (const part of purpose.slice("__mcp__|".length).split("|")) {
    const i = part.indexOf(":");
    if (i > 0) fields[part.slice(0, i)] = part.slice(i + 1);
  }
  return fields;
}

function localizeLegacyMcpPurpose(purpose: string, t: TFn): string | null {
  const withCreds = purpose.match(/^MCP 服务：(.+?)（凭证引用：(.+)）$/);
  if (withCreds) {
    const short = withCreds[1].trim().split(/[/\\]/).pop() || withCreds[1].trim();
    return t("data.purpose.mcpServiceWithCreds", { cmd: short, creds: withCreds[2] });
  }
  const named = purpose.match(/^MCP 服务：(.+)$/);
  if (named) {
    const short = named[1].trim().split(/[/\\]/).pop() || named[1].trim();
    return t("data.purpose.mcpServiceNamed", { cmd: short });
  }
  if (purpose === "MCP 服务") return t("data.purpose.mcpService");
  return null;
}

function localizeCveSummaryText(t: TFn, summary: string, isEn: boolean): string {
  if (!summary.trim()) return summary;
  const key = CVE_SUMMARY_ZH_TO_KEY[summary.trim()];
  if (key) {
    const localized = t(`data.cveSummary.${key}`);
    if (localized !== `data.cveSummary.${key}`) return localized;
  }
  return summary;
}

function localizeUpgradeAdviceText(
  t: TFn,
  advice: string,
  fixedVersion: string | null | undefined,
  isEn: boolean,
): string {
  if (!advice.trim()) return advice;
  const v = fixedVersion || "";

  if (isEn && hasCjk(advice)) {
    if (/暂无需升级/.test(advice)) return t("data.upgradeAdvice.noUpgradeNeeded");
    if (/暂无官方修复/.test(advice)) return t("data.upgradeAdvice.noOfficialFix");
    let m = advice.match(/建议升级到最新安全版本\s*([\d.]+)/);
    if (m) return t("data.upgradeAdvice.upgradeLatestSecurity", { version: m[1] });
    m = advice.match(/建议升级到\s*([\d.]+)，可修复上述已知漏洞/);
    if (m) return t("data.upgradeAdvice.upgradeToFix", { version: m[1] });
    m = advice.match(/升级到\s*([\d.]+)\s*以修复 Log4Shell/);
    if (m) return t("data.upgradeAdvice.upgradeLog4shell", { version: m[1] });
    m = advice.match(/升级到\s*([\d.]+)\s*并开启 safeMode/);
    if (m) return t("data.upgradeAdvice.upgradeSafemode", { version: m[1] });
    m = advice.match(/升级到\s*([\d.]+)\s*修复路径遍历/);
    if (m) return t("data.upgradeAdvice.upgradePathTraversal", { version: m[1] });
    m = advice.match(/升级到\s*([\d.]+)/);
    if (m) return t("data.upgradeAdvice.upgradeTo", { version: m[1] });
    if (v) return t("data.upgradeAdvice.upgradeToFix", { version: v });
    return t("data.upgradeAdvice.fallback");
  }

  if (!isEn && !hasCjk(advice)) {
    if (/no upgrade needed/i.test(advice)) return t("data.upgradeAdvice.noUpgradeNeeded");
    if (/no official fix/i.test(advice)) return t("data.upgradeAdvice.noOfficialFix");
    let m = advice.match(/upgrade to\s*([\d.]+)/i);
    if (m) return t("data.upgradeAdvice.upgradeToFix", { version: m[1] });
  }

  return advice;
}

function localizeEvidence(t: TFn, evidence: string): string {
  if (!evidence) return evidence;
  const snippetLabel = t("data.evidence.matchedSnippet");
  let out = evidence;
  out = out.replace(/\n命中片段：/g, `\n${snippetLabel}: `);
  out = out.replace(/^命中片段：/gm, `${snippetLabel}: `);
  out = out.replace(/\nMatched snippet:\s*/gi, `\n${snippetLabel}: `);
  out = out.replace(/^Matched snippet:\s*/gim, `${snippetLabel}: `);
  out = out.replace(/\n… 另有 (\d+) 处命中/g, (_, n) =>
    `\n${t("threatList.evidenceMoreHits", { count: n })}`
  );
  out = out.replace(/\n… and (\d+) more hits?/gi, (_, n) =>
    `\n${t("threatList.evidenceMoreHits", { count: n })}`
  );
  return out;
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

    threatTitle(ruleId: string, fallback: string, category: string) {
      const mapped = lookupAtrRuleTitle(ruleId, fallback);
      if (isEn) {
        if (mapped.en && !hasCjk(mapped.en)) return mapped.en;
        if (!hasCjk(fallback)) return fallback;
        const fixKey = `data.fixtureThreatTitle.${ruleId}`;
        const fix = t(fixKey);
        if (fix !== fixKey) return fix;
        return mapped.en || fallback;
      }
      if (mapped.zh && mapped.zh !== mapped.en) return mapped.zh;
      if (hasCjk(fallback)) return fallback;
      const fixKey = `data.fixtureThreatTitle.${ruleId}`;
      const fix = t(fixKey);
      if (fix !== fixKey && hasCjk(fix)) return fix;
      const dk = threatDataKey(category);
      if (dk) {
        const catLabel = t(`data.threatCategory.${dk}`);
        if (catLabel !== `data.threatCategory.${dk}`) return `${catLabel}风险`;
      }
      return fallback;
    },

    threatImpact(category: string, fallback: string) {
      // 英文界面优先展示 ATR 规则级 impact；中文界面用类别级本地化描述
      if (isEn && fallback.trim()) return fallback;
      return localizedThreatText(t, "threatImpact", category, fallback);
    },

    threatPlainExplanation(category: string, fallback: string) {
      return localizedThreatText(t, "threatPlain", category, fallback);
    },

    threatRecommendation(category: string, fallback: string) {
      return localizedThreatText(t, "threatReco", category, fallback);
    },

    threatEvidence(evidence: string) {
      return localizeEvidence(t, evidence);
    },

    agentDescription(description: string) {
      return description;
    },

    assetPurpose(purpose: string) {
      const mcp = parseMcpPurposeToken(purpose);
      if (mcp) {
        const label = mcp.label || "MCP";
        const detail = mcp.npm || mcp.script || mcp.cmd || "";
        if (mcp.creds) {
          return t("data.purpose.mcpStructuredWithCreds", {
            name: label,
            detail: detail || label,
            creds: mcp.creds,
          });
        }
        if (detail && detail !== label) {
          return t("data.purpose.mcpStructured", { name: label, detail });
        }
        return t("data.purpose.mcpNamed", { name: label });
      }
      const legacyMcp = localizeLegacyMcpPurpose(purpose, t);
      if (legacyMcp) return legacyMcp;
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

    upgradeAdvice(advice: string, fixedVersion?: string | null) {
      return localizeUpgradeAdviceText(t, advice, fixedVersion, isEn);
    },

    cveSummary(summary: string) {
      return localizeCveSummaryText(t, summary, isEn);
    },

    cvePlainExplanation(summary: string) {
      return localizeCveSummaryText(t, summary, isEn);
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
