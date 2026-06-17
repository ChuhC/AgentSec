import type { Route, Settings } from "./store";
import { localeFromSetting, themeFromSetting } from "./i18n";

/** 截图/文档生成：`?screenshot=1&route=results&lang=en` */
export function readScreenshotBootstrap(): {
  settings?: Partial<Settings>;
  route?: Route;
  preloadSnapshot?: boolean;
} | null {
  const params = new URLSearchParams(window.location.search);
  if (params.get("screenshot") !== "1") return null;

  const out: {
    settings?: Partial<Settings>;
    route?: Route;
    preloadSnapshot?: boolean;
  } = {};

  const lang = params.get("lang");
  if (lang) {
    out.settings = {
      language: localeFromSetting(lang),
      theme: themeFromSetting(params.get("theme") ?? "glass"),
    };
  }

  const route = params.get("route");
  if (route === "scan-home") out.route = { name: "scan-home" };
  else if (route === "results") {
    out.route = { name: "results" };
    out.preloadSnapshot = true;
  } else if (route === "threat-list") {
    out.route = { name: "threat-list" };
    out.preloadSnapshot = true;
  } else if (route === "vuln-list") {
    out.route = { name: "vuln-list" };
    out.preloadSnapshot = true;
  } else if (route === "agent-list") {
    out.route = { name: "agent-list" };
    out.preloadSnapshot = true;
  } else if (route === "agent-workbench") {
    out.route = {
      name: "agent-workbench",
      agentId: params.get("agent") ?? "hermes",
      tab: params.get("tab") ?? undefined,
    };
    out.preloadSnapshot = true;
  } else if (route === "settings") out.route = { name: "settings" };

  if (params.get("snapshot") === "1") out.preloadSnapshot = true;

  return out;
}
