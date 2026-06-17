import { messages, type Locale, type MessageParams, type MessageTree } from "./messages";
import {
  createLocaleLayer,
  getLocaleLayerFactory,
  setLocaleLayerFactory,
} from "./createLocaleLayer";
import type { LocaleDataLayer, LocaleLayerFactory, TFn } from "./types";

export type { Locale, MessageParams, LocaleDataLayer, LocaleLayerFactory, TFn, MessageTree };

type Path = string;

function getPath(tree: unknown, path: Path): string | undefined {
  const parts = path.split(".");
  let cur: unknown = tree;
  for (const p of parts) {
    if (cur == null || typeof cur !== "object") return undefined;
    cur = (cur as Record<string, unknown>)[p];
  }
  return typeof cur === "string" ? cur : undefined;
}

export function createT(locale: Locale) {
  return (path: Path, params?: MessageParams): string => {
    let text = getPath(messages[locale], path) ?? getPath(messages.zh, path) ?? path;
    if (params) {
      for (const [k, v] of Object.entries(params)) {
        text = text.replaceAll(`{${k}}`, String(v));
      }
    }
    return text;
  };
}

export function localeFromSetting(value: string): Locale {
  if (value === "en" || value === "English") return "en";
  return "zh";
}

export function themeFromSetting(value: string): "glass" | "dark" | "light" | "system" {
  if (value === "dark" || value === "深色") return "dark";
  if (value === "light" || value === "浅色") return "light";
  if (value === "system" || value === "跟随系统") return "system";
  return "glass";
}

export function scopeFromSetting(value: string): "all" | "custom" {
  if (value === "custom" || value === "自定义路径") return "custom";
  return "all";
}

export {
  createLocaleLayer,
  getLocaleLayerFactory,
  setLocaleLayerFactory,
};

export function buildLocaleLayer(locale: Locale, t?: TFn): LocaleDataLayer {
  const translate = t ?? createT(locale);
  return getLocaleLayerFactory()(locale, translate);
}
