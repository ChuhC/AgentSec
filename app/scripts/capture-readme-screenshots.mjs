#!/usr/bin/env node
/**
 * 生成 README 用界面截图（中英文）。
 * 依赖：npm run build && playwright chromium
 *
 * 用法（仓库根目录）：
 *   python3 scripts/export-demo-snapshot.py
 *   cd app && npm run build && npm run screenshots
 */
import { spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import { mkdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const APP_ROOT = path.resolve(__dirname, "..");
const REPO_ROOT = path.resolve(APP_ROOT, "..");
const OUT_ROOT = path.join(REPO_ROOT, "docs", "screenshots");
const SNAPSHOT_PATH = path.join(APP_ROOT, "scripts", "fixtures", "demo-snapshot.json");
const VIEWPORT = { width: 1440, height: 900 };

const SCENES = [
  { id: "01-scan-home", route: "scan-home", snapshot: false },
  { id: "02-results", route: "results", snapshot: true },
  { id: "03-threat-list", route: "threat-list", snapshot: true },
  { id: "04-vuln-list", route: "vuln-list", snapshot: true },
  { id: "05-agent-list", route: "agent-list", snapshot: true },
  { id: "06-agent-workbench", route: "agent-workbench", snapshot: true, agent: "hermes" },
  { id: "07-settings", route: "settings", snapshot: false },
];

const LOCALES = [
  { code: "zh", label: "中文" },
  { code: "en", label: "English" },
];

function waitForServer(url, timeoutMs = 60_000) {
  return new Promise((resolve, reject) => {
    const start = Date.now();
    const tick = async () => {
      try {
        const res = await fetch(url);
        if (res.ok) return resolve();
      } catch {
        /* retry */
      }
      if (Date.now() - start > timeoutMs) reject(new Error(`Server not ready: ${url}`));
      else setTimeout(tick, 400);
    };
    tick();
  });
}

function startPreview() {
  const child = spawn("npm", ["run", "preview", "--", "--host", "127.0.0.1", "--port", "4173"], {
    cwd: APP_ROOT,
    stdio: "pipe",
    env: { ...process.env, BROWSER: "none" },
  });
  return child;
}

async function main() {
  const demoSnapshot = JSON.parse(readFileSync(SNAPSHOT_PATH, "utf8"));

  mkdirSync(path.join(OUT_ROOT, "zh"), { recursive: true });
  mkdirSync(path.join(OUT_ROOT, "en"), { recursive: true });

  const preview = startPreview();
  const baseUrl = "http://127.0.0.1:4173";

  try {
    await waitForServer(baseUrl);
    const browser = await chromium.launch();
    const context = await browser.newContext({
      viewport: VIEWPORT,
      deviceScaleFactor: 2,
    });

    for (const locale of LOCALES) {
      for (const scene of SCENES) {
        const page = await context.newPage();
        const params = new URLSearchParams({
          screenshot: "1",
          route: scene.route,
          lang: locale.code,
          theme: "glass",
        });
        if (scene.snapshot) params.set("snapshot", "1");
        if (scene.agent) params.set("agent", scene.agent);

        await page.addInitScript((snap) => {
          window.agentsec = {
            request: async (method) => {
              if (method === "snapshot.get") return { snapshot: snap };
              return {};
            },
            onEvent: () => () => {},
          };
        }, demoSnapshot);

        const url = `${baseUrl}/?${params}`;
        await page.goto(url, { waitUntil: "networkidle" });
        await page.waitForTimeout(600);

        const outFile = path.join(OUT_ROOT, locale.code, `${scene.id}.png`);
        await page.screenshot({ path: outFile, fullPage: false });
        console.log(`✓ ${locale.code}/${scene.id}.png`);
        await page.close();
      }
    }

    await browser.close();
    console.log(`\nScreenshots saved to ${OUT_ROOT}`);
  } finally {
    preview.kill("SIGTERM");
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
