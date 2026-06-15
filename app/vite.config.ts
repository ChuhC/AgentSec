import { cpSync, existsSync, mkdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import electron from "vite-plugin-electron";
import renderer from "vite-plugin-electron-renderer";

const __root = path.dirname(fileURLToPath(import.meta.url));

/** preload 必须是 CommonJS；复制 electron/preload.cjs → dist-electron/ */
function copyPreload() {
  const src = path.join(__root, "electron/preload.cjs");
  const destDir = path.join(__root, "dist-electron");
  if (!existsSync(destDir)) mkdirSync(destDir, { recursive: true });
  cpSync(src, path.join(destDir, "preload.cjs"));
}

export default defineConfig({
  plugins: [
    react(),
    {
      name: "copy-preload",
      buildStart() {
        copyPreload();
      },
      configureServer() {
        copyPreload();
      },
    },
    electron([
      {
        // 主进程（package.json type=module，可输出 ESM）
        entry: "electron/main.ts",
        vite: {
          build: {
            rollupOptions: {
              output: { format: "es" },
            },
          },
        },
      },
    ]),
    renderer(),
  ],
});
