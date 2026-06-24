import React from "react";
import ReactDOM from "react-dom/client";
import { App } from "./App";
import { AppProvider } from "./store";
import { themeFromSetting } from "./i18n";
import { applyTheme } from "./theme";
import "./styles.css";

document.documentElement.dataset.platform =
  window.agentsec?.platform ?? "unknown";

try {
  const raw = localStorage.getItem("agentsec.settings");
  if (raw) {
    const parsed = JSON.parse(raw) as { theme?: string };
    applyTheme(themeFromSetting(String(parsed.theme ?? "glass")));
  } else {
    applyTheme("glass");
  }
} catch {
  applyTheme("glass");
}

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <AppProvider>
      <App />
    </AppProvider>
  </React.StrictMode>
);
