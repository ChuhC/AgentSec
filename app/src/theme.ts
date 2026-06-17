export type ThemeSetting = "glass" | "dark" | "light" | "system";
export type ResolvedTheme = "glass" | "dark" | "light";

export function resolveTheme(setting: ThemeSetting): ResolvedTheme {
  if (setting === "system") {
    return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  }
  return setting;
}

export function applyTheme(setting: ThemeSetting): () => void {
  const set = () => {
    document.documentElement.dataset.theme = resolveTheme(setting);
  };
  set();
  if (setting !== "system") return () => {};
  const mq = window.matchMedia("(prefers-color-scheme: dark)");
  const onChange = () => set();
  mq.addEventListener("change", onChange);
  return () => mq.removeEventListener("change", onChange);
}
