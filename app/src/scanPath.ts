import type { ScanScope } from "./store";

export function canConfirmScanPath(mode: ScanScope, path: string): boolean {
  return mode === "all" || path.trim().length > 0;
}

export function applySelectedDirectory(current: string, selected: string | null): string {
  const next = selected?.trim();
  return next || current;
}
