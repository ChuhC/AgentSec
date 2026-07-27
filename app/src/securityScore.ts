/** Shared 0–100 risk deduction used by result and per-Agent scores. */
export function computeSecurityScore(
  high: number,
  medium: number,
  low: number,
  cveHigh: number
): number {
  const threatDeduction = Math.min(75, high * 4 + medium * 2 + low);
  const cveDeduction = Math.min(25, cveHigh * 6);
  return Math.max(15, Math.min(100, 100 - threatDeduction - cveDeduction));
}
