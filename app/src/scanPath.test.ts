import { describe, expect, it } from "vitest";

import { applySelectedDirectory, canConfirmScanPath } from "./scanPath";

describe("scan path state", () => {
  it("allows whole-machine scans without a path", () => {
    expect(canConfirmScanPath("all", "")).toBe(true);
  });

  it("rejects an empty custom path", () => {
    expect(canConfirmScanPath("custom", "")).toBe(false);
    expect(canConfirmScanPath("custom", "   ")).toBe(false);
  });

  it("keeps the current value when directory selection is cancelled", () => {
    expect(applySelectedDirectory("/existing", null)).toBe("/existing");
  });

  it("uses the directory returned by the native picker", () => {
    expect(applySelectedDirectory("", "/Users/me/agents")).toBe("/Users/me/agents");
  });
});
