import { createRequire } from "node:module";
import { describe, expect, it } from "vitest";

const require = createRequire(import.meta.url);

describe("patched brace-expansion compatibility wrapper", () => {
  it("supports both legacy CommonJS and modern named/default consumers", () => {
    const braceExpansion = require("brace-expansion");

    expect(braceExpansion).toBeTypeOf("function");
    expect(braceExpansion.default).toBe(braceExpansion);
    expect(braceExpansion.expand).toBe(braceExpansion);
    expect(braceExpansion("file-{a,b}.txt")).toEqual([
      "file-a.txt",
      "file-b.txt",
    ]);
  });

  it("keeps the patched expansion resource limits enabled", () => {
    const braceExpansion = require("brace-expansion");

    expect(braceExpansion.EXPANSION_MAX).toBeGreaterThan(0);
    expect(braceExpansion.EXPANSION_MAX_LENGTH).toBeGreaterThan(0);
    expect(braceExpansion.EXPANSION_MAX_LENGTH).toBeLessThan(
      Number.MAX_SAFE_INTEGER,
    );
    expect(
      braceExpansion("{a,b}".repeat(20), { maxLength: 10 }),
    ).toEqual([]);
  });

  it("works through both legacy and modern minimatch consumers", () => {
    const modernMinimatch = require("minimatch");
    const asarRequire = createRequire(require.resolve("@electron/asar"));
    const legacyMinimatch = asarRequire("minimatch");

    expect(
      modernMinimatch.minimatch("file-a.txt", "file-{a,b}.txt"),
    ).toBe(true);
    expect(legacyMinimatch("file-a.txt", "file-{a,b}.txt")).toBe(true);
  });
});
