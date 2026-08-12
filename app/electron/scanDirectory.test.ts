import { describe, expect, it, vi } from "vitest";

import { pickScanDirectory } from "./scanDirectory";

describe("pickScanDirectory", () => {
  it("opens a directory-only native picker and returns the selected directory", async () => {
    const showOpenDialog = vi.fn().mockResolvedValue({
      canceled: false,
      filePaths: ["/tmp/agents"],
    });

    await expect(pickScanDirectory(showOpenDialog)).resolves.toBe("/tmp/agents");
    expect(showOpenDialog).toHaveBeenCalledWith(
      expect.objectContaining({ properties: ["openDirectory"] })
    );
  });

  it("returns null when selection is cancelled", async () => {
    const showOpenDialog = vi.fn().mockResolvedValue({ canceled: true, filePaths: [] });
    await expect(pickScanDirectory(showOpenDialog)).resolves.toBeNull();
  });

  it("returns null when the picker completes without a directory", async () => {
    const showOpenDialog = vi.fn().mockResolvedValue({ canceled: false, filePaths: [] });
    await expect(pickScanDirectory(showOpenDialog)).resolves.toBeNull();
  });
});
