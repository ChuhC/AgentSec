interface OpenDialogResult {
  canceled: boolean;
  filePaths: string[];
}

interface OpenDialogOptions {
  properties: Array<"openDirectory">;
}

type ShowOpenDialog = (options: OpenDialogOptions) => Promise<OpenDialogResult>;

export async function pickScanDirectory(showOpenDialog: ShowOpenDialog): Promise<string | null> {
  const result = await showOpenDialog({ properties: ["openDirectory"] });
  if (result.canceled) return null;
  return result.filePaths[0] || null;
}
