import { contextBridge, ipcRenderer } from "electron";

export type EngineEvent = { event: string; data: any };

contextBridge.exposeInMainWorld("agentsec", {
  request: (method: string, params?: any) =>
    ipcRenderer.invoke("engine-request", method, params ?? {}),
  onEvent: (cb: (e: EngineEvent) => void) => {
    const listener = (_e: unknown, payload: EngineEvent) => cb(payload);
    ipcRenderer.on("engine-event", listener);
    return () => ipcRenderer.removeListener("engine-event", listener);
  },
});
