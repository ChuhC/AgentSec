const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("agentsec", {
  platform: process.platform,
  request: (method, params) =>
    ipcRenderer.invoke("engine-request", method, params ?? {}),
  onEvent: (cb) => {
    const listener = (_e, payload) => cb(payload);
    ipcRenderer.on("engine-event", listener);
    return () => ipcRenderer.removeListener("engine-event", listener);
  },
  updater: {
    getInfo: () => ipcRenderer.invoke("updater-get-info"),
    check: () => ipcRenderer.invoke("updater-check"),
    download: () => ipcRenderer.invoke("updater-download"),
    install: () => ipcRenderer.invoke("updater-install"),
    onStatus: (cb) => {
      const listener = (_e, payload) => cb(payload);
      ipcRenderer.on("updater-event", listener);
      return () => ipcRenderer.removeListener("updater-event", listener);
    },
  },
});
