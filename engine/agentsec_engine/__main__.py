"""引擎入口：python -m agentsec_engine

由 Electron 主进程以子进程方式 spawn，通过 stdin/stdout 行分隔 JSON 通信。
"""

import multiprocessing

from .ipc import IPCServer


def main() -> None:
    # Windows / PyInstaller 下允许暴露面扫描启动可终止的 ATR worker。
    multiprocessing.freeze_support()
    IPCServer().serve_forever()


if __name__ == "__main__":
    main()
