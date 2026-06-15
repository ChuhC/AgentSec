"""引擎入口：python -m agentsec_engine

由 Electron 主进程以子进程方式 spawn，通过 stdin/stdout 行分隔 JSON 通信。
"""

from .ipc import IPCServer


def main() -> None:
    IPCServer().serve_forever()


if __name__ == "__main__":
    main()
