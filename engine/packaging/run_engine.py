"""PyInstaller 冻结入口：等价于 `python -m agentsec_engine`。

打包成二进制后由 Electron 生产构建直接 spawn（无需系统 Python）。
"""

from agentsec_engine.__main__ import main

if __name__ == "__main__":
    main()
