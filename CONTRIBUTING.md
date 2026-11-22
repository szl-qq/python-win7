# 贡献指南

## 报告问题

请在 Issue 里附上：

1. `check.bat` 的完整输出（截图或文本，别只贴最后一行）；
2. `python -c "import sys;print(sys.version)"` 的输出；
3. 系统信息：Win7 是否 SP1、是否装了 KB4474419、32/64 位；
4. 能复现问题的最小脚本。

缺 1、2 两项基本无法定位 —— 装载期失败与运行时降级的表现完全不同。

## 提交代码

- 改 `shim/*.c` 后务必重跑 `bash shim/build_shim.sh`，并核对导出与 `ret N`：
  ```bash
  i686-w64-mingw32-objdump -p shim/win7k32shim.dll | sed -n '/Export Address Table/,/^$/p'
  ```
- 新增一个需要重定向的导入时，`REDIRECT` 里的**占位函数参数字节数必须对齐**
  （见 `tools/add_win7_import_shim.py` 注释），否则误调时会破坏栈。
- 任何二进制改动后跑 `python3 tools/verify_imports.py <dll>`，必须 `PASS`。
- 不要把 `build/`、`dist/`、`vc_redist.x86.exe`、编译出的 `.dll` 提交进仓库。

## 新增 Python 版本支持

1. 下载对应版本的官方 embeddable 32 位包；
2. 对比 `pythonXY.dll` 的 `KERNEL32` 导入，找出新增的 Win8+ 项；
3. 在 `REDIRECT` 补条目，并在 `shim/win7k32shim.c` 里实现对应导出（记得改 `.def`）；
4. `VER=<版本> ./build.sh`，`verify_imports.py` 通过后，在**真机 Win7** 上跑一遍
   `check.bat` 与压力脚本；
5. 在 `docs/verification.md` 补上验证记录，注明哪些项未验证。
