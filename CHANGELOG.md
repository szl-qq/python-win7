# 更新记录

## v1.0.0 — 2026-11-22

首个公开版本。交付 **Python 3.13.16 (32-bit) for Windows 7 SP1**，
附实验性的 3.15.2 构建。

### 补丁内容

- 静态导入改名：`GetSystemTimePreciseAsFileTime` → `GetSystemTimeAsFileTime`（等长原地改写）
- 追加 `.w7imp` 节，把 6 个 Win8+ `KERNEL32` 导入重定向到 `win7k32shim.dll`
- 提供 `api-ms-win-core-path-l1-1-0.dll` 替身（`PathCchSkipRoot` / `PathCchCombineEx` → `shlwapi`）
- 内置 `cacert.pem`（118 张 Mozilla 根证书）+ `sitecustomize.py`，修复 Win7 上
  `CERTIFICATE_VERIFY_FAILED: unable to get local issuer certificate`
- 启用 `._pth` 里的 `import site`，使 `sitecustomize` 生效、pip 可用

### 工具与文档

- `tools/verify_imports.py`：独立复核导入表（无 Win8+ 残留 + 槽位别名 + 校验和）
- `build.sh`：一条命令从官方 embeddable 包复现整个交付包
- 打包门禁：payload 里只要还剩一个 Win8+ 静态导入就拒绝出包
- 装/卸/自检脚本兼容 PowerShell 2.0（Win7 默认版本）

### 修复（相对内部迭代）

- `check.ps1` 第 [5] 项：`cmd /c` 引号规整导致误报"文件名、目录名或卷标语法不正确"，
  退出码恒为 1。改为直接调用解释器，不再落临时文件
- `PATCH-NOTES.txt` 在 3.13 包内把 DLL 名误写为 `python315.dll`
- 补丁后未重算 PE 校验和（改为按最终字节重算）
- 自检新增第 [8] 项：打印实际加载的 CA 数量并发起真实 HTTPS 请求

### 验证

- Windows 7 SP1 真机：自检 7/7，`--version` 正常，HTTPS 200
- 压力：asyncio Proactor 100 并发文件 IO 332 ms、TCP echo 10 ms、
  `multiprocessing` spawn 1182 ms、`ThreadPoolExecutor` 400 ms
- 3.15.2：静态验证通过，真机未验证
