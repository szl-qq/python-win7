# python-win7

**在 Windows 7 SP1 上跑官方 32 位 CPython 3.13 —— 不改 CPython 源码，也不重新编译它。**

[English](README.md) · [原理详解](docs/how-it-works.md) · [构建方法](docs/build.md) · [验证记录](docs/verification.md) · [常见问题](docs/faq.md)

---

## 问题在哪

| 事实 | 说明 |
|---|---|
| 32 位 Windows 仍是 Tier 1 | PEP 11 里 `i686-pc-windows-msvc` 一直是支持平台，3.13 和 3.15 都照常发布 32 位安装包与 embeddable 包。**"32 位"从来不是问题。** |
| 支持门槛抬高了 | 3.9 起最低 Windows 8.1，3.14 起最低 Windows 10。Win7 早已不在支持范围。 |
| 失败方式是静默的 | DLL 里静态导入了 Win8+ 才有的函数，装载器在进入 `main` **之前**就拒绝加载，表现为双击一闪而过、`--version` 一个字符都不输出（`0xC0000135`）。没有报错、没有回溯。 |

所以要做的事很窄：从一个 DLL 里摘掉那几个 Win8/8.1 独占的依赖，再把这套 Win7 从未收到过的根证书补回去。

## 具体缺什么

`python313.dll` 里有 6 个导入（3.15 为 7 个），外加一整个 DLL：

| Win7 上缺失 | 引入版本 | 处理方式 |
|---|---|---|
| `GetSystemTimePreciseAsFileTime` | 8 | 原地等长改名为 `GetSystemTimeAsFileTime`（签名一致） |
| `CopyFile2` | 8 | shim → `CopyFileW`，HRESULT 映射 |
| `AddDllDirectory` / `RemoveDllDirectory` | 8 | shim → `SetDllDirectoryW`（全局作用域，非 per-call） |
| `PssCaptureSnapshot` / `PssQuerySnapshot` / `PssFreeSnapshot` | 8.1 | shim 返回 `ERROR_CALL_NOT_IMPLEMENTED` |
| `GetCurrentThreadStackLimits`（仅 3.15） | 8 | shim 读 TEB 的 `StackBase`/`StackLimit`，与 Win8 实现同源 |
| `api-ms-win-core-path-l1-1-0.dll` | 8 | 独立 shim，转发 `PathCchSkipRoot`/`PathCchCombineEx` 到 `shlwapi` |

缺任何一个，进程都会在加载阶段直接死掉。

## 怎么做的

**一、导入表手术** —— 不搬代码、不动重定位。

- 导入名**原地等长改写**（31 字节 → 22 字节 + 9 个 `\0`），镜像里所有 RVA 继续有效。
- 末尾追加 `.w7imp` 节，写入一套新的 `IMAGE_IMPORT_DESCRIPTOR` 数组：6 个重定向项各自拥有指向 `win7k32shim.dll` 的描述符，`FirstThunk` **精确对准原来的 IAT 槽位**。
- 装载器按数组顺序处理：`KERNEL32` 先写入占位地址，shim 描述符随后覆盖同一个 4 字节槽位，最终留下的是 shim 的实现。
- PE 校验和按最终字节重算；打包前有一道门禁：全量扫描 174 个 KERNEL32 导入，只要还剩一个 Win8+ 项就拒绝出包。

**二、先探测、再转发** —— 同一份二进制在 Win8/10/11 上不变差。

每个 shim 导出首次调用时 `GetProcAddress` 探测：系统有真实现就原样转发，没有（Win7）才走模拟分支。调用约定（stdcall、`ret N`）已用反汇编逐一核对。

**三、补回信任锚** —— 这才是"Python 能跑了但 HTTPS 全挂"的原因。

Win7 的 ROOT 证书库停留在多年前，缺 ISRG Root X1 这类公共根，于是**所有**新证书链都被判定为"无法获取本地颁发者证书"。包里带 `cacert.pem`（118 张 Mozilla 根证书），并由 `sitecustomize.py` 在解释器启动时**追加**进默认 SSL 上下文——是追加不是替换，也不关闭校验。`check.bat` 第 [8] 项会打印实际加载的 CA 数量并发起一次真实 HTTPS 请求。

## 状态

| 构建 | 状态 |
|---|---|
| **3.13.16（32 位）** | **稳定** —— 已在真实 Win7 SP1 机器上验证；自检 7/7，压力测试通过 |
| 3.15.2（32 位） | 实验性 —— 已构建并完成静态验证，**尚未**在真机运行 |

真机自检输出（Win7 SP1 实机截图）：

```
[2] python.exe            SHA256: PASS
[3] python313.dll         SHA256: PASS
[4] 两个 shim 均存在
[5] --version:            Python 3.13.16   退出码 0
[6] 模块自检(os/time/socket/ssl/sqlite3/hashlib/json):  OK 3.13.16
[8] cacert.pem 存在 · 已加载 CA: 132 · HTTPS: 200
```

压力测试（同一台机器）：asyncio Proactor 100 并发文件操作 332 ms · asyncio TCP echo 10 ms · `multiprocessing` spawn 1182 ms · `ThreadPoolExecutor` 400 ms · socket 选项与超时正常。

## 安装

1. 从 [Releases](../../releases) 下载 `Python-3.13.16-win32-win7.zip`。
2. 解压后运行 `install.bat`（自动提权：装 VC++ 运行库 → 复制文件 → 写用户 PATH → 校验哈希 → 试跑）。
3. 运行 `check.bat`，应看到 `Python 3.13.16`，第 [8] 项 HTTPS 返回 200。

默认装到 `C:\Python313-Win7`，可 `install.bat D:\Python313` 改路径。完整日志见 `install.log`。

> 需要 Windows 7 **SP1** + KB4474419（SHA-2 支持），否则 VC++ 运行库安装包会报签名不受信任。

## 从源码构建

依赖：Python 3 + `pefile`、`i686-w64-mingw32-gcc`、`curl`、`unzip`。

```bash
pip install pefile
./build.sh                 # 下载官方 embeddable 包 → 打补丁 → 出交付 zip
VER=3.15.2 ./build.sh      # 构建其他已支持的版本
```

产物在 `dist/Python-<ver>-win32-Win7-补丁版.zip`。分步说明见 [docs/build.md](docs/build.md)。

## 已知限制

- `time.time()` 精度从约 1 µs 降到系统时钟粒度（约 15.6 ms）。`time.perf_counter()` 不受影响，它走 `QueryPerformanceCounter`，Win7 本来就有。
- `Pss*Snapshot` 系列返回"未实现"，依赖它的诊断功能降级，但不会崩。
- `python313.dll` 的 Authenticode 签名已失效（字节变了），杀软可能提示，属预期。
- 仍需要 VC++ 2015-2022 运行库（UCRT），缺了同样是静默 `0xC0000135`。
- **不是安全维护分支**：这里不提供 CPython 的 Win7 安全回补，补丁级别等于构建时的上游版本。

## 常见问题

**这是 CPython 的分支吗？** 不是。就是官方二进制改了导入表再打包，标准库与解释器字节码未动。

**会不会让 Win10/11 上的 Python 变差？** 不会。系统有真 API 时 shim 直接转发。

**为什么不直接用 Python 3.8？** 3.8 同样已停止支持；3.13 有更新的标准库和可用的 wheel。如果你的机器只需要 3.8，那确实不用折腾。

**这个修了 TLS 1.3 吗？** 没有——TLS 1.3 不是病因。包里的 `libssl-3.dll` 是 OpenSSL 3，用户态实现 TLS 1.3，与系统版本无关。坏的是**信任锚**，修的也是它。

**能用 pip 吗？** 能。包里已启用 `site`，直接跑 `get-pip.py` 即可；老机器建议换国内镜像源。

## 目录结构

```
shim/     两个转发 DLL 的 C 源码与 .def，以及 build_shim.sh
tools/    add_win7_import_shim.py（PE 手术）、build_payload.py、make_python_pkg.py、sitecustomize.py
certs/    cacert.pem（Mozilla 根证书包）
docs/     原理、构建、验证、FAQ
build.sh  一条命令完成可复现构建
```

## 许可

脚本、shim 源码与文档：MIT。发布的二进制是打过补丁的 CPython，仍遵循 PSF License。第三方组件与条款见 [NOTICE.md](NOTICE.md)。
