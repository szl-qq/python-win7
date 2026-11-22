# 原理详解

本文说明三个补丁各自的动机、实现与边界，以及为什么选择这些做法。

---

## 0. 前情：为什么"支持 32 位"和"支持 Win7"是两件事

PEP 11 的平台分级里，`i686-pc-windows-msvc` 一直属于 Tier 1 —— 官方每个版本都发布 32 位
二进制。所以看到 "3.13 不支持 32 位" 这种说法可以直接否定。

真正变化的是**最低系统版本**：

| 版本 | 最低 Windows |
|---|---|
| 3.8 及以前 | Windows 7 |
| 3.9 – 3.13 | Windows 8.1 |
| 3.14 起 | Windows 10 |

`python.exe` 在 Win7 上的失败发生在 `main` 之前：Windows 装载器解析导入表时，只要有
一个 `KERNEL32` 导出在目标系统上不存在，就返回 `STATUS_ENTRYPOINT_NOT_FOUND`
（`0xC0000135`），进程直接退出。用户看到的现象是"双击闪一下就没了，命令行也没有任何输出"——
既没有 Python 的报错，也没有 Windows 的提示框。

因此补丁的目标不是"让代码跑得对"，而是"让装载器肯加载"。

---

## 1. 静态导入改名（补丁 A）

`python313.dll` 静态导入了 `KERNEL32!GetSystemTimePreciseAsFileTime`（Win8 起提供）。
Win7 上有个语义最接近的 `KERNEL32!GetSystemTimeAsFileTime`，两者签名都是
`void (LPFILETIME)`，只是精度不同（100 ns 级 vs 系统时钟粒度）。

**为什么用"等长原地改写"而不是重建导入表：**

- 导入名存放在 `.rdata` 的字符串池里，被 `IMAGE_IMPORT_BY_NAME` 以 RVA 引用。
  如果新名字更长，就得搬动字符串、扩张节、并修正所有相关 RVA —— 改动面大、风险高。
- 旧名 31 字节，新名 22 字节，**更短**。原地写入新名字 + 9 个 `\0` 即可：
  RVA 不变，节不扩，其余导入零影响。
- 结束后 PE 校验和按最终字节重算。

代码里必须**精确定位到导入名表**里那一条记录（`OriginalFirstThunk` 指向的
`IMAGE_THUNK_DATA` → `IMAGE_IMPORT_BY_NAME`），不能全文搜索字符串：
DLL 里同名字符串可能出现在调试信息或其他数据中，盲搜会改错地方。

**代价**：`time.time()` 精度降到系统时钟粒度（典型 15.6 ms）。
`time.perf_counter()` 不受影响 —— 它用 `QueryPerformanceCounter`，该 API Win7 已有，
在导入表里也原样保留。

---

## 2. 追加节 + 描述符别名（补丁 B/C）

剩下 6 个（3.13）或 7 个（3.15）导入在 Win7 上**没有任何名字相近的替代品**，
必须换成我们自己的实现。这里不能简单地把导入名改成别的系统函数 —— 参数个数、
返回类型都对不上，栈会失衡。

采用的做法是把这些导入**重定向到一个新的转发 DLL**，而重定向过程完全在 PE 结构层完成：

1. **追加一个新节 `.w7imp`**（3.13.16 上 1504 字节），内容依次是：
   - `KERNEL32` 的新 ILT：原有 174 项；其中 6 项换成"占位名"。
     占位名必须是 Win7 上确实存在的 KERNEL32 导出，且**参数字节数尽量对上**
     （例如 `CopyFile2` 是 3 参 12 字节，选 `GetVolumePathNameW`），
     即使两者永不被真正调用，也能保证万一被误调时不破坏栈。
   - 6 个新描述符，每个 `Name` 指向 `win7k32shim.dll`，各含一项导入，
     其 `FirstThunk` **精确指向原 IAT 中那 4 字节槽位的 RVA**。
   - 完整的描述符数组：原 24 个 + 6 个新 + 1 个结束项 = 25 项。
2. **导入目录（数据目录[1]）指向新数组**，`SizeOfImage` 与节表同步更新，
   PE 校验和重算。

**为什么这样能生效：** Windows 装载器按描述符数组顺序逐个处理，对每个 DLL
把解析到的函数地址写进对应的 `FirstThunk` 槽位。`KERNEL32` 的描述符先被处理，
把占位函数的地址写进那 6 个槽位；随后 `win7k32shim.dll` 的描述符指向**同样的槽位**，
把 shim 的实现覆盖上去。最终生效的是后者。

这一招的好处是**完全不碰 IAT 的位置**：所有调用点（call [IAT+offset]）不需要任何修改，
也不用处理重定位或增量重链接 —— 我们只改了数据，没改一行代码，函数体的字节与官方完全一致。

**验证**：打包门禁会重新解析产物导入表，确认 `KERNEL32` 里 0 个 Win8+ 残留项；
另外有一个独立脚本按装载器语义遍历全部描述符，核对槽位最终归属。

---

## 3. 先探测、再转发（shim 的设计）

`win7k32shim.dll` 导出 7 个函数。每个函数第一次被调用时执行 `GetProcAddress`：

- **系统有真实现**（Win8+）：直接转发，行为与官方 100% 一致，零语义损失。
- **系统没有**（Win7）：走等价实现或明确失败。

| 函数 | Win7 分支 | 语义差异 |
|---|---|---|
| `CopyFile2` | `CopyFileW`，错误码转 HRESULT | 无进度回调、无 `COPY_FILE_*` 标志 |
| `AddDllDirectory` | `SetDllDirectoryW` | **全局作用域**，不是 per-call 令牌 |
| `RemoveDllDirectory` | `SetDllDirectoryW(NULL)` | 会清掉别处设过的目录 |
| `PssCaptureSnapshot` / `PssQuerySnapshot` | 返回 `ERROR_CALL_NOT_IMPLEMENTED` | 进程快照能力缺失 |
| `PssFreeSnapshot` | 返回 `ERROR_SUCCESS`（空实现） | 与上一条配套，避免调用方二次报错 |
| `GetCurrentThreadStackLimits` | 读 TEB 的 `StackBase` / `StackLimit` | 与 Win8 实现同源，等价取值 |

最后一条值得单独说：`GetCurrentThreadStackLimits` 在 Win8 的内部实现就是读
当前线程 TEB 的这两个字段。我们在 Win7 上读同样两个字段，得到的是**同一个值**，
不是估算。

调用约定全部是 stdcall，`.def` 里按名字导出（链接时 `-Wl,--kill-at` 去掉 `@N` 修饰），
导出函数的 `ret N` 已用反汇编逐一核对，与 CPython 的调用点匹配。

第三个 DLL `api-ms-win-core-path-l1-1-0.dll` 是同样的思路：Win7 上这个 API set
整个不存在，而 `python313.dll` 静态导入了它的 `PathCchSkipRoot` 与 `PathCchCombineEx`。
shim 把两者转发到 Win7 自带的 `shlwapi!PathSkipRootW` / `PathCombineW`。

---

## 4. 信任锚（补丁 D）—— 与"能不能启动"无关，但同样是硬阻塞

即使 Python 正常启动，Win7 上 `pip install`、`urllib`、`requests`、`httpx` 也会全线报：

```
[SSL: CERTIFICATE_VERIFY_FAILED] unable to get local issuer certificate
```

这不是证书过期，也不是 TLS 版本问题（包里的 `libssl-3.dll` 是 OpenSSL 3，
在用户态实现 TLS 1.3，与系统版本无关）。原因是 **Win7 的 ROOT 证书库冻结在多年前**，
缺少 ISRG Root X1 这类后来才出现的公共根；于是中间证书找不到签发者，链路断在根部。

处理方式：

- 随包提供 `cacert.pem`（Mozilla 根证书快照，118 张），与 `python.exe` 同目录。
- `sitecustomize.py` 在解释器启动时把它 `load_verify_locations()` 进默认 SSL 上下文。
- **只追加，不替换**：系统已有证书继续有效，校验强度不变，也不调用任何 `CERT_NONE`。
- 同时设置 `SSL_CERT_FILE` / `REQUESTS_CA_BUNDLE` / `CURL_CA_BUNDLE`（仅当用户未自行设置），
  以覆盖 requests / pip 等库的默认行为。

要让 `sitecustomize` 被加载，embeddable 布局必须放开 `._pth` 里的 `import site`
——这正是官方 embeddable 包注释里写的那行。启用后 `Lib/site-packages`
也会自动进入 `sys.path`，顺带让 pip 可用。

---

## 5. 为什么不用别的方案

| 方案 | 为什么不用 |
|---|---|
| 重新编译 CPython（`PCbuild` + `_WIN32_WINNT=0x0601`） | 需要 VS 工具链与完整依赖；且 CPython 代码里大量 `#if` 依赖 Win8+ 类型定义，改起来远不止一处；产物也不再是官方二进制，难以对照 |
| API hooking / Detours | 需要在运行时注入，晚于装载器解析导入表 —— 对 `0xC0000135` 无效，进程根本起不来 |
| 改函数体打补丁（inline patch） | 需要处理重定位、代码校验、多线程一致性，且改动代码段更容易被反作弊/杀软判定为恶意 |
| 保留旧版 Python 3.8 | 3.8 也已 EOL，且拿不到新 wheel；本项目存在的意义在于新版 |
| 只做 PyInstaller 打包 | 不解决"解释器本身在 Win7 上起不来"，那是更下游的问题 |

本项目选择"只改导入表数据 + 外部转发 DLL"这条路，代价最小、可审计性最好：
代码段字节与官方完全一致，任何人可以拿官方包逐字节比对，差异只出现在导入表与新增节里。

---

## 6. 边界与未验证项

- 3.13.16 已在真实 Win7 SP1 上验证；3.15.2 仅完成静态验证（见 `verification.md`）。
- 依赖 Win8+ 语义的特性会降级：长路径 `\\?\` 前缀的部分行为、ETW 注册、进程快照。
- 改过的 DLL 失去数字签名，这是任何二进制补丁的必然结果。
- 本项目不跟踪 CPython 的安全回补；安全性等同你构建时选定的上游版本。
