# 常见问题

### 这算 CPython 的分支（fork）吗？

不算。没有一行解释器源码被修改或重编译。做法是拿官方 embeddable 包里的
`python313.dll`，只改导入表数据（导入名 + 新增节 + 描述符数组），代码段字节与官方一致。
你可以拿官方包逐字节比对，差异范围见 [verification.md](verification.md)。

### 能不能用在生产环境？

技术上可以跑，但请自行评估：

- 这是自制二进制补丁，没有上游支持，出问题只能自己排查；
- 不跟踪 CPython 的安全回补，安全性等于你构建时的上游版本；
- 签名失效，某些企业环境（应用白名单、签名强制策略）会拦。

个人项目、内网工具、嵌入式设备上的老系统，通常没问题；关键业务建议升级系统。

### 杀毒软件报毒怎么办？

改过字节的 DLL 必然失去 Authenticode 签名。部分引擎会对"无签名 + 修改过的系统 DLL 名"
给启发式告警。可以加到排除列表；如果公司策略不允许，这条路走不通。

### 32 位 Python 能装在 64 位 Win7 上吗？

能。实测环境就是 64 位 Win7 SP1 + 32 位 Python，这也是常见组合（为了兼容老插件）。

### 为什么不直接装 Python 3.8？

3.8 也已停止支持，且很多库的新版本不再提供 cp38 wheel。如果你不需要新特性，
3.8 在 Win7 上确实开箱可用，不必用本项目。

### 3.14 / 3.15 呢？

3.15.2 已构建但**未真机验证**（实验性）。3.14 未提供：它新增了更多 Win10 依赖，
需要额外补丁工作，目前不在范围内。

### 为什么 `time.time()` 精度变低了？

`GetSystemTimePreciseAsFileTime` 在 Win7 上不存在，只能退回
`GetSystemTimeAsFileTime`，精度从约 100 ns 降到系统时钟粒度（典型 15.6 ms）。

受影响：`time.time()`、`datetime.now()`、`logging` 默认时间戳、`perf_counter` **不受影响**
（它走 `QueryPerformanceCounter`）。

如果需要高精度计时，用 `time.perf_counter()` / `time.monotonic()`。

### `Pss*Snapshot` 缺失会影响什么？

那是进程快照 API（抓取线程栈、句柄等诊断信息），Win8.1 才有。CPython 用于崩溃/诊断路径。
Win7 上这些函数返回"未实现"，相关诊断能力降级，但不会崩 —— 实测 asyncio、subprocess、
multiprocessing 均正常。

### 为什么 HTTPS 之前全挂，现在好了？

不是证书过期，也不是 TLS 版本问题（包里 OpenSSL 3 支持 TLS 1.3）。是 Win7 的 ROOT
证书库太旧，缺 ISRG Root X1 这类公共根，链路找不到签发者。包里追加了 118 张 Mozilla
根证书，校验仍然开启。

### 怎么更新根证书？

用新版 [cacert.pem](https://curl.se/ca/cacert.pem) 覆盖安装目录下的同名文件即可，不用重装。
内网自签证书可以追加到该文件末尾，不要关校验。

### 能用 pip 装带 C 扩展的包吗？

能，但只能装**为 Windows 32 位 + 对应 CPython 版本**编译的 wheel
（如 `cp313-win32`）。`manylinux` 的 wheel 不适用。没有预编译包时会尝试源码编译，
需要 MSVC 或 mingw 工具链。

### 会不会影响我在 Win10/11 上用同一个包？

不会。shim 是"先探测、再转发"：系统有真 API 就原样转发，只有 Win7 才走模拟分支。

### 装了之后 `python` 命令不是我预期的版本？

Windows 上系统 PATH 优先于用户 PATH。若旧 Python 装在系统变量里，会盖住本包。
把旧路径删掉，或调整顺序后重开命令行窗口。

### 我发现某个场景仍然失败，怎么反馈？

带三样东西开 Issue：`check.bat` 的完整输出截图、`python -c "import sys;print(sys.version)"`、
以及能复现问题的最小脚本。这些信息足够定位是装载期问题、证书问题还是运行时降级。
