# 验证记录

分两部分：**你可以自己复跑的静态复核**，以及**真机实测结果**。

---

## 一、静态复核（任何人都能复跑）

### 1. 导入表里没有 Win8+ 残留

```bash
pip install pefile
python3 - <<'EOF'
import pefile
WIN8PLUS = {
    "GetSystemTimePreciseAsFileTime", "CopyFile2", "AddDllDirectory",
    "RemoveDllDirectory", "PssCaptureSnapshot", "PssQuerySnapshot",
    "PssFreeSnapshot", "GetCurrentThreadStackLimits",
}
pe = pefile.PE("build/payload-3.13.16/python313.dll")
pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
for e in pe.DIRECTORY_ENTRY_IMPORT:
    if e.dll.decode().lower() == "kernel32.dll":
        names = {i.name.decode() for i in e.imports if i.name}
        print("KERNEL32 导入数:", len(names))
        print("残留 Win8+ 项:", sorted(names & WIN8PLUS) or "无")
EOF
```

期望输出：`KERNEL32 导入数: 174`、`残留 Win8+ 项: 无`。

### 2. 描述符数组与槽位归属（别名是否真的生效）

```bash
python3 tools/verify_imports.py build/payload-3.13.16/python313.dll
```

该脚本只读不写，按装载器语义遍历全部导入描述符，验证每个 shim 重定向都精确落在
`KERNEL32` 的同一批 IAT 槽位上（槽位重叠 = 后写的 shim 会覆盖先写的占位地址）。
实际输出：

```
KERNEL32    导入 174 项   槽位 174 个
  [通过] 无 Win8+ 静态导入
shim        重定向   6 项
  [通过] IAT RVA 0x2e0108  LoadLibraryW                 <- AddDllDirectory
  [通过] IAT RVA 0x2e011c  Sleep                        <- RemoveDllDirectory
  [通过] IAT RVA 0x2e0138  WriteFile                    <- PssQuerySnapshot
  [通过] IAT RVA 0x2e0164  GetCurrentDirectoryW         <- PssFreeSnapshot
  [通过] IAT RVA 0x2e01a8  GetFullPathNameW             <- PssCaptureSnapshot
  [通过] IAT RVA 0x2e026c  GetVolumePathNameW           <- CopyFile2
PE 校验和   stored=0x005525f4 calc=0x005525f4  [通过]

结果: PASS
```

左列是 `KERNEL32` 里被换上的占位函数（保证 Win7 能解析成功），右列是覆盖同一槽位的
shim 实现。两者地址相同，覆盖才成立。

### 3. PE 校验和自洽

```bash
python3 -c "
import pefile; p='build/payload-3.13.16/python313.dll'; pe=pefile.PE(p)
print('stored=%#010x calc=%#010x 一致=%s' % (pe.OPTIONAL_HEADER.CheckSum, pe.generate_checksum(),
      pe.OPTIONAL_HEADER.CheckSum==pe.generate_checksum()))"
```

### 4. 与官方二进制逐字节比对

`python313.dll` 与官方包里的同名文件相比，差异应当**只出现在**：

- 导入名表里那条 `GetSystemTimePreciseAsFileTime` 的记录（31 → 22 字节 + 补 0）；
- 文件尾新增的 `.w7imp` 节（3.13.16 为 1504 字节）；
- 节表末尾新增的一项、`SizeOfImage`、数据目录[1]、`NumberOfSections`、PE 校验和。

代码段（`.text`）**一个字节都不应改变**。可以用 `cmp -l` 或脚本列出差异区间自查。

### 5. shim 导出与调用约定

```bash
i686-w64-mingw32-objdump -p shim/win7k32shim.dll | sed -n '/Export Address Table/,/^$/p'
i686-w64-mingw32-objdump -d shim/win7k32shim.dll | grep -E "ret +\\$?0x"
```

期望：7 个导出名无 `@N` 修饰；各导出函数以 `ret N`（`N` 为参数总字节数）返回。

---

## 二、真机实测（Windows 7 SP1，32 位 Python）

### 自检 7 项

| 项 | 结果 |
|---|---|
| `python.exe` SHA256 | PASS |
| `python313.dll` SHA256 | PASS |
| `win7k32shim.dll` / `api-ms-win-core-path-l1-1-0.dll` | 均存在 |
| `python.exe --version` | `Python 3.13.16`，退出码 0 |
| 模块导入（os/time/socket/ssl/sqlite3/hashlib/json） | OK |
| 根证书 | 已加载 132 张（系统 14 + 内置 118） |
| HTTPS 实测 | HTTP 200 |

### 压力/兼容性测试

| 场景 | 结果 |
|---|---|
| asyncio Proactor + 100 并发文件 IO | 332 ms |
| asyncio TCP echo | 10 ms |
| `multiprocessing` spawn | 1182 ms |
| `ThreadPoolExecutor` | 400 ms |
| socket 选项 + 超时 | 正常 |
| HTTPS（`ssl` / `urllib`） | 200（修复前全挂） |

结论：`ProactorEventLoop`（依赖 IOCP，Win7 自带）、`spawn` 子进程、线程池、
socket 全链正常；`psutil` 未安装时的跳过属预期。

### 修复前的失败样本（供对照）

同一台机器、同一脚本、未加 CA 补丁时：

```
ssl    -> CERTIFICATE_VERIFY_FAILED: unable to get local issuer certificate
urllib -> 同上
```

在"只保留旧根证书"的隔离环境里可稳定复现该报错；追加 `cacert.pem` 后
`https://curl.se`、`https://pypi.org/simple/` 均返回 200，CA 池由 1 张变为 118 张。

---

## 三、未验证项（如实说明）

| 项 | 状态 |
|---|---|
| 3.15.2 真机启动 | **未验证**。仅完成静态验证：导入描述符 26 个、`KERNEL32` 183 项、7 项重定向、门禁 PASS |
| 长路径 `\\?\` 语义 | 未逐项验证，预计部分降级 |
| ETW / 事件注册 | 未验证，`Pss*Snapshot` 相关能力确认缺失 |
| 无 SP1 / 未装 KB4474419 的 Win7 | 未验证，VC++ 运行库很可能装不上 |
| 32 位 Win7 原生系统 | 未验证（实测机为 64 位 Win7 + 32 位 Python） |

如果你在别的环境跑通了（或跑不通），欢迎在 Issues 里带上 `check.bat` 输出与
`python --version`，这对补全矩阵很有用。
