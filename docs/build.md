# 构建方法

## 前置要求

| 依赖 | 用途 | 获取方式 |
|---|---|---|
| Python 3.8+ | 跑打补丁与打包脚本 | — |
| `pefile` | 解析/重写 PE 结构 | `pip install pefile` |
| `i686-w64-mingw32-gcc` | 交叉编译 shim | Debian/Ubuntu: `apt install gcc-mingw-w64-i686`；macOS: `brew install mingw-w64`；Windows: MSYS2 |
| `curl`、`unzip` | 下载并解包官方二进制 | 系统自带或包管理器 |

不需要 Visual Studio，也不需要 CPython 源码。

## 一条命令

```bash
./build.sh
```

它依次做六件事：

```
[1/6] 下载 python-3.13.16-embed-win32.zip        -> build/
[2/6] 下载 vc_redist.x86.exe                     -> 仓库根目录
[3/6] 解包官方 embeddable                         -> build/embed-3.13.16/
[4/6] 编译两个 shim                               -> shim/*.dll
[5/6] 生成 payload（改导入名 + 重定向 + 放 shim）  -> build/payload-3.13.16/
[6/6] 组装交付 zip                                -> dist/
```

构建 3.15.2：

```bash
VER=3.15.2 ./build.sh
```

> 3.15 需要 `REDIRECT` 表里额外的 `GetCurrentThreadStackLimits` 项，脚本已支持；
> 但该版本尚未在真机验证，见 [verification.md](verification.md)。

## 分步执行（便于调试）

```bash
# 1. shim（改过 C 源码后需重编）
bash shim/build_shim.sh

# 2. payload：从官方目录生成打过补丁的运行时
python3 tools/build_payload.py \
        build/embed-3.13.16 \
        build/payload-3.13.16 \
        python313.dll

# 3. 组装交付包（含 CA 注入、脚本生成、自校验）
PYWIN_VER=3.13.16 \
PYWIN_PAYLOAD=$PWD/build/payload-3.13.16 \
PYWIN_OUTDIR=$PWD/dist \
PYWIN_REDIST=$PWD/vc_redist.x86.exe \
python3 tools/make_python_pkg.py
```

### 可覆盖的环境变量

| 变量 | 默认 | 说明 |
|---|---|---|
| `PYWIN_VER` | `3.13.16` | 目标版本，决定 `pythonXY.dll` 与包内文案 |
| `PYWIN_PAYLOAD` | `$OUTDIR/payload` | 已打好补丁的运行时目录 |
| `PYWIN_OUTDIR` | 仓库根目录 | 产物输出目录 |
| `PYWIN_REDIST` | `$ROOT/vc_redist.x86.exe` | VC++ 运行库安装包 |
| `PYWIN_CACERT` | `certs/cacert.pem` | 根证书包路径 |
| `PYWIN_SHIM_DIR` | `shim/` | 编译好的 shim 目录 |

## 三份脚本各干什么

| 脚本 | 作用 | 是否改二进制 |
|---|---|---|
| `tools/add_win7_import_shim.py` | 追加 `.w7imp` 节、重建导入描述符数组、重算校验和 | 是 |
| `tools/build_payload.py` | 复制官方目录；等长改名 `GetSystemTimePreciseAsFileTime`；调用上一个脚本；放入两个 shim | 是 |
| `tools/make_python_pkg.py` | 生成安装/自检/卸载脚本与文档、注入 CA、打包、自校验 | 否（只组装） |

`tools/make_python_pkg.py` 打包前会执行**门禁**：遍历 payload 里每个 PE，
列出所有 `KERNEL32` 静态导入，只要还有 Win8+ 项就中止。这一步是为了防止
把没补干净的二进制发出去。

## 构建产物自校验

`make_python_pkg.py` 打包后会重新打开 zip 检查：

- 无未替换的 `@@PLACEHOLDER@@`；
- 关键文件齐全（dll、两个 shim、`cacert.pem`、四个脚本）；
- payload 内每个文件都进了 zip；
- 内层标准库 zip 含 `sitecustomize.py`；
- `pythonXY._pth` 已启用 `import site`。

任何一项不满足都会非零退出。

## 常见构建问题

**`ModuleNotFoundError: pefile`** —— `pip install pefile`。

**`i686-w64-mingw32-gcc: command not found`** —— 装 mingw-w64 i686 工具链，
或把 `CC` 指向 MSYS2 的 `i686-w64-mingw32-gcc`。

**门禁报 "KERNEL32 残留 Win8+ 项"** —— 说明 `add_win7_import_shim.py` 没跑成功，
或 `REDIRECT` 表漏了新版本的导入。先用 `python3 -c` 解析导入表确认缺哪个名字，
再补进 `REDIRECT`（注意占位函数的参数字节数要对齐）。

**产出的 dll 校验和不匹配** —— 脚本会按最终字节重算；若手工改过 dll，
用 `pefile` 的 `generate_checksum()` 重新写入即可。Windows 加载 DLL 不校验该字段，
但审计工具会看。

**构建出的包在 Win7 上仍然闪退** —— 99% 是缺 UCRT（VC++ 运行库）。
先装 `vc_redist.x86.exe` 并重启，再跑 `check.bat`。
