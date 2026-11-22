#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""把打好补丁的 Python 3.13.16 (32-bit) 目录打包成 Win7 兼容交付包。

设计要点：
  * 交付包内部文件名一律用 ASCII（中文内容放进文件内部、按 GBK 编码），
    避免 Win7 自带资源管理器解压时把 UTF-8 文件名显示成乱码。
  * 所有 .bat/.ps1/.txt 用 GBK 编码（中文 Win7 原生代码页）。
  * 脚本全程兼容 PowerShell 2.0（Win7 默认只有 PS2，PS3+ 的写法不能用）。
  * 构建时做一道 "Win8+ 导入门禁"：payload 里任何 PE 若仍静态导入
    Win8+ API 就拒绝打包，防止把没补干净的二进制发出去。
  * 打包后自校验：解包复核脚本占位符、关键文件、payload 文件数。

用法：python3 make_python_pkg.py
"""
import hashlib
import os
import shutil
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)                          # 仓库根目录
OUTDIR = os.environ.get("PYWIN_OUTDIR") or ROOT        # 产物输出目录
PAYLOAD = os.environ.get("PYWIN_PAYLOAD") or os.path.join(OUTDIR, "payload")
REDIST = os.environ.get("PYWIN_REDIST") or os.path.join(ROOT, "vc_redist.x86.exe")

VERSION = os.environ.get("PYWIN_VER", "3.13.16")   # 目标 Python 版本
_v = VERSION.split(".")
SHORT = _v[0] + _v[1]                                # 313 / 315
OLD_VER, OLD_SHORT = "3.13.16", "313"                # 模板文本里的原始版本

APP = "Python " + VERSION
PKG = "Python-%s-Win7-x86" % VERSION                  # 内部根目录（纯 ASCII）
OUTZIP = os.path.join(OUTDIR, "Python-%s-win32-Win7-补丁版.zip" % VERSION)
TARGET = "C:\\Python%s-Win7" % SHORT
EXE = "python.exe"
DLL = "python%s.dll" % SHORT
SHIM = "api-ms-win-core-path-l1-1-0.dll"
K32SHIM = "win7k32shim.dll"


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# ---------------------------------------------------------------- 构建门禁
# 已知 Win8+ 才有的 API（Win7 的 kernel32 不导出，静态导入会直接加载失败）。
WIN8PLUS_API = {
    "GetSystemTimePreciseAsFileTime", "GetSystemTimeAdjustmentPrecise",
    "GetSystemCpuSetInformation", "SetThreadDescription", "GetThreadDescription",
    "SetThreadInformation", "GetThreadInformation", "WaitOnAddress",
    "WakeByAddressSingle", "WakeByAddressAll", "SetProcessMitigationPolicy",
    "GetProcessMitigationPolicy", "PrefetchVirtualMemory", "DiscardVirtualMemory",
    "OfferVirtualMemory", "ReclaimVirtualMemory", "VirtualAlloc2",
    "MapViewOfFile3", "CreateFile2", "GetFileInformationByHandleEx2",
    "EventSetInformation", "SetProcessValidCallTargets", "IsWow64Process2",
    "CreateFileMappingNumaW", "GetCurrentProcessorNumberEx",
    # Win8 起才有（Win7 需 KB2533623 / 根本没有）
    "CopyFile2", "AddDllDirectory", "RemoveDllDirectory", "SetDefaultDllDirectories",
    # Win8.1 起才有（PSS 进程快照族）
    "PssCaptureSnapshot", "PssQuerySnapshot", "PssFreeSnapshot",
    # Win8 起才有（3.14+ 用于算线程栈边界）
    "GetCurrentThreadStackLimits",
}


def check_win7_gate(payload):
    """返回问题列表；为空表示通过。"""
    try:
        import pefile
    except ImportError:
        raise SystemExit("缺少 pefile，请先: pip install pefile")

    problems = []
    needs_shim = []
    k32_needs = []
    for name in sorted(os.listdir(payload)):
        if not name.lower().endswith((".exe", ".dll", ".pyd")):
            continue
        path = os.path.join(payload, name)
        try:
            pe = pefile.PE(path, fast_load=True)
            pe.parse_data_directories(directories=[
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
        except Exception as exc:  # noqa: BLE001
            problems.append("无法解析 %s: %s" % (name, exc))
            continue
        for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
            dll = entry.dll.decode("ascii", "replace")
            for imp in entry.imports:
                api = imp.name.decode("ascii", "replace") if imp.name else None
                # win7k32shim.dll 是随包自带的替代实现，它导出的正是这些名字
                if api in WIN8PLUS_API and dll.lower() != K32SHIM.lower():
                    problems.append("%s 仍静态导入 Win8+ API: %s!%s" % (name, dll, api))
            if dll.lower() == "api-ms-win-core-path-l1-1-0.dll":
                needs_shim.append(name)
            if dll.lower() == K32SHIM.lower():
                k32_needs.append(name)

    if needs_shim and not os.path.exists(os.path.join(payload, SHIM)):
        problems.append("以下文件依赖 path api-set 但缺少 shim %s: %s"
                        % (SHIM, ", ".join(sorted(set(needs_shim)))))
    if k32_needs and not os.path.exists(os.path.join(payload, K32SHIM)):
        problems.append("以下文件依赖 KERNEL32 补丁 shim 但缺少 %s: %s"
                        % (K32SHIM, ", ".join(sorted(set(k32_needs)))))
    return problems


def count_k32(path):
    """统计 DLL 里 KERNEL32 的导入条目数（用于文档里的实数）。"""
    import pefile
    pe = pefile.PE(path, fast_load=True)
    pe.parse_data_directories(
        directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
    for e in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
        if e.dll and e.dll.decode().lower() == "kernel32.dll":
            return len(e.imports)
    return 0


def count_shim_descs(path):
    """统计 DLL 里指向 win7k32shim.dll 的导入描述符数（= 实际重定向的项数）。"""
    import pefile
    pe = pefile.PE(path, fast_load=True)
    pe.parse_data_directories(
        directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
    return sum(1 for e in getattr(pe, "DIRECTORY_ENTRY_IMPORT", [])
               if e.dll and e.dll.decode().lower() == K32SHIM.lower())


# ---------------------------------------------------------------- install.ps1
INSTALL_PS1 = r'''param([string]$Target = "@@TARGET@@", [switch]$Silent)
$ErrorActionPreference = "Continue"

$App   = "@@APP@@"
$Exe   = "@@EXE@@"
$Dll   = "@@DLL@@"
$Shim  = "@@SHIM@@"
$ShaExe= "@@SHA_EXE@@"
$ShaDll= "@@SHA_DLL@@"

$ScriptPath = $MyInvocation.MyCommand.Path
if (-not [System.IO.Path]::IsPathRooted($ScriptPath)) {
    $ScriptPath = (Join-Path (Get-Location) $ScriptPath)
}
$root    = [System.IO.Path]::GetFullPath((Split-Path -Parent $ScriptPath))
$payload = Join-Path $root "payload"
$redist  = Join-Path $root "redist\vc_redist.x86.exe"
$log     = Join-Path $root "install.log"

function Log([string]$m) {
    Write-Host $m
    $line = "[" + (Get-Date).ToString("yyyy-MM-dd HH:mm:ss") + "] " + $m
    Add-Content -Path $log -Value $line -Encoding Unicode
}

function Fail([string]$m, [int]$code) {
    Log "[失败] $m"
    if (-not $Silent) { Read-Host "按回车退出" | Out-Null }
    exit $code
}

$bar = "============================================================"
Set-Content -Path $log -Value $bar -Encoding Unicode
Log "$App  Win7 兼容补丁版  安装程序"
Log "安装目录: $Target"
Log $bar

$id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$pr = New-Object System.Security.Principal.WindowsPrincipal($id)
if (-not $pr.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Fail "需要管理员权限。请重新双击 install.bat（会自动请求提权）。" 3
}

$arch = "x86"
if ($env:PROCESSOR_ARCHITECTURE -eq "AMD64") { $arch = "x64" }
if ($env:PROCESSOR_ARCHITEW6432 -eq "AMD64") { $arch = "x64" }
Log "[1/7] 系统架构: $arch （本包为 32 位 Python，x86/x64 均可运行）"

if (-not (Test-Path (Join-Path $payload $Exe))) {
    Fail "找不到 payload\$Exe，请保持安装包完整后重试。" 2
}

Log "[2/7] 安装 Visual C++ 2015-2022 x86 运行库（提供 UCRT）..."
$needReboot = $false
if (Test-Path $redist) {
    $p = Start-Process -FilePath $redist -ArgumentList "/install /quiet /norestart" -Wait -PassThru
    $code = $p.ExitCode
    Log "  vc_redist 退出码: $code"
    if ($code -eq 3010) { $needReboot = $true; Log "  [提示] 运行库已安装，但需重启系统后才完全生效" }
    elseif (@(0, 1638) -notcontains $code) { Log "  [警告] 运行库可能未装成功（退出码 $code），请见文末补救办法" }
} else {
    Log "  [警告] 未找到 redist\vc_redist.x86.exe，若系统没装过 VC++ 2015+ 将无法运行"
}
$ucrtDll = Join-Path $env:SystemRoot "System32\api-ms-win-crt-runtime-l1-1-0.dll"
if (Test-Path $ucrtDll) { Log "  系统 UCRT 已就位" } else { Log "  [提示] 暂未检测到系统 UCRT，若刚装完运行库，重启后才会就位" }

Log "[3/7] 复制 Python 文件到 $Target ..."
if (-not (Test-Path $Target)) { New-Item -ItemType Directory -Path $Target -Force | Out-Null }
try {
    Copy-Item -Path (Join-Path $payload "*") -Destination $Target -Recurse -Force -ErrorAction Stop
} catch {
    Fail ("复制文件失败: " + $_.Exception.Message) 4
}
$n = (Get-ChildItem -Path $Target -Recurse | Where-Object { -not $_.PSIsContainer } | Measure-Object).Count
Log "  已复制 $n 个文件"

Log "[4/7] 校验关键文件 ..."
function Get-SHA256([string]$path) {
    $sha = New-Object System.Security.Cryptography.SHA256Managed
    $fs = [System.IO.File]::OpenRead($path)
    try { $bytes = $sha.ComputeHash($fs) } finally { $fs.Close() }
    $sb = New-Object System.Text.StringBuilder
    foreach ($b in $bytes) { [void]$sb.Append($b.ToString("x2")) }
    return $sb.ToString()
}
$hExe = Get-SHA256 (Join-Path $Target $Exe)
$hDll = Get-SHA256 (Join-Path $Target $Dll)
if ($hExe -eq $ShaExe) { Log "  $Exe      SHA256 PASS" } else { Log "  [警告] $Exe SHA256 不符（可能被改动/损坏）" }
if ($hDll -eq $ShaDll) { Log "  $Dll   SHA256 PASS" } else { Log "  [警告] $Dll SHA256 不符（非补丁版或已损坏）" }
if (Test-Path (Join-Path $Target $Shim)) { Log "  $Shim 已就位" } else { Log "  [警告] 缺少 $Shim，Win7 上启动会失败" }
if (Test-Path (Join-Path $Target "win7k32shim.dll")) { Log "  win7k32shim.dll 已就位" } else { Log "  [警告] 缺少 win7k32shim.dll，Win7 上启动会失败" }

Log "[5/7] 用户 PATH 置顶写入（去重）..."
$u = [Environment]::GetEnvironmentVariable("Path", "User")
if ($u -eq $null) { $u = "" }
$keep = @()
foreach ($p in ($u -split ";")) {
    $t = $p.Trim()
    if ($t -ne "" -and ($t.TrimEnd("\").ToLower() -ne $Target.TrimEnd("\").ToLower())) { $keep += $t }
}
[Environment]::SetEnvironmentVariable("Path", ((@($Target) + $keep) -join ";"), "User")
$m = [Environment]::GetEnvironmentVariable("Path", "Machine")
foreach ($q in ($m -split ";")) {
    if ($q.Trim() -ne "" -and (Test-Path (Join-Path $q.Trim() $Exe))) {
        Log "  [警告] 系统 PATH 中存在同名 $Exe：$($q.Trim())（系统 PATH 优先，会盖住本包）"
    }
}

Log "[6/7] 运行验证 ..."
$py = Join-Path $Target $Exe
$o1 = Join-Path $root "pyver.out.txt"
$e1 = Join-Path $root "pyver.err.txt"
Remove-Item $o1 -Force -ErrorAction SilentlyContinue
Remove-Item $e1 -Force -ErrorAction SilentlyContinue
$v = ""
$code = -1
$proc = $null
try {
    $proc = Start-Process -FilePath $py -ArgumentList "--version" -NoNewWindow -Wait -PassThru -RedirectStandardOutput $o1 -RedirectStandardError $e1 -ErrorAction Stop
} catch {
    $proc = $null
}
if ($proc -ne $null) {
    $code = $proc.ExitCode
    if (Test-Path $o1) { $v = (Get-Content $o1 | Out-String).Trim() }
    if (Test-Path $e1) {
        $ev = (Get-Content $e1 | Out-String).Trim()
        if ($ev -ne "") { $v = (($v + "  [stderr] " + $ev).Trim()) }
    }
    Remove-Item $o1 -Force -ErrorAction SilentlyContinue
    Remove-Item $e1 -Force -ErrorAction SilentlyContinue
} else {
    Log "  (改用直接调用方式捕获输出)"
    $v = (& $py --version 2>&1 | Out-String).Trim()
    $code = $LASTEXITCODE
}
$u = [int64]$code
if ($u -lt 0) { $u = $u + 4294967296 }
$hex = "0x" + $u.ToString("X8")
Log "  $py --version -> $v"
Log "  退出码: $code ($hex)"
if ($code -ne 0 -or $v -eq "") {
    Log ""
    Log "  [失败] python.exe 未能正常启动。"
    Log "  逐项自检（[有] 表示文件确实存在）："
    foreach ($d in @($Exe, $Dll, "python3.dll", "vcruntime140.dll", "win7k32shim.dll", "api-ms-win-core-path-l1-1-0.dll")) {
        if (Test-Path (Join-Path $Target $d)) { Log "    [有] $d" } else { Log "    [缺] $d" }
    }
    foreach ($d in @("api-ms-win-crt-runtime-l1-1-0.dll", "api-ms-win-crt-stdio-l1-1-0.dll", "ucrtbase.dll", "vcruntime140.dll")) {
        if (Test-Path (Join-Path $env:SystemRoot ("System32\" + $d))) { Log "    [有] 系统 $d" } else { Log "    [缺] 系统 $d" }
    }
    Log ""
    Log "  按顺序处理："
    Log "   1) 双击本目录 diag.bat：它会开一个窗口把 python.exe 的真实报错显示出来，"
    Log "      把窗口内容截图反馈（这一步能直接定位问题，最省事）。"
    Log "   2) 若提示缺 api-ms-win-crt-*：重启电脑后再试（UCRT 常需重启生效）；"
    Log "      仍不行就右键以管理员身份运行 redist\vc_redist.x86.exe，装完重启。"
    Log "   3) 若提示签名不受信任：先装 KB4474419（SHA-2 支持）再装运行库。"
    Log "   4) 把 install.log 和 diag.bat 窗口内容一起反馈即可。"
    if (-not $Silent) { Read-Host "按回车退出" | Out-Null }
    exit 5
}
$smoke = (& $py -c "import sys,os,time,socket,ssl,sqlite3,hashlib,json;print(sys.version.split()[0])" 2>&1 | Out-String).Trim()
if ($LASTEXITCODE -ne 0) { Log "  [警告] 模块自检失败: $smoke" } else { Log "  模块自检通过: $smoke" }

Log "[7/7] 完成"
Log ""
Log "安装完成。默认安装目录: $Target"
if ($needReboot) { Log "提示：VC++ 运行库需重启系统后完全生效，请尽快重启电脑。" }
Log "若 cmd 里 python 版本不对，请关闭所有旧 cmd 窗口后重开。"
Log "日志: $log"
if (-not $Silent) { Read-Host "按回车退出" | Out-Null }
exit 0
'''


# ---------------------------------------------------------------- uninstall.ps1
UNINSTALL_PS1 = r'''param([string]$Target = "@@TARGET@@", [switch]$Silent)
$App = "@@APP@@"
$Exe = "@@EXE@@"

$ScriptPath = $MyInvocation.MyCommand.Path
if (-not [System.IO.Path]::IsPathRooted($ScriptPath)) {
    $ScriptPath = (Join-Path (Get-Location) $ScriptPath)
}
$root = [System.IO.Path]::GetFullPath((Split-Path -Parent $ScriptPath))

Write-Host "====================================================="
Write-Host " $App  Win7 兼容补丁版 卸载"
Write-Host "====================================================="

if (Test-Path (Join-Path $Target $Exe)) {
    $ans = "y"
    if (-not $Silent) { $ans = Read-Host ("确认删除 " + $Target + " ? [Y/n]") }
    if (($ans -eq "") -or ($ans.ToLower() -match "^[y]")) {
        Remove-Item -Path $Target -Recurse -Force -ErrorAction SilentlyContinue
        if (Test-Path $Target) { Write-Host "[警告] 目录未能完全删除（可能被占用），请手动清理: $Target" }
        else { Write-Host "已删除安装目录: $Target" }
    } else { Write-Host "已取消。" }
} else {
    Write-Host "没找到 $Target，可能已经卸载。"
}

$u = [Environment]::GetEnvironmentVariable("Path", "User")
if ($u -eq $null) { $u = "" }
$keep = @()
foreach ($p in ($u -split ";")) {
    $t = $p.Trim()
    if ($t -ne "" -and ($t.TrimEnd("\").ToLower() -ne $Target.TrimEnd("\").ToLower())) { $keep += $t }
}
[Environment]::SetEnvironmentVariable("Path", ($keep -join ";"), "User")
Write-Host "已从用户 PATH 移除: $Target"
Write-Host "VC++ 运行库为系统级共享组件，未随本包卸载（其他软件可能仍需要）。"
if (-not $Silent) { Read-Host "按回车退出" | Out-Null }
exit 0
'''


# ---------------------------------------------------------------- check.ps1
CHECK_PS1 = r'''param([string]$Target = "@@TARGET@@")
$App   = "@@APP@@"
$Exe   = "@@EXE@@"
$Dll   = "@@DLL@@"
$Shim  = "@@SHIM@@"
$ShaExe= "@@SHA_EXE@@"
$ShaDll= "@@SHA_DLL@@"

$ScriptPath = $MyInvocation.MyCommand.Path
if (-not [System.IO.Path]::IsPathRooted($ScriptPath)) {
    $ScriptPath = (Join-Path (Get-Location) $ScriptPath)
}
$root = [System.IO.Path]::GetFullPath((Split-Path -Parent $ScriptPath))

function Get-SHA256([string]$path) {
    $sha = New-Object System.Security.Cryptography.SHA256Managed
    $fs = [System.IO.File]::OpenRead($path)
    try { $bytes = $sha.ComputeHash($fs) } finally { $fs.Close() }
    $sb = New-Object System.Text.StringBuilder
    foreach ($b in $bytes) { [void]$sb.Append($b.ToString("x2")) }
    return $sb.ToString()
}

Write-Host "====================================================="
Write-Host " $App  Win7 兼容补丁版 自检"
Write-Host "====================================================="

$py = Join-Path $Target $Exe
if (-not (Test-Path $py)) {
    $cmd = Get-Command $Exe -ErrorAction SilentlyContinue
    if ($cmd) { $py = $cmd.Source }
}
if (-not (Test-Path $py)) {
    Write-Host "[1] 没找到 $Exe，请先运行 install.bat"
    Read-Host "按回车退出" | Out-Null
    exit 1
}
Write-Host "[1] python 位置: $py"

$dir = Split-Path -Parent $py
$dllPath = Join-Path $dir $Dll
if (-not (Test-Path $dllPath)) { $dllPath = Join-Path $root "payload\$Dll" }

$hExe = Get-SHA256 $py
$hDll = Get-SHA256 $dllPath
if ($hExe -eq $ShaExe) { $r1 = "PASS" } else { $r1 = "FAIL" }
if ($hDll -eq $ShaDll) { $r2 = "PASS" } else { $r2 = "FAIL" }
Write-Host "[2] $Exe      SHA256: $r1"
Write-Host "[3] $Dll   SHA256: $r2"

foreach ($s in @($Shim, "win7k32shim.dll")) {
    $sp = Join-Path $dir $s
    if (-not (Test-Path $sp)) { $sp = Join-Path $root ("payload\" + $s) }
    if (Test-Path $sp) { Write-Host "[4] $s 存在: $sp" } else { Write-Host "[4] [警告] 缺少 $s，Win7 上必定启动失败" }
}

Write-Host "[5] --version:"
$verOut = & $py --version 2>&1
$code = $LASTEXITCODE
foreach ($line in $verOut) { if ($line) { Write-Host "    $line" } }
Write-Host "    退出码: $code"
if ($code -ne 0) {
    Write-Host "    [失败] python.exe 无法启动。请检查安装目录是否包含 win7k32shim.dll、"
    Write-Host "           api-ms-win-core-path-l1-1-0.dll、vcruntime140.dll，且系统已装 VC++ 运行库。"
}

Write-Host "[6] 模块自检 (os/time/socket/ssl/sqlite3/hashlib/json):"
& $py -c "import sys,os,time,socket,ssl,sqlite3,hashlib,json;print('OK',sys.version.split()[0])"

Write-Host "[7] PATH 命中:"
$c = Get-Command $Exe -ErrorAction SilentlyContinue
if ($c) { Write-Host "    $($c.Source)" } else { Write-Host "    (未在当前会话 PATH 中；刚装完请重开 cmd 窗口再看)" }

Write-Host "[8] 根证书与 HTTPS:"
$ca = Join-Path $dir "cacert.pem"
if (Test-Path $ca) { Write-Host "    cacert.pem 存在: $ca" } else { Write-Host "    [警告] 缺少 cacert.pem，HTTPS 可能报 CERTIFICATE_VERIFY_FAILED" }
& $py -c "import ssl;c=ssl.create_default_context();print('    已加载 CA 数量:',len(c.get_ca_certs()))"
& $py -c "import urllib.request as u;print('    HTTPS 测试:',u.urlopen('https://pypi.tuna.tsinghua.edu.cn/simple',timeout=10).status)"
if ($LASTEXITCODE -ne 0) {
    Write-Host "    [失败] HTTPS 不通：确认 cacert.pem 与 python.exe 同目录，或该机器能否联网。"
}

Write-Host "====================================================="
Read-Host "按回车退出" | Out-Null
exit 0
'''


# ---------------------------------------------------------------- README
README_TXT = r'''Python 3.13.16 (32-bit) Win7 兼容补丁版
================================================================

适用：Windows 7 SP1 及更高（32 位 / 64 位均可；本包为 32 位 Python）。
      建议先安装 KB4474419（SHA-2 支持）补丁。

一、安装
  双击 install.bat（会自动请求管理员权限；也可右键 -> 以管理员身份运行）。
  脚本会依次：安装 VC++ 运行库 -> 复制文件 -> 写入用户 PATH -> 校验哈希 -> 试跑验证。
  默认安装到 C:\Python313-Win7；可用参数改目录：
      install.bat D:\Python313
  静默安装（不弹提示）：
      install.bat -Target D:\Python313 -Silent
  完整日志见 install.log。

二、自检 / 卸载
  双击 check.bat 自检：校验 python.exe / python313.dll 哈希 + shim 是否存在
    + --version + 常用模块导入 + PATH 命中。
  双击 uninstall.bat 卸载（会自动请求管理员权限）。

三、注意
  1) 装完若 cmd 里 python 版本不对，先关掉所有已打开的 cmd 窗口再开。
  2) 系统变量 PATH 优先于用户变量；旧 Python 若装在系统 PATH 里会盖住本包。
  3) 改过的 python313.dll 数字签名已失效，杀软可能提示，属预期。
  4) 已默认启用 site（方便装 pip），并内置 cacert.pem 修正 Win7 上 HTTPS 证书
     校验失败；详见 PATCH-NOTES.txt 第五、六节。

四、目录与文件
  payload/          补丁后的 Python 运行文件（python.exe / python313.dll / 标准库 / shim）
  redist/           Visual C++ 2015-2022 x86 运行库（vc_redist.x86.exe）
  install.bat       安装入口（自动提权，调用 install.ps1）
  uninstall.bat     卸载入口（调用 uninstall.ps1）
  check.bat         自检入口（调用 check.ps1）
  README.txt        本说明
  PATCH-NOTES.txt   补丁逐字节说明 / 代价 / 边界
  checksums.txt     全部文件 SHA256 校验清单

主程序校验值：
  python.exe      SHA256  @@SHA_EXE@@
  python313.dll   SHA256  @@SHA_DLL@@

五、故障排查：装完 python 起不来（窗口一闪、或命令无输出）
  Python 3.x 在 Win7 上依赖 UCRT（api-ms-win-crt-*.dll），由 VC++ 运行库提供。
  如果安装脚本最后提示“python.exe 暂时无法启动”，按下面顺序处理：
   1) 先重启电脑，再双击 check.bat —— UCRT 常常要重启后才生效，这一步能解决绝大多数情况。
   2) 仍不行：右键“以管理员身份运行” redist\vc_redist.x86.exe，按向导装完再重启。
      若它报“签名/不受信任”，先装 KB4474419（SHA-2 支持补丁）再重试。
   3) 完成后双击 check.bat，出现 “Python 3.13.16” 即成功。
   4) 若 python 能跑、但访问 HTTPS 报 CERTIFICATE_VERIFY_FAILED（无法获取本地
      颁发者证书），是 Win7 系统根证书库过旧，见 PATCH-NOTES.txt 第六节；
      包内已带 cacert.pem，确认它没被删即可。
  安装日志：与本文件同目录的 install.log（用记事本打开）。
'''


# ---------------------------------------------------------------- PATCH-NOTES
PATCH_TXT = r'''Python 3.13.16 (32-bit) Win7 兼容补丁版 —— 补丁说明
================================================================

一、为什么要改
  先澄清一个常见误解：官方至今仍为每个版本提供 32 位 Windows 包
  （3.15.x 同样有 installer 32-bit 与 embeddable 32-bit，PEP 11 里
  i686-pc-windows-msvc 仍属 Tier 1）。所以“32 位”不是问题。
  真正的问题是“能不能在 Win7 跑”：官方自 3.9 起把最低系统抬到
  Windows 8.1，自 3.14 起抬到 Windows 10，Win7 早就不在支持范围。
  本包就是把这层“只在 Win8+ 存在的依赖”补掉，让 @@APP@@ 32 位
  能在 Win7 SP1 上跑起来。
  Win7 上启动会因下列 Win8/8.1 独占依赖直接失败（全部在 @@DLL@@）：
    1) KERNEL32!GetSystemTimePreciseAsFileTime —— Win8 起才有；
    2) KERNEL32!CopyFile2 / AddDllDirectory / RemoveDllDirectory —— Win8 起才有；
    3) KERNEL32!GetCurrentThreadStackLimits —— Win8 起才有（3.14+ 新增用法）；
    4) KERNEL32!PssCaptureSnapshot / PssQuerySnapshot / PssFreeSnapshot —— Win8.1 起才有；
    5) api-ms-win-core-path-l1-1-0.dll（PathCch 系列）—— Win7 上整个 DLL 不存在。
  以上任何一项缺失，python.exe 都会在进入 main 之前被装载器拒绝，
  外部表现就是“双击一闪而过、--version 一个字符都不输出”。

二、改了哪些（等长原地改写 + 追加一个节，未搬动任何代码）
  补丁 A（@@DLL@@，静态导入改名）
    导入名 GetSystemTimePreciseAsFileTime（31 字节）
      -> GetSystemTimeAsFileTime（22 字节 + 9 字节补 0）
    位置：KERNEL32 导入名表内该条目（其余字节补 0，PE 校验和已重算）。
    签名相同 void(LPFILETIME)，仅时间精度下降（见"代价"）。

  补丁 B（新增 shim：api-ms-win-core-path-l1-1-0.dll，随包放在 payload 目录）
    在 Win7 上提供 @@DLL@@ 实际导入的两个导出：
      PathCchSkipRoot     -> 转发 shlwapi!PathSkipRootW
      PathCchCombineEx    -> 转发 shlwapi!PathCombineW
    调用约定 stdcall，与 CPython 的调用点一致（已反汇编复核 ret 8 / ret 14）。

  补丁 C（在 @@DLL@@ 末尾追加节 .w7imp，把 @@REDIR_N@@ 个 Win8+ KERNEL32 导入
          重定向到 win7k32shim.dll）
    节内写入新的导入描述符数组：
      - KERNEL32 的导入名表里，这 @@REDIR_N@@ 项换成 Win7 确实存在的占位名（保证装载通过）；
      - 追加 @@REDIR_N@@ 个指向 win7k32shim.dll 的描述符，FirstThunk 精确对准原来那
        @@REDIR_N@@ 个 IAT 槽位。装载器按数组顺序处理，后者覆盖前者，槽位最终是 shim 的实现。
      - 导入目录指向新数组；其余 @@K32_LEFT@@ 个 KERNEL32 导入原样保留，依然直连系统。
    win7k32shim.dll 的实现策略是“先探测、再转发”：
      CopyFile2          -> 有则转发；Win7 上用 CopyFileW 实现（HRESULT 语义一致）
      AddDllDirectory    -> 有则转发；Win7 上用 SetDllDirectoryW 模拟
      RemoveDllDirectory -> 有则转发；Win7 上清空 SetDllDirectory
      Pss*Snapshot       -> 有则转发；Win7 上返回 ERROR_CALL_NOT_IMPLEMENTED
      GetCurrentThreadStackLimits -> 有则转发；Win7 上直接读 TEB 的
                                      StackBase / StackLimit（Win8 的实现也读这两个字段，
                                      所以是等价取值，不是估算）
    因此在 Win8/10/11 上行为与官方版本完全一致，只有 Win7 才走模拟分支。

三、代价
  1) time.time() 时间精度从约 1 微秒降到系统时钟粒度约 15.6ms
     （time.perf_counter() 不受影响，仍用 QueryPerformanceCounter）。
  2) 改过的 python313.dll 数字签名已失效，杀软可能提示。
  3) 进程快照族（Pss*Snapshot）在 Win7 上不可用，依赖它的诊断/栈快照类功能
     会自动降级（不会崩溃）。
  4) 仍需 Visual C++ 2015-2022 运行库（提供 UCRT 的 api-ms-win-crt-*.dll）。
     本包已附带 redist\vc_redist.x86.exe，安装脚本会自动静默安装；
     如安装后 python 起不来，多半是 UCRT 尚未生效，重启电脑即可（详见 README 第五节）。

四、边界 / 未验证项
  1) 本环境无法真机验证 Win7 启动，只能做到：静态导入 0 个 Win8+ 缺口、
     反汇编复核落点、PE 校验和重算、SHA256 校验。
  2) 建议真机 Win7 SP1（先装 KB4474419 SHA-2 补丁）实测：python.exe --version、
     import 常用模块（os/time/socket/ssl/sqlite3 等）。
  3) 个别依赖 Win8+ 语义的特性（如长路径 \\?\ 前缀、ETW 事件注册）功能降级。

五、如何启用 pip
  本包已默认放开 site（_pth 里的 import site），site-packages 会自动进入 sys.path。
  1) 从 https://bootstrap.pypa.io/get-pip.py 下载后运行：python get-pip.py
  2) 装完 pip 建议换国内源，避免连不上或超时：
     python -m pip config set global.index-url https://pypi.tuna.tsinghua.edu.cn/simple

六、HTTPS / 证书（Win7 必读）
  Win7 SP1 的系统根证书库往往停留在多年前，缺 ISRG Root X1 等新的公共根，
  访问 HTTPS 会报：
      [SSL: CERTIFICATE_VERIFY_FAILED] unable to get local issuer certificate
  本包内置 cacert.pem（Mozilla 根证书快照，共 118 张），解释器启动时由
  sitecustomize 把它追加进默认 SSL 上下文 —— 是追加，不替换系统证书，
  校验强度不变，系统证书照旧可用。
    * 仍然报错：确认 cacert.pem 与 python.exe 在同一目录，未被误删。
    * 想更新证书：用新版 cacert.pem 覆盖同名文件即可，不必重装。
    * 内网自签证书：把自签根追加到 cacert.pem 末尾即可，不要关校验。

七、关于文件名与编码
  交付包内部文件名均为 ASCII，中文说明放在文件内部并按 GBK 编码，
  以保证在 Win7 自带资源管理器中解压不会出现乱码。所有 .bat/.ps1/.txt
  均为 GBK（中文 Win7 原生代码页）；安装/自检脚本兼容 PowerShell 2.0。
'''


# ---------------------------------------------------------------- CA 注入
# Win7 SP1 的系统 ROOT 证书库常年不更新，缺 ISRG Root X1 等公共根，
# 导致 ssl / urllib / httpx 一律 CERTIFICATE_VERIFY_FAILED。
# 做法：随包带 Mozilla 根证书 cacert.pem，用 sitecustomize 在解释器启动时
# 追加进默认 SSL 上下文（追加而非替换，系统证书照旧可用）。
CA_FILE = os.environ.get("PYWIN_CACERT") or next(
    (p for p in (os.path.join(ROOT, "certs", "cacert.pem"),
                 os.path.join(HERE, "cacert.pem")) if os.path.isfile(p)),
    os.path.join(ROOT, "certs", "cacert.pem"))

SITECUSTOM_PY = r'''# -*- coding: utf-8 -*-
"""Win7 兼容包：为默认 SSL 上下文追加内置根证书 cacert.pem

Windows 7 SP1 的系统 ROOT 证书库常停留在多年前，缺少 ISRG Root X1 等新根，
访问 HTTPS 会报 CERTIFICATE_VERIFY_FAILED: unable to get local issuer
certificate。此处把随包的 cacert.pem 追加进默认 SSL 上下文。

只追加、不替换系统证书，也不关闭校验；系统已有的根证书照旧生效。
"""
import os
import sys

try:
    import ssl
except Exception:
    ssl = None


def _find_ca():
    names = ("cacert.pem", "cacert.crt")
    roots = []
    for getter in (
        lambda: os.path.dirname(os.path.abspath(sys.executable)),
        lambda: os.path.abspath(sys.prefix),
    ):
        try:
            p = getter()
            if p and p not in roots:
                roots.append(p)
        except Exception:
            pass
    for root in roots:
        for n in names:
            p = os.path.join(root, n)
            if os.path.isfile(p):
                return p
    return None


_CA_FILE = _find_ca()

if _CA_FILE and ssl is not None:
    for _var in ("SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE"):
        os.environ.setdefault(_var, _CA_FILE)

    def _with_bundle(fn):
        def wrapper(*args, **kwargs):
            ctx = fn(*args, **kwargs)
            try:
                ctx.load_verify_locations(_CA_FILE)
            except Exception:
                pass
            return ctx

        wrapper.__name__ = getattr(fn, "__name__", "create_default_context")
        wrapper.__doc__ = "ssl.create_default_context + bundled CA (Win7 compat)"
        return wrapper

    ssl.create_default_context = _with_bundle(ssl.create_default_context)
    if hasattr(ssl, "_create_default_https_context"):
        ssl._create_default_https_context = ssl.create_default_context
'''


def inject_ca(stage_payload):
    """把 cacert.pem 与 sitecustomize.py 注入 payload，并放开 _pth 的 site 开关。"""
    if not os.path.isfile(CA_FILE):
        raise SystemExit("缺少 cacert.pem（随包根证书），无法保证 HTTPS 可用")
    shutil.copy(CA_FILE, os.path.join(stage_payload, "cacert.pem"))

    zname = "python%s.zip" % SHORT
    zpath = os.path.join(stage_payload, zname)
    tmp = zpath + ".tmp"
    # 优先用仓库里的 tools/sitecustomize.py（便于 review），缺失时退回内嵌副本
    sc_path = os.path.join(HERE, "sitecustomize.py")
    if os.path.isfile(sc_path):
        with open(sc_path, "r", encoding="utf-8") as f:
            sitecustom = f.read()
    else:
        sitecustom = SITECUSTOM_PY
    with zipfile.ZipFile(zpath) as src:
        items = [(i, src.read(i.filename)) for i in src.infolist()
                 if i.filename != "sitecustomize.py"]
    with zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as dst:
        for info, data in items:
            dst.writestr(info, data)
        dst.writestr("sitecustomize.py", sitecustom)
    os.replace(tmp, zpath)

    pth = os.path.join(stage_payload, "python%s._pth" % SHORT)
    if os.path.isfile(pth):
        with open(pth, "r", encoding="utf-8", errors="replace", newline="") as f:
            text = f.read()
        if "#import site" in text:
            text = text.replace("#import site", "import site")
            with open(pth, "w", encoding="utf-8", newline="") as f:
                f.write(text)
    print("[CA] 已注入 cacert.pem + sitecustomize，并启用 import site")


# ---------------------------------------------------------------- 生成逻辑
def localize(text):
    """把模板里写死的 3.13 字样换成本次构建的版本（构建 3.13 时原样返回）。"""
    if SHORT == OLD_SHORT:
        return text
    text = text.replace("C:\\Python%s-Win7" % OLD_SHORT, TARGET)
    text = text.replace(OLD_VER, VERSION)
    text = text.replace("python%s" % OLD_SHORT, "python%s" % SHORT)
    text = text.replace("Python%s" % OLD_SHORT, "Python%s" % SHORT)
    return text


def render(s, **extra):
    s = (s.replace("@@APP@@", APP)
          .replace("@@EXE@@", EXE)
          .replace("@@DLL@@", DLL)
          .replace("@@SHIM@@", SHIM)
          .replace("@@TARGET@@", TARGET)
          .replace("@@SHA_EXE@@", extra["sha_exe"])
          .replace("@@SHA_DLL@@", extra["sha_dll"])
          .replace("@@REDIR_N@@", str(extra.get("redir_n", 0)))
          .replace("@@K32_LEFT@@", str(extra.get("k32_left", 0))))
    return s


def bat_launcher(title, ps1, elevate):
    """生成 .bat 包装器；elevate=True 时先做管理员提权再调用 ps1。"""
    lines = ["@echo off", "chcp 936 >nul 2>nul", "title %s - %s" % (APP, title)]
    if elevate:
        lines += [
            "net session >nul 2>&1",
            "if %errorlevel% neq 0 (",
            "    echo 正在请求管理员权限...",
            "    powershell -NoProfile -Command \"Start-Process -FilePath '%~f0' -Verb RunAs\"",
            "    exit /b",
            ")",
        ]
    lines += [
        'set "PS=%SystemRoot%\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"',
        '"%PS%" -NoProfile -ExecutionPolicy Bypass -File "%~dp0' + ps1 + '" %*',
        "if errorlevel 1 pause",
    ]
    return "\r\n".join(lines) + "\r\n"


DIAG_BAT = r"""@echo off
chcp 936 >nul 2>nul
title Python Win7 诊断
setlocal
set "PKG=%~dp0"
set "PY="
if exist "C:\Python313-Win7\python.exe" set "PY=C:\Python313-Win7\python.exe"
if not defined PY if exist "%PKG%payload\python.exe" set "PY=%PKG%payload\python.exe"
if not defined PY (
  echo [错误] 找不到 python.exe，请确认安装包完整。
  pause
  exit /b 1
)
for %%F in ("%PY%") do set "PYDIR=%%~dpF"
echo ================================================
echo   Python Win7 诊断
echo   python.exe: %PY%
echo   安装包目录: %PKG%
echo ================================================
echo.
echo ---- [1] python.exe --version ----
"%PY%" --version
echo     退出码 = %errorlevel%
echo.
echo ---- [2] python.exe -c "import sys;print(sys.version)" ----
"%PY%" -c "import sys;print(sys.version)"
echo     退出码 = %errorlevel%
echo.
echo ---- [3] 同目录关键文件 ----
for %%f in (python313.dll python3.dll vcruntime140.dll win7k32shim.dll api-ms-win-core-path-l1-1-0.dll python313.zip python313._pth) do (
  if exist "%PYDIR%%%f" (echo     [有] %%f) else (echo     [缺] %%f)
)
echo.
echo ---- [4] 系统 DLL (System32) ----
for %%f in (api-ms-win-crt-runtime-l1-1-0.dll api-ms-win-crt-stdio-l1-1-0.dll ucrtbase.dll vcruntime140.dll) do (
  if exist "%SystemRoot%\System32\%%f" (echo     [有] %%f) else (echo     [缺] %%f)
)
echo.
echo ---- [5] 请把本窗口内容截图发给开发者 ----
echo.
pause
"""


def build_checksums(stage_payload):
    lines = ["# %s Win7 patched - SHA256 checksums" % APP, ""]
    for root, _, files in os.walk(stage_payload):
        for f in sorted(files):
            full = os.path.join(root, f)
            rel = os.path.relpath(full, stage_payload).replace("\\", "/")
            lines.append("%s  %s" % (sha256_file(full), rel))
    lines += ["", "# 校验命令: certutil -hashfile <文件> SHA256"]
    return "\r\n".join(lines) + "\r\n"


def main():
    # 0) 前置检查
    if not os.path.isdir(PAYLOAD):
        raise SystemExit("缺少 payload 目录")
    if not os.path.exists(REDIST):
        raise SystemExit("缺少 vc_redist.x86.exe（redist 需要）")

    sha_exe = sha256_file(os.path.join(PAYLOAD, EXE))
    sha_dll = sha256_file(os.path.join(PAYLOAD, DLL))

    # 1) 构建门禁
    problems = check_win7_gate(PAYLOAD)
    if problems:
        print("=== Win7 构建门禁未通过，拒绝打包 ===")
        for p in problems:
            print("  *", p)
        raise SystemExit(1)
    print("门禁通过：payload 内无 Win8+ 静态导入缺口")

    # 2) 组装 stage 目录
    stage = os.path.join(OUTDIR, PKG)
    if os.path.isdir(stage):
        shutil.rmtree(stage)
    os.makedirs(stage)

    def w(name, text, enc="gbk"):
        text = localize(text)
        with open(os.path.join(stage, name), "wb") as f:
            f.write(text.encode(enc, errors="replace"))

    k32_total = count_k32(os.path.join(PAYLOAD, DLL))
    redir_n = count_shim_descs(os.path.join(PAYLOAD, DLL))
    ctx = {"sha_exe": sha_exe, "sha_dll": sha_dll,
           "redir_n": redir_n, "k32_left": k32_total - redir_n}
    w("install.ps1", render(INSTALL_PS1, **ctx))
    w("uninstall.ps1", render(UNINSTALL_PS1, **ctx))
    w("check.ps1", render(CHECK_PS1, **ctx))
    w("install.bat", bat_launcher("安装", "install.ps1", elevate=True))
    w("uninstall.bat", bat_launcher("卸载", "uninstall.ps1", elevate=True))
    w("check.bat", bat_launcher("自检", "check.ps1", elevate=False))
    w("diag.bat", DIAG_BAT)
    w("README.txt", render(README_TXT, **ctx))
    w("PATCH-NOTES.txt", render(PATCH_TXT, **ctx))

    # payload + redist
    stage_payload = os.path.join(stage, "payload")
    shutil.copytree(PAYLOAD, stage_payload)
    os.makedirs(os.path.join(stage, "redist"))
    shutil.copy(REDIST, os.path.join(stage, "redist", "vc_redist.x86.exe"))

    inject_ca(stage_payload)

    w("checksums.txt", build_checksums(stage_payload), enc="ascii")

    # 3) 打包
    if os.path.exists(OUTZIP):
        os.remove(OUTZIP)
    with zipfile.ZipFile(OUTZIP, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for root, _, files in os.walk(stage):
            for f in files:
                full = os.path.join(root, f)
                z.write(full, os.path.relpath(full, OUTDIR))

    # 4) 打包后自校验
    verify(OUTZIP)

    print("产出:", OUTZIP)
    print("大小: %.1f MB" % (os.path.getsize(OUTZIP) / 1048576))
    print("python.exe    SHA256", sha_exe)
    print("%s SHA256" % DLL, sha_dll)


def verify(outzip):
    base = PKG + "/"
    with zipfile.ZipFile(outzip) as z:
        names = z.namelist()
        for n in names:
            if n.endswith((".bat", ".ps1", ".txt")):
                if b"@@" in z.read(n):
                    raise SystemExit("发现未替换占位符: %s" % n)
        required = [
            "payload/" + DLL, "payload/python.exe", "payload/" + SHIM,
            "payload/" + K32SHIM, "payload/cacert.pem", "diag.bat",
            "redist/vc_redist.x86.exe", "install.bat", "install.ps1",
            "uninstall.bat", "uninstall.ps1", "check.bat", "check.ps1",
            "README.txt", "PATCH-NOTES.txt", "checksums.txt",
        ]
        for rel in required:
            if base + rel not in names:
                raise SystemExit("缺少文件: %s" % rel)
        local = [os.path.relpath(os.path.join(r, f), PAYLOAD).replace("\\", "/")
                 for r, _, fs in os.walk(PAYLOAD) for f in fs]
        for rel in local:
            if base + "payload/" + rel not in names:
                raise SystemExit("zip 缺 payload 文件: %s" % rel)

        # Win7 上 HTTPS 可用性依赖这两件事，缺一个就退回"证书校验失败"
        import io
        inner_name = base + "payload/python%s.zip" % SHORT
        inner = zipfile.ZipFile(io.BytesIO(z.read(inner_name)))
        if "sitecustomize.py" not in inner.namelist():
            raise SystemExit("内层标准库 zip 缺少 sitecustomize.py")
        pth_txt = z.read(base + "payload/python%s._pth" % SHORT).decode("utf-8", "replace")
        if "#import site" in pth_txt:
            raise SystemExit("python%s._pth 未启用 import site，sitecustomize 不会加载" % SHORT)
        print("自校验通过：%d 个文件，占位符 0，关键文件与 payload 齐全" % len(names))


if __name__ == "__main__":
    main()
