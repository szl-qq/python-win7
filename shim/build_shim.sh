#!/usr/bin/env bash
# 交叉编译两个 shim DLL。
# 依赖：i686-w64-mingw32-gcc（Debian/Ubuntu: apt install gcc-mingw-w64-i686）
# 在 MSYS2 下把 CC 设为 mingw32 gcc 亦可。
set -euo pipefail
cd "$(dirname "$0")"

CC=${CC:-i686-w64-mingw32-gcc}
CFLAGS=${CFLAGS:--Os -s -shared -Wl,--kill-at}

echo "[1/2] win7k32shim.dll"
$CC $CFLAGS -o win7k32shim.dll win7k32shim.c win7k32shim.def 2>/dev/null

echo "[2/2] api-ms-win-core-path-l1-1-0.dll"
$CC $CFLAGS -o api-ms-win-core-path-l1-1-0.dll pathcch_shim.c pathcch_shim.def -lshlwapi 2>/dev/null

echo "[OK] shim 编译完成："
ls -l win7k32shim.dll api-ms-win-core-path-l1-1-0.dll
