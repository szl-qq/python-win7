#!/usr/bin/env bash
# 一键复现：下载官方 32 位 embeddable 包 -> 打补丁 -> 生成交付 zip
#
#   ./build.sh                 # 默认 3.13.16
#   VER=3.15.2 ./build.sh      # 构建别的版本（需脚本已支持该版本）
#
# 依赖：python3 + pefile、i686-w64-mingw32-gcc、curl、unzip
set -euo pipefail
ROOT=$(cd "$(dirname "$0")" && pwd)
cd "$ROOT"

VER=${VER:-3.13.16}
MAJ=$(echo "$VER" | cut -d. -f1)
MIN=$(echo "$VER" | cut -d. -f2)
SHORT="$MAJ$MIN"                       # 3.13.16 -> 313

EMBED="python-$VER-embed-win32.zip"
URL="https://www.python.org/ftp/python/$VER/$EMBED"
REDIST_URL="https://aka.ms/vs/17/release/vc_redist.x86.exe"

mkdir -p build dist

# 1) 取官方二进制（已存在则跳过）
if [ ! -f "build/$EMBED" ]; then
  echo "[1/6] 下载 $URL"
  curl -fL --retry 3 -o "build/$EMBED" "$URL"
else
  echo "[1/6] 已缓存 build/$EMBED"
fi
if [ ! -f vc_redist.x86.exe ]; then
  echo "[2/6] 下载 vc_redist.x86.exe"
  curl -fL --retry 3 -o vc_redist.x86.exe "$REDIST_URL"
else
  echo "[2/6] 已缓存 vc_redist.x86.exe"
fi

# 2) 解包官方 embeddable
EMBED_DIR="build/embed-$VER"
rm -rf "$EMBED_DIR"
echo "[3/6] 解包 -> $EMBED_DIR"
mkdir -p "$EMBED_DIR"
unzip -q -o "build/$EMBED" -d "$EMBED_DIR"

# 3) 编译 shim（若仓库里没有 dll 或强制重建）
if [ ! -f shim/win7k32shim.dll ] || [ ! -f shim/api-ms-win-core-path-l1-1-0.dll ]; then
  echo "[4/6] 编译 shim"
  bash shim/build_shim.sh
else
  echo "[4/6] shim 已存在（删除后重跑可强制重建）"
fi

# 4) 生成 payload：改导入名 + 重定向 Win8+ 导入 + 放入 shim
echo "[5/6] 生成 payload"
python3 tools/build_payload.py "$EMBED_DIR" "build/payload-$VER" "python$SHORT.dll"

# 5) 组装交付包
echo "[6/6] 组装交付 zip"
PYWIN_VER=$VER \
PYWIN_PAYLOAD="$ROOT/build/payload-$VER" \
PYWIN_OUTDIR="$ROOT/dist" \
PYWIN_REDIST="$ROOT/vc_redist.x86.exe" \
python3 tools/make_python_pkg.py

echo
echo "产物：dist/Python-$VER-win32-Win7-补丁版.zip"
