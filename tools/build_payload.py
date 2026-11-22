#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""build_payload.py —— 由官方 embeddable 目录生成 Win7 可用的 payload。

两个版本（3.13 / 3.15）共用同一套流程：
  1) 复制官方目录到目标目录
  2) 静态导入改名：GetSystemTimePreciseAsFileTime -> GetSystemTimeAsFileTime
     （同为 void(LPFILETIME)，等长改写，只降时间精度）
  3) 追加节 .w7imp：把 7 个 Win8/8.1 独占的 KERNEL32 导入重定向到
     win7k32shim.dll（见 add_win7_import_shim.py）
  4) 放入两个 shim：win7k32shim.dll、api-ms-win-core-path-l1-1-0.dll

用法: python3 build_payload.py <官方目录> <输出目录> <pythonXY.dll>
"""
import os
import shutil
import struct
import subprocess
import sys

import pefile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)                       # 仓库根目录
SHIM_DIR = os.environ.get("PYWIN_SHIM_DIR") or os.path.join(ROOT, "shim")

RENAME = ("GetSystemTimePreciseAsFileTime", "GetSystemTimeAsFileTime")


def rename_import(data, old, new):
    """把导入名就地改写成长度更短的名字（后面补 0）。

    必须精确定位到 *导入名表* 里的那条记录：DLL 里同名文本可能出现在
    别处（如调试/文档字符串），盲搜会改错地方。
    """
    pe = pefile.PE(data=data, fast_load=True)
    pe.parse_data_directories(
        directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]]
    )
    raw = bytes(data)
    for e in pe.DIRECTORY_ENTRY_IMPORT:
        ilt = e.struct.OriginalFirstThunk
        if not ilt:
            continue
        base = pe.get_offset_from_rva(ilt)
        for i, imp in enumerate(e.imports):
            if not imp.name or imp.name.decode() != old:
                continue
            v = struct.unpack_from("<I", raw, base + i * 4)[0]
            off = pe.get_offset_from_rva(v & 0x7FFFFFFF) + 2
            if raw[off:off + len(old)] != old.encode():
                continue
            patch = new.encode() + b"\x00" * (len(old) - len(new))
            return (raw[:off] + patch + raw[off + len(old):]), 1
    return raw, 0


def main(src, dst, dll_name):
    if os.path.isdir(dst):
        shutil.rmtree(dst)
    shutil.copytree(src, dst)

    dll = os.path.join(dst, dll_name)
    data = open(dll, "rb").read()
    data, hits = rename_import(data, RENAME[0], RENAME[1])
    open(dll, "wb").write(data)
    print("[2] 导入改名 %s -> %s  命中 %d 处" % (RENAME[0], RENAME[1], hits))

    tmp = dll + ".tmp"
    r = subprocess.run([sys.executable, os.path.join(HERE, "add_win7_import_shim.py"), dll, tmp],
                       capture_output=True, text=True)
    print(r.stdout.strip())
    if r.returncode != 0:
        print(r.stderr)
        raise SystemExit("导入重定向失败")
    os.replace(tmp, dll)

    for n in ("win7k32shim.dll", "api-ms-win-core-path-l1-1-0.dll"):
        shutil.copy2(os.path.join(SHIM_DIR, n), os.path.join(dst, n))
        print("[4] 放入 shim %s" % n)

    print("\n[OK] payload 就绪: %s（%d 个文件）" % (dst, len(os.listdir(dst))))


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2], sys.argv[3])
