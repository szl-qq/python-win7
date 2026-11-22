#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""verify_imports.py —— 独立复核打过补丁的 pythonXY.dll 是否真的能在 Win7 加载。

不做任何修改，只按 Windows 装载器的语义读导入表，检查四件事：

  1) 是否还有 Win8+ 独占的静态导入（剩下一个就启动失败）；
  2) 重定向描述符的 FirstThunk 是否精确落在 KERNEL32 的同一批 IAT 槽位上
     （槽位重叠是"别名覆盖"生效的前提，装载器按顺序后写覆盖先写）；
  3) 每个 KERNEL32 导入是否有名字（无名字的序号导入无法核对）；
  4) PE 校验和是否与最终字节自洽。

用法: python3 tools/verify_imports.py build/payload-3.13.16/python313.dll
退出码 0 = 全部通过。
"""
import sys

import pefile

WIN8PLUS = {
    "GetSystemTimePreciseAsFileTime",
    "CopyFile2",
    "AddDllDirectory",
    "RemoveDllDirectory",
    "PssCaptureSnapshot",
    "PssQuerySnapshot",
    "PssFreeSnapshot",
    "GetCurrentThreadStackLimits",
}

SHIM = "win7k32shim.dll"


def main(path):
    pe = pefile.PE(path)
    pe.parse_data_directories(
        directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]]
    )

    ok = True
    k32_slots = {}          # IAT 槽位 RVA -> 导入名
    shim_slots = {}         # 槽位 RVA -> shim 导出名
    k32_count = 0

    for e in pe.DIRECTORY_ENTRY_IMPORT:
        dll = e.dll.decode()
        low = dll.lower()
        if low == "kernel32.dll":
            k32_count = len(e.imports)
            unnamed = 0
            for imp in e.imports:
                name = imp.name.decode() if imp.name else None
                if name is None:
                    unnamed += 1
                else:
                    k32_slots[imp.address - pe.OPTIONAL_HEADER.ImageBase] = name
            bad = sorted({n for n in k32_slots.values() if n in WIN8PLUS})
            print("KERNEL32    导入 %3d 项   槽位 %3d 个" % (k32_count, len(k32_slots)))
            if unnamed:
                print("  [警告] %d 项按序号导入，无法核对名字" % unnamed)
            if bad:
                print("  [失败] 残留 Win8+ 静态导入: %s" % ", ".join(bad))
                ok = False
            else:
                print("  [通过] 无 Win8+ 静态导入")
        elif low == SHIM:
            for imp in e.imports:
                name = imp.name.decode() if imp.name else str(imp.ordinal)
                shim_slots[imp.address - pe.OPTIONAL_HEADER.ImageBase] = name

    # 别名检查：每个 shim 槽位必须同时是 KERNEL32 的槽位，否则覆盖不会发生
    print("shim        重定向 %3d 项" % len(shim_slots))
    orphan = sorted(set(shim_slots) - set(k32_slots))
    for rva, name in sorted(shim_slots.items()):
        target = k32_slots.get(rva)
        if target:
            print("  [通过] IAT RVA %#08x  %-28s <- %s" % (rva, target, name))
        else:
            print("  [失败] IAT RVA %#08x  该槽位不属于 KERNEL32" % rva)
    if orphan:
        ok = False

    if not shim_slots:
        print("  [提示] 未发现 %s 描述符：该 DLL 可能未打补丁" % SHIM)
        ok = False

    stored = pe.OPTIONAL_HEADER.CheckSum
    calc = pe.generate_checksum()
    same = stored == calc
    print("PE 校验和   stored=%#010x calc=%#010x  %s" % (stored, calc, "[通过]" if same else "[警告] 不自洽"))
    if not same:
        print("  （Windows 加载用户态 DLL 不校验该字段，不影响运行；建议重算）")

    print("\n结果: %s" % ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("用法: python3 verify_imports.py <pythonXY.dll>")
        sys.exit(2)
    sys.exit(main(sys.argv[1]))
