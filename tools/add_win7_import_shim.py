#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
add_win7_import_shim.py — 把 python313.dll 里 6 个 Windows 8/8.1 才有的
KERNEL32 导入，重定向到随包分发的 win7k32shim.dll。

原理（纯 PE 结构手术：不搬代码、不改 IAT 地址）：
  1) 新增节 .w7imp，内含
       - KERNEL32 的新 ILT：168 项原样保留，6 个 Win8+ 项改指向「占位名」
         （Win7 确实存在的导出，只为让装载器解析成功）
       - 6 个新导入描述符，各指向 win7k32shim.dll，FirstThunk 精确指向
         原 IAT 中对应的那 4 字节槽位
       - 完整描述符数组（原 N 个 + 6 个新 + 结束项）
  2) 导入目录指向新数组。装载器按顺序处理：KERNEL32 先写占位地址，
     shim 后覆盖为真实现 —— 槽位最终是 shim 的函数。

用法: python3 add_win7_import_shim.py <in.dll> <out.dll>
"""
import struct
import sys

import pefile

SHIM_DLL = "win7k32shim.dll"

# 函数名 -> Win7 上确实存在的占位导出（参数字节数尽量对齐，避免误调时栈失衡）
REDIRECT = {
    "CopyFile2": "GetVolumePathNameW",          # 3 参 12 字节
    "PssCaptureSnapshot": "GetFullPathNameW",   # 4 参 16 字节
    "PssQuerySnapshot": "WriteFile",            # 5 参 20 字节
    "PssFreeSnapshot": "GetCurrentDirectoryW",  # 2 参 8 字节
    "AddDllDirectory": "LoadLibraryW",          # 1 参 4 字节
    "RemoveDllDirectory": "Sleep",              # 1 参 4 字节
    "GetCurrentThreadStackLimits": "GetCurrentDirectoryW",  # 2 参 8 字节
}


def align(v, a):
    return (v + a - 1) & ~(a - 1)


class Buf:
    def __init__(self, rva):
        self.base = rva
        self.buf = bytearray()

    def rva(self):
        return self.base + len(self.buf)

    def add(self, data, a=4):
        while len(self.buf) % a:
            self.buf.append(0)
        r = self.base + len(self.buf)
        self.buf += data
        return r

    def add_string(self, text):
        while len(self.buf) % 2:
            self.buf.append(0)
        r = self.base + len(self.buf)
        self.buf += text.encode() + b"\x00"
        return r

    def add_hint_name(self, text):
        while len(self.buf) % 2:
            self.buf.append(0)
        r = self.base + len(self.buf)
        self.buf += struct.pack("<H", 0) + text.encode() + b"\x00"
        return r


def main(src, dst):
    orig = open(src, "rb").read()
    data = bytearray(orig)
    pe = pefile.PE(data=orig, fast_load=True)
    pe.parse_data_directories(
        directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]]
    )

    opt = pe.OPTIONAL_HEADER
    sec_align, file_align = opt.SectionAlignment, opt.FileAlignment
    opt_off = pe.OPTIONAL_HEADER.get_file_offset()
    e_lfanew = pe.DOS_HEADER.e_lfanew

    descs = list(pe.DIRECTORY_ENTRY_IMPORT)
    i_k32 = next(i for i, e in enumerate(descs) if e.dll.decode().lower() == "kernel32.dll")
    k32 = descs[i_k32]
    ilt_rva = k32.struct.OriginalFirstThunk
    iat_rva = k32.struct.FirstThunk
    cnt = len(k32.imports)
    ilt = list(struct.unpack_from("<%dI" % (cnt + 1), data, pe.get_offset_from_rva(ilt_rva)))

    targets = [(i, imp.name.decode(), ilt[i])
               for i, imp in enumerate(k32.imports)
               if imp.name and imp.name.decode() in REDIRECT]
    if not targets:
        print("[i] KERNEL32 中无待重定向项（可能已处理），原样复制。")
        open(dst, "wb").write(orig)
        return

    last = pe.sections[-1]
    new_rva = align(last.VirtualAddress + max(last.Misc_VirtualSize, last.SizeOfRawData), sec_align)
    new_off = align(len(data), file_align)

    b = Buf(new_rva)

    # 1) 新 ILT 占位
    ilt_rva_new = b.add(b"\x00" * ((cnt + 1) * 4))
    ilt_buf_pos = len(b.buf) - (cnt + 1) * 4

    # 2) 占位 hint/name
    ph = {f: b.add_hint_name(REDIRECT[f]) for _, f, _ in targets}

    # 3) shim DLL 名
    dll_rva = b.add_string(SHIM_DLL)

    # 4) 每个被重定向函数：独享一个 8 字节 ILT + hint/name
    slots = []
    for i, f, _ in targets:
        nm = b.add_hint_name(f)
        one = b.add(struct.pack("<II", nm, 0))
        slots.append((f, one, i))

    # 回填新 ILT
    new_ilt = list(ilt)
    for i, f, _ in targets:
        new_ilt[i] = ph[f]
    struct.pack_into("<%dI" % (cnt + 1), b.buf, ilt_buf_pos, *new_ilt)

    # 5) 描述符数组
    arr = bytearray()
    for j, e in enumerate(descs):
        oft = ilt_rva_new if j == i_k32 else e.struct.OriginalFirstThunk
        arr += struct.pack("<IIIII", oft, e.struct.TimeDateStamp,
                           e.struct.ForwarderChain, e.struct.Name, e.struct.FirstThunk)
    for f, one, i in slots:
        arr += struct.pack("<IIIII", one, 0, 0, dll_rva, iat_rva + i * 4)
    arr += b"\x00" * 20
    desc_rva = b.add(bytes(arr))

    # ---- 落盘 ----
    body = bytes(b.buf)
    padded = body + b"\x00" * (align(len(body), file_align) - len(body))
    if len(data) < new_off:
        data += b"\x00" * (new_off - len(data))
    data += padded

    # 节头
    hdr_off = last.get_file_offset() + 40
    sh = struct.pack("<8sIIIIIIHHI",
                     b".w7imp\x00\x00", len(body), new_rva, len(padded), new_off,
                     0, 0, 0, 0, 0xC0000040)
    data[hdr_off:hdr_off + 40] = sh

    # 文件头：节数 +1
    struct.pack_into("<H", data, e_lfanew + 6, pe.FILE_HEADER.NumberOfSections + 1)
    # 可选头：SizeOfImage
    struct.pack_into("<I", data, opt_off + 56, align(new_rva + len(body), sec_align))
    # 数据目录[1] = 新导入表
    struct.pack_into("<II", data, opt_off + 96 + 8, desc_rva, len(arr))

    open(dst, "wb").write(bytes(data))

    # PE 校验和必须按「最终内容」重算：改过字节后，从官方 DLL 继承来的校验和已失效。
    # Windows 加载用户态 DLL 并不校验该字段，但审计/签名工具会看，保持自洽。
    _pe = pefile.PE(dst)
    _csum = _pe.generate_checksum()
    _off = _pe.OPTIONAL_HEADER.get_field_absolute_offset("CheckSum")
    _pe.close()
    with open(dst, "r+b") as _f:
        _f.seek(_off)
        _f.write(struct.pack("<I", _csum))

    print("[+] 写出 %s" % dst)
    print("    PE 校验和 0x%08X（按最终内容重算）" % _csum)
    print("    .w7imp  RVA=0x%x  off=0x%x  size=%d" % (new_rva, new_off, len(padded)))
    print("    导入表  RVA=0x%x  描述符=%d" % (desc_rva, len(descs) + len(slots) + 1))
    print("    重定向  %s" % ", ".join("%s->%s" % (f, SHIM_DLL) for _, f, _ in targets))

    # ---- 复核 ----
    chk = pefile.PE(dst, fast_load=True)
    chk.parse_data_directories(
        directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]]
    )
    ok = True
    for e in chk.DIRECTORY_ENTRY_IMPORT:
        d = e.dll.decode()
        names = [i.name.decode() if i.name else str(i.ordinal) for i in e.imports]
        if d == SHIM_DLL:
            print("    复核 %s -> %s" % (d, names))
        if d.lower() == "kernel32.dll":
            bad = [n for n in names if n in REDIRECT]
            print("    复核 KERNEL32 残留 Win8+ 项: %s" % (bad or "无"))
            ok = ok and not bad
            print("    复核 KERNEL32 导入数: %d" % len(names))
    print("    结果: %s" % ("PASS" if ok else "FAIL"))
    if not ok:
        sys.exit(1)


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
