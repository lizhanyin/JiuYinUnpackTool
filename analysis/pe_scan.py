# -*- coding: utf-8 -*-
"""fxpackage.dll 静态分析：定位 PCK0 解析与索引解密代码。"""
import struct

DLL = r"F:\Game\Online\9yin\9yin\bin64\fxpackage.dll"
data = open(DLL, "rb").read()
print(f"size={len(data):#x}, dos={data[:2]}")

# --- 手工解析 PE 头 ---
pe_off = struct.unpack_from("<I", data, 0x3C)[0]
assert data[pe_off:pe_off+4] == b"PE\x00\x00"
machine = struct.unpack_from("<H", data, pe_off + 4)[0]
nsec = struct.unpack_from("<H", data, pe_off + 6)[0]
opt_size = struct.unpack_from("<H", data, pe_off + 20)[0]
opt = pe_off + 24
magic = struct.unpack_from("<H", data, opt)[0]
imgbase = struct.unpack_from("<Q", data, opt + 24)[0] if magic == 0x20b else struct.unpack_from("<I", data, opt + 28)[0]
print(f"machine={machine:#x} (8664=x64) sections={nsec} optmagic={magic:#x} imagebase={imgbase:#x}")

secs = []
sec_off = opt + opt_size
for i in range(nsec):
    o = sec_off + i * 40
    name = data[o:o+8].rstrip(b"\x00").decode()
    vsize, vaddr, rsize, raddr = struct.unpack_from("<IIII", data, o + 8)
    secs.append((name, vaddr, vsize, raddr, rsize))
    print(f"  {name:<10} va={vaddr:#010x} vsz={vsize:#010x} raw={raddr:#010x} rsz={rsize:#010x}")

def rva2off(rva):
    for name, vaddr, vsize, raddr, rsize in secs:
        if vaddr <= rva < vaddr + max(vsize, rsize):
            return raddr + (rva - vaddr)
    return None

def off2rva(off):
    for name, vaddr, vsize, raddr, rsize in secs:
        if raddr <= off < raddr + rsize:
            return vaddr + (off - raddr)
    return None

# --- 找 .text 里的 "PCK0" 立即数 ---
for name, vaddr, vsize, raddr, rsize in secs:
    if name == ".text":
        text = data[raddr:raddr+rsize]
        text_va = vaddr
        break

hits = []
start = 0
while True:
    i = text.find(b"PCK0", start)
    if i < 0:
        break
    hits.append(i)
    start = i + 1
print(f"\n'PCK0' in .text: {len(hits)} hits at rva:", [hex(text_va + h) for h in hits])

# 0xC8 = 200 立即数出现位置（太常见，仅在 PCK0 命中附近找）
for h in hits:
    rva = text_va + h
    print(f"\n--- context around rva {rva:#x} ---")
    lo = max(0, h - 64)
    hi = min(len(text), h + 64)
    print(text[lo:hi].hex(" "))
