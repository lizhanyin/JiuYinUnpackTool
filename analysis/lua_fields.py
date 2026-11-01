# -*- coding: utf-8 -*-
"""逐字段解密新 dump，打印每个字段的解密值，定位第一个异常字段。"""
import struct, zlib, json
import numpy as np

KEY = open(r"F:\pojie\ai\JiuYinUnpackTool\analysis\_new_key.bin", "rb").read() if False else None
data = open(r"F:\Game\Online\9yin\9yin\updater_\fxupdate.exe", "rb").read()
i = data.find(b"abcd464fghfgfjhf")
end = i
while 0x20 <= data[end] <= 0x7e:
    end += 1
KEY = data[i:end]

def get_first_lua(pkg, idx_key_hex):
    with open(pkg, "rb") as f:
        head = f.read(0x13)
        idxend = struct.unpack_from("<I", head, 0x0E)[0]
        f.seek(0x13)
        nidx = f.read(idxend - 0x13)
    kb = bytes.fromhex(idx_key_hex)
    P = len(kb)
    C = np.frombuffer(nidx, np.uint8)
    tile = np.tile(np.frombuffer(kb, np.uint8), len(C)//P + 1)[:len(C)]
    dec = (C ^ tile).tobytes()
    pos = 0
    while pos + 27 <= len(dec):
        rl = struct.unpack_from("<H", dec, pos)[0]
        nm = dec[pos+27:pos+rl-1]
        if nm.endswith(b".lua"):
            off = struct.unpack_from("<Q", dec, pos+2)[0]
            raw, comp = struct.unpack_from("<II", dec, pos+10)
            whole = open(pkg, "rb").read()
            return zlib.decompress(whole[off:off+comp])
        pos += rl

keys = json.load(open(r"G:\pojie\ai\JiuYinUnpackTool\analysis\keys_norm.json"))
d = get_first_lua(r"F:\Game\Online\9yin\9yin\res\lua.package", keys["96fc"])
K = len(KEY)
n = len(d)

def fx(buf, p, m):
    """按逐字段 XOR 解密 buf[p:p+m]（密钥从 0）。"""
    return bytes(buf[p + j] ^ KEY[j % K] for j in range(m))

p = 12
print(f"dump 长度 {n}，密钥 {K}")
# 1. source size_t 前缀
sz = int.from_bytes(fx(d, p, 4), "little"); p += 4
print(f"source n = {sz}")
# 2. source 内容
src = fx(d, p, sz); p += sz
print(f"source = {src!r}")
# 3. linedefined / lastlinedefined
ld = int.from_bytes(fx(d, p, 4), "little"); p += 4
lld = int.from_bytes(fx(d, p, 4), "little"); p += 4
print(f"linedefined={ld} lastlinedefined={lld}")
# 4. nups numparams is_vararg maxstack
b4 = fx(d, p, 4); p += 4
print(f"nups={b4[0]} numparams={b4[1]} is_vararg={b4[2]} maxstack={b4[3]}")
# 5. sizecode
sizecode = int.from_bytes(fx(d, p, 4), "little"); p += 4
print(f"sizecode={sizecode}（剩余 {n-p}，需 {sizecode*4}）")
# 6. 指令数组（不解全部，取前 3 条指令看 opcode）
ins = fx(d, p, 12)
print(f"前3条指令: {' '.join(f'{x:08x}' for x in struct.unpack('<3I', ins))}")
p += sizecode * 4
# 7. sizek
sizek = int.from_bytes(fx(d, p, 4), "little"); p += 4
print(f"sizek={sizek}（剩余 {n-p}）")
# 8. 常量 tag
for ci in range(min(sizek, 8)):
    tag = fx(d, p, 1)[0]; p += 1
    print(f"  k[{ci}] tag={tag}", end="")
    if tag == 3:
        num = fx(d, p, 8); p += 8
        print(f" NUMBER={struct.unpack('<d', num)[0]!r}", end="")
    elif tag == 4:
        slen = int.from_bytes(fx(d, p, 4), "little"); p += 4
        print(f" STRING len={slen}", end="")
        if 0 < slen < 200 and p + slen <= n:
            s = fx(d, p, slen); p += slen
            print(f" {s[:40]!r}", end="")
    print()
    if tag not in (0, 1, 3, 4):
        print("  ^^ 非法 tag —— 分歧定位到此处")
        break
