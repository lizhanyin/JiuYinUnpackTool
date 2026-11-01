# -*- coding: utf-8 -*-
"""诊断：
1) 2023 dump 是否明文（chunkname 直接可读？）
2) 新 dump 系统测试 XOR 变体：密钥旋转 r、连续流 vs 逐字段、字段粒度变化
"""
import struct, zlib, json
import numpy as np

d_old = open(r"G:\pojie\ai\JiuYinUnpackTool\analysis\_old_anim.bin", "rb").read()
print("== 2023 lua\\animation.lua ==")
n_old = int.from_bytes(d_old[12:16], "little")
print(f"source size_t(明文读) = {n_old}")
if 0 < n_old < 300:
    print(f"source = {d_old[16:16+n_old][:60]!r}")

# 新 dump
keys = json.load(open(r"G:\pojie\ai\JiuYinUnpackTool\analysis\keys_norm.json"))
def get_first_lua(pkg, idx_key_hex):
    with open(pkg, "rb") as f:
        head = f.read(0x13)
        idxend = struct.unpack_from("<I", head, 0x0E)[0]
        f.seek(0x13)
        nidx = f.read(idxend - 0x13)
    P = len(bytes.fromhex(idx_key_hex))
    C = np.frombuffer(nidx, np.uint8)
    tile = np.tile(np.frombuffer(bytes.fromhex(idx_key_hex), np.uint8), len(C)//P + 1)[:len(C)]
    dec = (C ^ tile).tobytes()
    pos = 0
    while pos + 27 <= len(dec):
        rl = struct.unpack_from("<H", dec, pos)[0]
        nm = dec[pos+27:pos+rl-1]
        if nm.endswith(b".lua"):
            off = struct.unpack_from("<Q", dec, pos+2)[0]
            raw, comp = struct.unpack_from("<II", dec, pos+10)
            whole = open(pkg, "rb").read()
            return nm.decode(), zlib.decompress(whole[off:off+comp])
        pos += rl
    return None, None

name, d_new = get_first_lua(r"F:\Game\Online\9yin\9yin\res\lua.package", keys["96fc"])
print(f"\n== 新 lua\\{name} == 头12: {d_new[:12].hex(' ')} 长度 {len(d_new)}")

new_key = open(r"F:\Game\Online\9yin\9yin\updater_\fxupdate.exe", "rb").read()
i = new_key.find(b"abcd464fghfgfjhf")
end = i
while 0x20 <= new_key[end] <= 0x7e:
    end += 1
KEY = new_key[i:end]
K = len(KEY)
print(f"密钥 {K} 字节")

# 变体 A：逐字段重置 + 密钥旋转 r —— 第一个字段是 source 的 size_t 前缀
# n = LE32(d[12:16] ^ KEY[r:r+4])；chunkname 通常 20..90 且以 '@' 开头
print("\n-- 密钥旋转扫描（逐字段，source 前缀合理性）--")
hits = []
for r in range(K):
    x = bytes(a ^ b for a, b in zip(d_new[12:16], KEY[r:r+4]))
    n = int.from_bytes(x, "little")
    if 20 <= n <= 120:
        # 内容也用旋转密钥解：位置 12+4+j 用 KEY[(r+4+j)%K]
        content = bytes(a ^ b for a, b in zip(d_new[16:16+8], KEY[(r+4)%K:(r+12)%K or K]))
        hits.append((r, n, content[:8]))
for r, n, c in hits[:10]:
    print(f"  r={r}: n={n} 内容头={c!r}")

# 变体 B：连续流（不逐字段重置）：payload[0]=d[12] 用 key[r]，payload[j] 用 key[(r+j)%K]
print("\n-- 连续流扫描 --")
hits2 = []
for r in range(K):
    x = bytes(a ^ b for a, b in zip(d_new[12:16], KEY[r:r+4]))
    n = int.from_bytes(x, "little")
    if 20 <= n <= 120:
        content = bytes(d_new[16+j] ^ KEY[(r+4+j) % K] for j in range(8))
        hits2.append((r, n, content))
for r, n, c in hits2[:10]:
    print(f"  r={r}: n={n} 内容头={c!r}")

# 变体 C：xor 常数/加法？先看密文与已知明文的关系。
# chunkname 以 '@' 开头的概率高：如果 source 可读，d[16]^k = '@'(0x40)
# 变体 D：密钥用反转
KR = KEY[::-1]
hits3 = []
for r in range(K):
    x = bytes(a ^ b for a, b in zip(d_new[12:16], KR[r:r+4]))
    n = int.from_bytes(x, "little")
    if 20 <= n <= 120:
        content = bytes(d_new[16+j] ^ KR[(r+4+j) % K] for j in range(8))
        hits3.append((r, n, content))
print("\n-- 反转密钥（连续流）--")
for r, n, c in hits3[:6]:
    print(f"  r={r}: n={n} 内容头={c!r}")
