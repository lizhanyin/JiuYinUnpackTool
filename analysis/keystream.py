# -*- coding: utf-8 -*-
"""已知明文攻击：eff.package 新旧索引同长（cnt=79, idxend=0xe7c）。
若条目未变，old_index 即明文，new_index 为密文，XOR 得密钥流。"""
import struct

OLD = r"F:\Game\Online\9yin\20230423\9yin\res\eff.package"
NEW = r"F:\Game\Online\9yin\9yin\res\eff.package"

def load_index(path):
    with open(path, "rb") as f:
        head = f.read(0x13)
        flag, = struct.unpack_from("<H", head, 6)
        cnt, = struct.unpack_from("<I", head, 0x0A)
        idxend, = struct.unpack_from("<I", head, 0x0E)
        idx = f.read(idxend - 0x13)
    return flag, cnt, idxend, idx

fo, co, eo, io = load_index(OLD)
fn, cn, en, inx = load_index(NEW)
print(f"old: flag={fo} cnt={co} idxend=0x{eo:x} len={len(io)}")
print(f"new: flag={fn} cnt={cn} idxend=0x{en:x} len={len(inx)}")
assert len(io) == len(inx)

ks = bytes(a ^ b for a, b in zip(io, inx))
print("\nkeystream (old XOR new), first 256 bytes:")
for i in range(0, 256, 32):
    row = ks[i:i+32]
    print(f"  {i:04x}: {row.hex(' ')}  {''.join(chr(c) if 32 <= c < 127 else '.' for c in row)}")

# 检查周期性：ks[i] == ks[i+L] 的比例
n = len(ks)
print(f"\nkeystream length = {n}")
for L in range(1, 513):
    if n <= 2 * L:
        break
    match = sum(1 for i in range(n - L) if ks[i] == ks[i + L])
    if match == n - L:
        print(f"PERFECT period {L}")
    elif match / (n - L) > 0.9:
        print(f"partial period {L}: {match}/{n-L} = {match/(n-L):.3f}")

# 长程熵
distinct = len(set(ks))
print(f"distinct byte values in keystream: {distinct}/256")
