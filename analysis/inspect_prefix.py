# -*- coding: utf-8 -*-
"""精确检查 ks 中周期性重复的区段，并排打印新旧索引前几条记录。"""
import struct

OLD = r"F:\Game\Online\9yin\20230423\9yin\res\eff.package"
NEW = r"F:\Game\Online\9yin\9yin\res\eff.package"
IDX_LEN = 0xe7c - 0x13

def load(path):
    with open(path, "rb") as f:
        f.seek(0x13)
        return f.read(IDX_LEN)

old, new = load(OLD), load(NEW)
ks = bytes(a ^ b for a, b in zip(old, new))

# 1) ks 与 ks[L:] 的逐位置相等-run，对所有 L 1..600
print("== ks 自相关（相等 run >= 24）==")
for L in range(1, 601):
    run = 0
    best = 0
    best_end = 0
    for i in range(len(ks) - L):
        if ks[i] == ks[i + L]:
            run += 1
            if run > best:
                best = run
                best_end = i + 1
        else:
            run = 0
    if best >= 24:
        print(f"  L={L} (0x{L:x}): longest equal-run = {best}, ends at abs {best_end}")

# 2) 记录边界
recs = []
pos = 0
while pos + 27 <= IDX_LEN:
    rl = struct.unpack_from("<H", old, pos)[0]
    recs.append((pos, rl))
    pos += rl
print("\n== 旧索引前 6 条记录 ==")
for k, (s, rl) in enumerate(recs[:6]):
    rec = old[s:s+rl]
    off = struct.unpack_from("<Q", rec, 2)[0]
    raw, comp = struct.unpack_from("<II", rec, 10)
    name = rec[27:27+rec[27:].index(0)]
    print(f"  #{k} @0x{s:04x} len={rl:3d} off=0x{off:08x} raw={raw:6d} comp={comp:6d} ts={rec[18:25].hex()} name={name.decode('gbk', 'replace')}")
lens = [rl for _, rl in recs]
print(f"record lens: {lens[:12]} ...")
