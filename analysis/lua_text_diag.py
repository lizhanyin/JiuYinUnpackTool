# -*- coding: utf-8 -*-
"""lua / text 最终攻坚：正确的旧 rec0 名 crib + crib 长度阶梯 + 周期扫描 + 链式走。"""
import struct, collections, json, zlib
import numpy as np

OLD_ROOT = r"F:\Game\Online\9yin\20230423\9yin"
NEW_ROOT = r"F:\Game\Online\9yin\9yin"

def load_head_index(path):
    with open(path, "rb") as f:
        head = f.read(0x13)
        rsv, = struct.unpack_from("<H", head, 8)
        cnt, = struct.unpack_from("<I", head, 0x0A)
        idxend, = struct.unpack_from("<I", head, 0x0E)
        f.seek(0x13)
        return rsv, cnt, idxend, f.read(idxend - 0x13)

def old_rec0(path):
    _, _, _, oidx = load_head_index(path)
    rl = struct.unpack_from("<H", oidx, 0)[0]
    return oidx[27:rl - 1], oidx, rl

for rel in ("res\\lua.package", "res\\text.package"):
    nm, oidx, rl0 = old_rec0(OLD_ROOT + "\\" + rel)
    rsv, cn, en, nidx = load_head_index(NEW_ROOT + "\\" + rel)
    print(f"{rel}: rsv=0x{rsv:04x} cnt={cn} 旧rec0={nm[:50]!r} (len={len(nm)})")

# ---- lua：注意 lua64 实测名字无 res 前缀，先确认旧 lua 名字 ----
# ---- 通用函数 ----
def pscan(C, KS, P):
    n = len(C)
    kmod = {}
    for p_, v in KS.items():
        r = p_ % P
        if r in kmod and kmod[r] != v:
            return -1
        kmod[r] = v
    kv = np.full(P, -1, np.int32)
    for r, v in kmod.items():
        kv[r] = v
    pos = np.arange(n - 27, dtype=np.int64)
    ok = np.ones(len(pos), bool)
    for o in (6, 7, 8, 9):
        k = kv[(pos + o) % P]
        ok &= (k >= 0) & (C[pos + o].astype(np.int32) == k)
    return int(ok.sum())

def crib_ladder(name0, C, P_list):
    """crib 长度 8..min(48,len)，返回 (best_len, {P: hits})"""
    out = []
    for L in range(8, min(49, len(name0)) + 1):
        KS = {**{j: int(C[j]) for j in (6, 7, 8, 9, 25, 26)},
              19: int(C[19]) ^ 0x07,
              **{27 + j: int(C[27 + j]) ^ ch for j, ch in enumerate(name0[:L])}}
        best = max(((pscan(C, KS, P), P) for P in P_list))
        out.append((L, best))
    return out

print()
for rel, P_list in (("res\\lua.package", list(range(16, 2601, 2))),
                    ("res\\text.package", list(range(16, 2601, 2)))):
    nm, oidx, rl0 = old_rec0(OLD_ROOT + "\\" + rel)
    rsv, cn, en, nidx = load_head_index(NEW_ROOT + "\\" + rel)
    C = np.frombuffer(nidx, np.uint8)
    ladder = crib_ladder(nm, C, P_list)
    print(f"{rel} crib 阶梯 (长度 -> (命中, P)):")
    prev = -1
    for L, (h, P) in ladder:
        mark = ""
        if h > prev:
            mark = " <- 增长"
        elif h < prev:
            mark = " <- 下降(名字分叉)"
        prev = max(prev, h)
        print(f"  L={L}: hits={h} P={P}{mark}")
