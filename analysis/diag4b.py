# -*- coding: utf-8 -*-
"""诊断 4 个失败包：前缀 crib + P=16..1024 折叠零命中扫描（全向量化）。"""
import struct, os
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

targets = ["res\\lua.package", "res\\lua64.package", "res\\map_ini.package", "res\\text.package"]
PREFIX = {"lua": b"res\\lua\\", "lua64": b"res\\lua64\\",
          "map_ini": b"res\\map\\ini\\", "text": b"res\\text\\"}

for rel in targets:
    np_ = os.path.join(NEW_ROOT, rel)
    rn, cn, en, nidx = load_head_index(np_)
    stem = os.path.basename(rel).rsplit(".", 1)[0]
    pref = PREFIX[stem]
    C = np.frombuffer(nidx, np.uint8)
    n = len(C)
    KS = {}
    for j, ch in enumerate(pref):
        KS[27 + j] = int(C[27 + j]) ^ ch
    for j in range(6, 10):
        KS[j] = int(C[j])
    KS[19] = int(C[19]) ^ 0x07
    KS[25] = int(C[25])
    KS[26] = int(C[26])

    pos_arr = np.arange(n - 27, dtype=np.int64)
    res = []
    for P in range(16, 1025):
        kmod = np.full(P, -1, np.int32)
        conflict = False
        for p_, v in KS.items():
            r = p_ % P
            if kmod[r] >= 0 and kmod[r] != v:
                conflict = True
                break
            kmod[r] = v
        if conflict:
            continue
        ok = np.ones(len(pos_arr), bool)
        for o in (6, 7, 8, 9):
            r = (pos_arr + o) % P
            kv = kmod[r]
            vals = C[pos_arr + o].astype(np.int32)
            ok &= (kv >= 0) & (vals == kv)
        res.append((int(ok.sum()), P))
    res.sort(reverse=True)
    print(f"{rel} rsv=0x{rn:04x}: top5 = {res[:5]}")
