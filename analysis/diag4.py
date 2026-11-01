# -*- coding: utf-8 -*-
"""诊断 4 个失败包：record0 是否以预期前缀开头（用 crib 检查解密一致性）。
若前缀 crib 成立，则对 P=16..1024 做折叠零命中扫描 + 全量验证。"""
import struct, os, json
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

def parse_old(idx):
    recs, pos = [], 0
    while pos + 27 <= len(idx):
        rl = struct.unpack_from("<H", idx, pos)[0]
        nm = idx[pos+27:pos+rl]
        z = nm.find(0)
        recs.append(nm[:z])
        pos += rl
    return recs

# 每个失败包：拿旧前 20 个记录名做 record0 crib 候选，同时测试多个 P
targets = ["res\\lua.package", "res\\lua64.package", "res\\map_ini.package", "res\\text.package"]
PREFIX_BY_STEM = {"lua": b"res\\lua\\", "lua64": b"res\\lua64\\",
                  "map_ini": b"res\\map\\ini\\", "text": b"res\\text\\"}

for rel in targets:
    np_ = os.path.join(NEW_ROOT, rel)
    op = os.path.join(OLD_ROOT, rel)
    rn, cn, en, nidx = load_head_index(np_)
    _, co, eo, oidx = load_head_index(op)
    orecs = parse_old(oidx)
    stem = os.path.basename(rel).rsplit(".", 1)[0]
    pref = PREFIX_BY_STEM.get(stem, b"res\\")
    C = np.frombuffer(nidx, np.uint8)
    n = len(C)
    # crib: 前缀 + record0 结构（绝对位置 KS）
    KS = {}
    for j, ch in enumerate(pref):
        KS[27 + j] = int(C[27 + j]) ^ ch
    for j in range(6, 10):
        KS[j] = int(C[j])
    KS[19] = int(C[19]) ^ 0x07
    KS[25] = int(C[25])
    KS[26] = int(C[26])
    # P 扫描：折叠后已知残差类的零命中
    best = []
    for P in range(16, 1025):
        kmod = {}
        conflict = False
        for pos, v in KS.items():
            r = pos % P
            if r in kmod and kmod[r] != v:
                conflict = True
                break
            kmod[r] = v
        if conflict:
            continue
        # 扫描：位置 p 使 p+6..9 折叠残差全部已知且密文==K
        cnt_hit = 0
        rs = [(6, 0), (7, 0), (8, 0), (9, 0)]
        # 向量化
        pos_arr = np.arange(n - 27)
        ok = np.ones(len(pos_arr), bool)
        for o in (6, 7, 8, 9):
            r = np.array([(p + o) % P for p in pos_arr[:min(n, 200000)]])
            kv = np.array([kmod.get(int(x), -1) for x in r])
            okseg = kv >= 0
            vals = C[pos_arr[:min(n, 200000)] + o]
            ok[:min(n, 200000)][okseg] &= (vals[okseg] == kv[okseg])
            ok[:min(n, 200000)][~okseg] = False
        cnt_hit = int(ok.sum())
        best.append((cnt_hit, P))
    best.sort(reverse=True)
    print(f"{rel} (rsv=0x{rn:04x}): 前5候选 (命中,P): {best[:5]}  旧rec0={orecs[0][:30]!r}")
