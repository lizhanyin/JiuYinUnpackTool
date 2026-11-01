# -*- coding: utf-8 -*-
"""掩码自相关破解：只统计新旧明文必然相同的位置（名字、偏移高4字节零、
extra 零、NUL），排除数据重写污染的 offset低位/size/ts 字段。
适用于 map_ini / lua / lua64 / text 等数据被重写的包。"""
import struct, collections, json, os, sys
import numpy as np

OLD_ROOT = r"F:\Game\Online\9yin\20230423\9yin"
NEW_ROOT = r"F:\Game\Online\9yin\9yin"

def load_head_index(path):
    with open(path, "rb") as f:
        head = f.read(0x13)
        flag, = struct.unpack_from("<H", head, 6)
        rsv, = struct.unpack_from("<H", head, 8)
        cnt, = struct.unpack_from("<I", head, 0x0A)
        idxend, = struct.unpack_from("<I", head, 0x0E)
        f.seek(0x13)
        return flag, rsv, cnt, idxend, f.read(idxend - 0x13)

def parse_old_records(idx):
    recs, pos = [], 0
    while pos + 27 <= len(idx):
        rl = struct.unpack_from("<H", idx, pos)[0]
        if rl < 28 or pos + rl > len(idx):
            break
        recs.append((pos, rl))
        pos += rl
    return recs

def masked_ks(recs, oidx, nidx):
    """返回 (ks, mask)：仅包含新旧明文必然相同的位置。"""
    m = min(len(oidx), len(nidx))
    ks = np.frombuffer(bytes(a ^ b for a, b in zip(oidx[:m], nidx[:m])), np.uint8)
    mask = np.zeros(m, bool)
    for pos, rl in recs:
        if pos + rl > m:
            break
        # 偏移高 4 字节（恒 0）
        mask[pos+6:pos+10] = True
        # extra（.package 恒 0）
        mask[pos+25:pos+27] = True
        # 名字字符 + 结尾 NUL
        mask[pos+27:pos+rl] = True
    return ks, mask

def find_period_masked(ks, mask, pmin=16, pmax=8192):
    idx = np.nonzero(mask)[0]
    if len(idx) < 400:
        return []
    res = []
    for P in range(pmin, pmax + 1):
        a = idx[idx + P < len(ks)]
        if len(a) < 200:
            break
        b = a + P
        # 两端都必须在掩码内（同一记录的相同字段未必同余，故要求两侧皆掩码位）
        both = a[mask[b]]
        if len(both) < 100:
            continue
        eq = np.count_nonzero(ks[both] == ks[both + P])
        res.append((eq / len(both), P, len(both)))
    res.sort(reverse=True)
    return res

def extract_key_masked(ks, mask, recs, P):
    votes = collections.defaultdict(collections.Counter)
    for pos, rl in recs:
        if pos + rl > len(ks):
            break
        for j in list(range(6, 10)) + [25, 26] + list(range(27, rl)):
            p_ = pos + j
            if p_ < len(ks) and mask[p_]:
                votes[p_ % P][int(ks[p_])] += 1
    key = {}
    for r in range(P):
        if r in votes:
            v, c = votes[r].most_common(1)[0]
            key[r] = v
    if len(key) < P:
        return None
    return bytes(key[r] for r in range(P))

def full_parse(nidx, key, cnt):
    P = len(key)
    C = np.frombuffer(nidx, np.uint8)
    tile = np.tile(np.frombuffer(key, np.uint8), len(C) // P + 1)[:len(C)]
    dec = (C ^ tile).tobytes()
    pos, nrec = 0, 0
    while pos + 27 <= len(dec):
        rl = struct.unpack_from("<H", dec, pos)[0]
        if rl < 28 or pos + rl > len(dec) or dec[pos + rl - 1] != 0:
            return None, nrec
        pos += rl
        nrec += 1
    return (nrec == cnt and pos == len(dec)), nrec

def crack(rel):
    np_ = os.path.join(NEW_ROOT, rel)
    op = os.path.join(OLD_ROOT, rel)
    flag, rsv, cn, en, nidx = load_head_index(np_)
    fo, ro, co, eo, oidx = load_head_index(op)
    recs = parse_old_records(oidx)
    ks, mask = masked_ks(recs, oidx, nidx)
    print(f"{rel}: rsv=0x{rsv:04x} cnt={cn} 掩码位={int(mask.sum())}/{len(ks)}")
    top = find_period_masked(ks, mask)
    print(f"  掩码自相关 top5: {[(round(r,3),P,n) for r,P,n in top[:5]]}")
    seen = set()
    for rate, P, _n in top[:40]:
        fam = [P] + [P // d for d in range(2, 60) if P % d == 0 and P // d >= 16]
        for Pc in sorted(set(fam), reverse=True):
            if Pc in seen:
                continue
            seen.add(Pc)
            key = extract_key_masked(ks, mask, recs, Pc)
            if key is None:
                continue
            ok, nrec = full_parse(nidx, key, cn)
            if ok:
                return rsv, Pc, key
    return None, None, None

if __name__ == "__main__":
    targets = sys.argv[1:] or ["res\\map_ini.package", "res\\text.package",
                               "res\\lua.package", "res\\lua64.package"]
    keys = json.load(open(r"G:\pojie\ai\JiuYinUnpackTool\analysis\keys_norm.json"))
    for rel in targets:
        rsv, P, key = crack(rel)
        if key:
            keys[f"{rsv:04x}"] = key.hex()
            print(f"  -> P={P} OK！密钥已提取\n")
        else:
            print(f"  -> FAIL\n")
    json.dump(keys, open(r"G:\pojie\ai\JiuYinUnpackTool\analysis\keys_norm.json", "w"), indent=1)
    print(f"keys_norm.json 现有 {len(keys)} 个密钥")
