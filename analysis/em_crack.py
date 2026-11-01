# -*- coding: utf-8 -*-
"""EM 精化破解：适用于数据重写（offset 全变）的包。
1. ks = old ^ new 前缀（名字/零区仍是有效密钥流，仅 offset/size 字段被污染）
2. P 扫描：列一致性（每列众数占比均值），而非总体匹配率
3. 种子密钥 = 各列众数
4. EM：解密 -> 扫描全索引真起点（4零+extra 零+0x07 投票）-> 重建列 -> 迭代
5. 全量解析终审"""
import struct, collections, os, json
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

def old_bounds(oidx):
    b, pos = [], 0
    while pos + 27 <= len(oidx):
        rl = struct.unpack_from("<H", oidx, pos)[0]
        b.append(pos + rl)
        pos += rl
    return b

def column_consistency(a, P):
    x = (len(a) // P) * P
    if x < 2 * P:
        return 0.0
    m = a[:x].reshape(-1, P).astype(np.int32)
    rows = m.shape[0]
    offs = (np.arange(P, dtype=np.int32) * 256)
    counts = np.bincount((m + offs).ravel(), minlength=P * 256).reshape(P, 256)
    return float(counts.max(axis=1).sum()) / (P * rows)

def column_mode(a, P):
    x = (len(a) // P) * P
    m = a[:x].reshape(-1, P).astype(np.int32)
    offs = (np.arange(P, dtype=np.int32) * 256)
    counts = np.bincount((m + offs).ravel(), minlength=P * 256).reshape(P, 256)
    return counts.argmax(axis=1).astype(np.uint8)

def em_refine(C, cnt, key, rounds=6):
    n = len(C)
    P = len(key)
    for it in range(rounds):
        tile = np.tile(key, n // P + 1)[:n]
        D = C ^ tile
        # 候选起点：4 连零 + 19=07 + 25/26 零（用当前 key 解密）
        z4 = np.zeros(n - 27, bool)
        z4 |= (D[6:n-21] | D[7:n-20] | D[8:n-19] | D[9:n-18]) != 0  # True 表示非零
        cand = np.arange(n - 27)[~z4]
        if len(cand) == 0:
            return None, 0
        # +19/+25/+26 硬校验
        keep = (D[cand + 19] == 0x07) & (D[cand + 25] == 0) & (D[cand + 26] == 0)
        cand = cand[keep]
        if len(cand) < 10:
            return None, len(cand)
        # 投票
        votes = collections.defaultdict(collections.Counter)
        for p in cand.tolist():
            for o in (6, 7, 8, 9, 25, 26):
                votes[(p + o) % P][int(C[p + o])] += 1
            votes[(p + 19) % P][int(C[p + 19]) ^ 0x07] += 2
        newkey = np.array(key)
        for r, c in votes.items():
            v, k = c.most_common(1)[0]
            newkey[r] = v
        if np.array_equal(newkey, key):
            break
        key = newkey
    # 终审：全量解析
    tile = np.tile(key, n // P + 1)[:n]
    dec = (C ^ tile).tobytes()
    pos = nrec = 0
    while pos + 27 <= len(dec):
        rl = struct.unpack_from("<H", dec, pos)[0]
        if rl < 28 or pos + rl > len(dec) or dec[pos + rl - 1] != 0:
            return None, nrec
        pos += rl
        nrec += 1
    if nrec != cnt or pos != len(dec):
        return None, nrec
    return key.tobytes(), nrec

def em_crack(np_, op, cn, nidx):
    fo, ro, co, eo, oidx = load_head_index(op)
    m = min(len(oidx), len(nidx))
    ks = np.frombuffer(bytes(a ^ b for a, b in zip(oidx[:m], nidx[:m])), np.uint8)
    bounds = old_bounds(oidx)
    C = np.frombuffer(nidx, np.uint8)
    cands = []
    for k in (16, 32, 64, 128, 256, 512):
        if k > len(bounds):
            break
        x = bounds[k - 1]
        for P in range(24, min(4096, x // 2) + 1):
            sc = column_consistency(ks[:x], P)
            if sc > 0.55:
                cands.append((sc, P, x))
    cands.sort(reverse=True)
    seen = set()
    for sc, P, x in cands[:60]:
        if P in seen:
            continue
        seen.add(P)
        key0 = column_mode(ks[:x], P)
        key, nrec = em_refine(C, cn, key0)
        if key is not None:
            return P, key, f"sc={sc:.2f}"
    return None, None, None

if __name__ == "__main__":
    keys = json.load(open(r"G:\pojie\ai\JiuYinUnpackTool\analysis\keys.json", encoding="utf-8"))
    for rel in ["res\\lua.package", "res\\lua64.package", "res\\map_ini.package", "res\\text.package"]:
        np_ = os.path.join(NEW_ROOT, rel)
        op = os.path.join(OLD_ROOT, rel)
        flag, rsv, cn, en, nidx = load_head_index(np_)
        P, key, note = em_crack(np_, op, cn, nidx)
        if key:
            keys[rel] = dict(rsv=rsv, P=P, key=key.hex())
            print(f"{rel}: P={P} {note} -> OK")
        else:
            print(f"{rel}: FAIL")
    with open(r"G:\pojie\ai\JiuYinUnpackTool\analysis\keys.json", "w", encoding="utf-8") as f:
        json.dump(keys, f, indent=1)
    print(f"\n累计 {len(keys)} 密钥")
