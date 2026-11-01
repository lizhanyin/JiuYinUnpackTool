# -*- coding: utf-8 -*-
"""批量破解 v2：逐记录递增前缀。
用旧包前 k 条记录做已知明文，k 从小到大试；每个 k 自相关找周期，
rate>0.95 即提密钥并全量解析验证；分叉点之后的 k 自动失效（rate 掉），
但较小的 k 已覆盖。"""
import struct, os, json
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
    b = []
    pos = 0
    while pos + 27 <= len(oidx):
        rl = struct.unpack_from("<H", oidx, pos)[0]
        b.append(pos + rl)
        pos += rl
    return b

def best_period(a, pmin=16, pmax=4096):
    n = len(a)
    if n < 400:
        return 0.0, 0
    res = []
    for P in range(pmin, min(pmax, n // 2) + 1):
        m = n - P
        eq = np.count_nonzero(a[:m] == a[P:])
        res.append((eq / m, P))
    res.sort(reverse=True)
    return res[0]

def column_mode_key(a, P):
    usable = (len(a) // P) * P
    if usable == 0:
        return None
    m = a[:usable].reshape(-1, P)
    key = np.zeros(P, np.uint8)
    for c in range(P):
        vals, counts = np.unique(m[:, c], return_counts=True)
        key[c] = vals[np.argmax(counts)]
    return key.tobytes()

def decrypt(idx, key):
    L = len(key)
    tile = np.tile(np.frombuffer(key, np.uint8), len(idx) // L + 1)[:len(idx)]
    return (np.frombuffer(idx, np.uint8) ^ tile).tobytes()

def parse(dec, cnt):
    pos, nrec = 0, 0
    while pos + 27 <= len(dec):
        rl = struct.unpack_from("<H", dec, pos)[0]
        if rl < 28 or pos + rl > len(dec):
            return nrec, f"@0x{pos:x} rl={rl}"
        if dec[pos + rl - 1] != 0:
            return nrec, f"rec{nrec} 缺NUL @0x{pos:x}"
        pos += rl
        nrec += 1
    return nrec, (None if (nrec == cnt and pos == len(dec)) else f"数 {nrec}/{cnt} 消费 0x{pos:x}/0x{len(dec):x}")

def crack(np_, op, cn, nidx):
    fo, ro, co, eo, oidx = load_head_index(op)
    m = min(len(oidx), len(nidx))
    ks = np.frombuffer(bytes(a ^ b for a, b in zip(oidx[:m], nidx[:m])), np.uint8)
    bounds = old_bounds(oidx)
    # 候选 k：对数间隔
    tried = set()
    for k in sorted(set([1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, len(bounds)])):
        if k > len(bounds) or k in tried:
            continue
        tried.add(k)
        x = bounds[k - 1]
        rate, P = best_period(ks[:x])
        if rate < 0.95 or P == 0:
            continue
        key = column_mode_key(ks[:x], P)
        nrec, err = parse(decrypt(nidx, key), cn)
        if err is None:
            return P, key, f"k={k}"
        # 试试周期的因子（真周期可能是检测到的因子/倍数）
        for P2 in [P // g for g in (2, 3, 4) if P % g == 0]:
            if P2 < 16:
                continue
            key2 = column_mode_key(ks[:x], P2)
            nrec2, err2 = parse(decrypt(nidx, key2), cn)
            if err2 is None:
                return P2, key2, f"k={k}(÷)"
    return None, None, None

pkgs = []
for dirpath, _, files in os.walk(NEW_ROOT):
    for f in files:
        if f.lower().endswith(".package"):
            rel = os.path.relpath(os.path.join(dirpath, f), NEW_ROOT)
            op = os.path.join(OLD_ROOT, rel)
            if os.path.exists(op):
                fn, rn, cn, en, nidx = load_head_index(os.path.join(dirpath, f))
                if fn == 4:
                    pkgs.append((rel, op, os.path.join(dirpath, f), cn, nidx, rn))

ok = {}
fail = []
for rel, op, np_, cn, nidx, rn in sorted(pkgs):
    P, key, note = crack(np_, op, cn, nidx)
    if key:
        print(f"{rel:<30} rsv=0x{rn:04x} P={P:<5} {note} -> OK")
        ok[rel] = dict(rsv=rn, P=P, key=key.hex())
    else:
        print(f"{rel:<30} rsv=0x{rn:04x} -> FAIL")
        fail.append(rel)

print(f"\n成功 {len(ok)}/{len(pkgs)}")
with open(r"G:\pojie\ai\JiuYinUnpackTool\analysis\keys.json", "w") as f:
    json.dump(ok, f, indent=1)
print("密钥表: analysis/keys.json")
