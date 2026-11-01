# -*- coding: utf-8 -*-
"""lua / text 链式求解（复用 map_ini 成功方案：全名 crib + rl0 直推 + 链走 + 终审）。"""
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
    return oidx[27:rl - 1]

def chain_solve(nidx, cn, name0, P, min_rl):
    C = np.frombuffer(nidx, np.uint8)
    n = len(C)
    K = {}
    def put(r, v):
        r %= P
        if r in K and K[r] != v:
            return False
        K[r] = v
        return True
    rl0 = 28 + len(name0)
    if not (put(0, int(C[0]) ^ (rl0 & 0xFF)) and put(1, int(C[1]) ^ (rl0 >> 8))):
        return None, "len0 冲突"
    for j in (6, 7, 8, 9, 25, 26):
        put(j, int(C[j]))
    put(19, int(C[19]) ^ 0x07)
    for j, ch in enumerate(name0):
        if not put(27 + j, int(C[27 + j]) ^ ch):
            return None, f"名字 crib 冲突 @{j}"
    votes = collections.defaultdict(collections.Counter)
    def learn(r, v, w=2):
        r %= P
        votes[r][v] += w
        t = votes[r].most_common(2)
        if t and t[0][1] >= 3 and (len(t) == 1 or t[0][1] >= 3 * t[1][1]):
            K[r] = t[0][0]
    for r, v in list(K.items()):
        votes[r][v] += 9

    def name_ok(p, rl):
        q = p + rl - 1
        if q >= n:
            return False
        rq = q % P
        if rq in K and (int(C[q]) ^ K[rq]) != 0:
            return False
        for j in range(27, rl - 1):
            r = (p + j) % P
            if r in K:
                pt = int(C[p + j]) ^ K[r]
                if not (0x20 <= pt < 0x7f or pt >= 0x80):
                    return False
        return True

    def next_ok(p1):
        if p1 + 27 > n:
            return True
        for o in range(6, 10):
            r = (p1 + o) % P
            if r in K and (int(C[p1 + o]) ^ K[r]) != 0:
                return False
        r19 = (p1 + 19) % P
        if r19 in K and (int(C[p1 + 19]) ^ K[r19]) != 0x07:
            return False
        return True

    p, hops = 0, 0
    while p + 27 <= n:
        r0, r1 = p % P, (p + 1) % P
        if r0 in K and r1 in K:
            rl = (int(C[p]) ^ K[r0]) | ((int(C[p + 1]) ^ K[r1]) << 8)
            if not (min_rl <= rl <= 8192) or p + rl > n or not name_ok(p, rl) or not next_ok(p + rl):
                return None, f"len 非法 @0x{p:x} rl={rl} (hops={hops} known={len(K)}/{P})"
        else:
            surv = []
            for cand in range(min_rl, min(8193, n - p)):
                if name_ok(p, cand) and next_ok(p + cand):
                    surv.append(cand)
                if len(surv) > 3:
                    break
            if len(surv) != 1:
                return None, f"rl 歧义 @0x{p:x}: {surv[:4]} (known={len(K)}/{P} hops={hops})"
            rl = surv[0]
            learn(r0, int(C[p]) ^ (rl & 0xFF))
            learn(r1, int(C[p + 1]) ^ ((rl >> 8) & 0xFF))
        for o in (6, 7, 8, 9, 25, 26):
            learn(p + o, int(C[p + o]))
        learn(p + 19, int(C[p + 19]) ^ 0x07, w=2)
        learn(p + rl - 1, int(C[p + rl - 1]), w=1)
        p += rl
        hops += 1
    if len(K) < P:
        return None, f"仅 {len(K)}/{P}"
    key = bytes(K[r] for r in range(P))
    tile = np.tile(np.frombuffer(key, np.uint8), n // P + 1)[:n]
    dec = (C ^ tile).tobytes()
    pos2 = nrec = 0
    while pos2 + 27 <= len(dec):
        rl = struct.unpack_from("<H", dec, pos2)[0]
        if rl < 28 or pos2 + rl > len(dec) or dec[pos2 + rl - 1] != 0:
            return None, f"验证断 @0x{pos2:x} ({nrec})"
        pos2 += rl
        nrec += 1
    if nrec != cn or pos2 != len(dec):
        return None, f"数 {nrec}/{cn}"
    return key, f"OK {hops} 跳"

def zlib_probe(path, key, cnt, k=60):
    rsv, cn, en, nidx = load_head_index(path)
    P = len(key)
    C = np.frombuffer(nidx, np.uint8)
    tile = np.tile(np.frombuffer(key, np.uint8), len(C) // P + 1)[:len(C)]
    dec = (C ^ tile).tobytes()
    recs, pos = [], 0
    while pos + 27 <= len(dec):
        rl = struct.unpack_from("<H", dec, pos)[0]
        recs.append(dec[pos:pos + rl]); pos += rl
    whole = open(path, "rb").read()
    ok = fail = 0
    for rec in recs[:k] + recs[-k:]:
        off = struct.unpack_from("<Q", rec, 2)[0]
        raw, comp = struct.unpack_from("<II", rec, 10)
        try:
            d = zlib.decompress(whole[off:off + comp])
            assert len(d) == raw
            ok += 1
        except Exception:
            fail += 1
    return len(recs), ok, fail, recs

keys = json.load(open(r"G:\pojie\ai\JiuYinUnpackTool\analysis\keys_norm.json"))

for rel, P_list, min_rl in (
    ("res\\lua.package", [252, 504, 126, 84, 63, 1008], 34),
    ("res\\text.package", [254, 508, 127, 1016], 40),
):
    nm = old_rec0(OLD_ROOT + "\\" + rel)
    rsv, cn, en, nidx = load_head_index(NEW_ROOT + "\\" + rel)
    print(f"\n{rel}: rsv=0x{rsv:04x} cnt={cn} crib={nm!r}")
    done = False
    for P in P_list:
        key, msg = chain_solve(nidx, cn, nm, P, min_rl)
        print(f"  P={P}: {msg}")
        if key:
            path = NEW_ROOT + "\\" + rel
            nrec, ok, fail, recs = zlib_probe(path, key, cn)
            print(f"  zlib 抽查: {ok} OK / {fail} FAIL（共 {nrec} 条）")
            if fail == 0:
                keys[f"{rsv:04x}"] = key.hex()
                json.dump(keys, open(r"G:\pojie\ai\JiuYinUnpackTool\analysis\keys_norm.json", "w"), indent=1)
                for rec in recs[:3]:
                    off = struct.unpack_from("<Q", rec, 2)[0]
                    print(f"    off=0x{off:08x} {rec[27:-1].decode('gbk','replace')}")
                print(f"  -> 密钥 0x{rsv:04x} 已存")
                done = True
            break
    if not done:
        print("  -> FAIL")

print(f"\nkeys_norm.json: {len(keys)} 个密钥")
