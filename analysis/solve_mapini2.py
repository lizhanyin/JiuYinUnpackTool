# -*- coding: utf-8 -*-
"""map_ini 终版：新旧 record0 名字相同的假设 + 60 字节 crib + 链式走。"""
import struct, collections, json
import numpy as np

NEW = r"F:\Game\Online\9yin\9yin\res\map_ini.package"
OLD = r"F:\Game\Online\9yin\20230423\9yin\res\map_ini.package"

def load_head_index(path):
    with open(path, "rb") as f:
        head = f.read(0x13)
        rsv, = struct.unpack_from("<H", head, 8)
        cnt, = struct.unpack_from("<I", head, 0x0A)
        idxend, = struct.unpack_from("<I", head, 0x0E)
        f.seek(0x13)
        return rsv, cnt, idxend, f.read(idxend - 0x13)

rn, cn, en, nidx = load_head_index(NEW)
ro, co, eo, oidx = load_head_index(OLD)
rl0_old = struct.unpack_from("<H", oidx, 0)[0]
name0 = oidx[27:rl0_old - 1]          # 60 字节全名
C = np.frombuffer(nidx, np.uint8)
n = len(C)
MIN_RL = 40

def chain(P, namelen0, verbose=False):
    K = {}
    def put(r, v):
        r %= P
        if r in K and K[r] != v:
            return False
        K[r] = v
        return True
    # crib：record0 全名 + 结构零 + 0x07 + rl0
    rl0 = 28 + namelen0
    if not (put(0, int(C[0]) ^ (rl0 & 0xFF)) and put(1, int(C[1]) ^ (rl0 >> 8))):
        return None, "len0 crib 冲突"
    for j in (6, 7, 8, 9, 25, 26):
        put(j, int(C[j]))
    put(19, int(C[19]) ^ 0x07)
    for j, ch in enumerate(name0[:namelen0]):
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
            if not (MIN_RL <= rl <= 8192) or p + rl > n or not name_ok(p, rl) or not next_ok(p + rl):
                return None, f"len 非法 @0x{p:x} rl={rl} (hops={hops} known={len(K)}/{P})"
        else:
            surv = []
            for cand in range(MIN_RL, min(8193, n - p)):
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
        return None, f"链走完但仅 {len(K)}/{P}"
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

print(f"map_ini cnt={cn} 旧rec0名(60B)={name0[:36]!r}...")
for P in (74, 148, 296, 592):
    key, msg = chain(P, len(name0))
    print(f"P={P}: {msg}")
    if key:
        print("KEY:", key.hex())
        tile = np.tile(np.frombuffer(key, np.uint8), n // P + 1)[:n]
        dec = (C ^ tile).tobytes()
        pos, recs = 0, []
        while pos + 27 <= len(dec):
            rl = struct.unpack_from("<H", dec, pos)[0]
            recs.append(dec[pos:pos + rl]); pos += rl
        def show(rec):
            off = struct.unpack_from("<Q", rec, 2)[0]
            raw, comp = struct.unpack_from("<II", rec, 10)
            return f"off=0x{off:08x} raw={raw:8d} comp={comp:7d} {rec[27:-1].decode('gbk','replace')}"
        for r in recs[:4]:
            print("  ", show(r))
        print("   ...")
        for r in recs[-2:]:
            print("  ", show(r))
        keys = json.load(open(r"G:\pojie\ai\JiuYinUnpackTool\analysis\keys_norm.json"))
        keys[f"{rn:04x}"] = key.hex()
        json.dump(keys, open(r"G:\pojie\ai\JiuYinUnpackTool\analysis\keys_norm.json", "w"), indent=1)
        print(f"\n密钥 0x{rn:04x} 已存 keys_norm.json（现 {len(keys)} 个）—— 待验证后同步 jiuyin-keys.txt")
        break
