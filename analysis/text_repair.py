# -*- coding: utf-8 -*-
"""text 残差修复：从 record0 crib 出发，用检测起点的精确约束全票重建，
再链走 + 终审。对可疑（非全票）残差给出报告。"""
import struct, collections, json
import numpy as np
import importlib.util

NEW = r"F:\Game\Online\9yin\9yin\res\text.package"
OLD = r"F:\Game\Online\9yin\20230423\9yin\res\text.package"
P = 254

def load_head_index(path):
    with open(path, "rb") as f:
        head = f.read(0x13)
        rsv, = struct.unpack_from("<H", head, 8)
        cnt, = struct.unpack_from("<I", head, 0x0A)
        idxend, = struct.unpack_from("<I", head, 0x0E)
        f.seek(0x13)
        return rsv, cnt, idxend, f.read(idxend - 0x13)

def parse_plain(idx):
    recs, pos = [], 0
    while pos + 27 <= len(idx):
        rl = struct.unpack_from("<H", idx, pos)[0]
        recs.append((pos, rl, idx[pos + 27:pos + rl - 1]))
        pos += rl
    return recs

rsv, cn, en, nidx = load_head_index(NEW)
ro, co, eo, oidx = load_head_index(OLD)
name0 = parse_plain(oidx)[0][2]
C = np.frombuffer(nidx, np.uint8)
n = len(C)

# 初始 K（仅 crib，绝不掺投票毒）
K = {}
rl0 = 28 + len(name0)
K[0] = int(C[0]) ^ (rl0 & 0xFF)
K[1] = int(C[1]) ^ (rl0 >> 8)
for j in (6, 7, 8, 9, 25, 26):
    K[j % P] = int(C[j])
K[19] = int(C[19]) ^ 0x07
for j, ch in enumerate(name0):
    K[(27 + j) % P] = int(C[27 + j]) ^ ch

def karr():
    kv = np.full(P, -1, np.int32)
    for r, v in K.items():
        kv[r] = v
    return kv

def detect_starts():
    kv = karr()
    known = kv >= 0
    det = np.zeros(P, bool)
    for c in range(P):
        if known[(c+6)%P] and known[(c+7)%P] and known[(c+8)%P] and known[(c+9)%P]:
            det[c] = True
    if not det.any():
        return []
    tile = np.tile(np.where(known, kv, 0).astype(np.uint8), n // P + 1)[:n]
    D = C ^ tile
    p = np.arange(n - 27, dtype=np.int64)
    p = p[det[p % P]]
    p = p[(D[p+6] | D[p+7] | D[p+8] | D[p+9]) == 0]
    for o, want in ((19, 0x07), (25, 0), (26, 0)):
        chk = known[(p + o) % P]
        if chk.any():
            v = D[p[chk] + o]
            ok = np.ones(len(p), bool)
            ok[chk] = (v == want)
            p = p[ok]
    return p.tolist()

# 约束重建循环：检测起点 -> 每残差收集精确候选 -> 全票/多数确定 -> 扩张
for it in range(30):
    starts = detect_starts()
    cand = collections.defaultdict(collections.Counter)
    for p in starts:
        for o in (6, 7, 8, 9, 25, 26):
            cand[(p + o) % P][int(C[p + o])] += 1
        cand[(p + 19) % P][int(C[p + 19]) ^ 0x07] += 2
    before = len(K)
    for r in range(P):
        if r in K or r not in cand:
            continue
        t = cand[r].most_common(2)
        # 严格：全票或 ≥3 倍次票且 ≥5 票
        if t and t[0][1] >= 5 and (len(t) == 1 or t[0][1] >= 3 * t[1][1]):
            K[r] = t[0][0]
    print(f"iter {it}: starts={len(starts)} known={len(K)}/{P}")
    if len(K) == P or len(starts) == 0:
        break

# 链式收尾
p, hops, breaks = 0, 0, 0
while p + 27 <= n:
    r0, r1 = p % P, (p + 1) % P
    if r0 in K and r1 in K:
        rl = (int(C[p]) ^ K[r0]) | ((int(C[p+1]) ^ K[r1]) << 8)
        if not (28 <= rl <= 8192) or p + rl > n:
            print(f"链断 @0x{p:x} rl={rl}"); break
    else:
        surv = []
        for c2 in range(28, min(8193, n - p)):
            q = p + c2 - 1
            if q % P in K and (int(C[q]) ^ K[q % P]) != 0:
                continue
            ok = True
            for o in (6, 7, 8, 9):
                rr = (p + c2 + o) % P
                if rr in K and (int(C[p + c2 + o]) ^ K[rr]) != 0:
                    ok = False; break
            if ok:
                surv.append(c2)
            if len(surv) > 2:
                break
        if len(surv) != 1:
            print(f"歧义 @0x{p:x} {surv[:3]} known={len(K)}"); break
        rl = surv[0]
        K[r0] = int(C[p]) ^ (rl & 0xFF)
        K[r1] = int(C[p+1]) ^ (rl >> 8)
    q = p + rl - 1
    if q % P in K:
        if int(C[q]) ^ K[q % P] != 0:
            print(f"NUL 冲突 @0x{p:x} (residue {q%P})"); break
    else:
        K[q % P] = int(C[q])
    p += rl
    hops += 1
print(f"链走 {hops} 跳 -> 0x{p:x}/0x{n:x}, known={len(K)}/{P}")

if len(K) == P:
    key = bytes(K[r] for r in range(P))
    tile = np.tile(np.frombuffer(key, np.uint8), n // P + 1)[:n]
    dec = (C ^ tile).tobytes()
    pos2 = nrec = 0
    okall = True
    while pos2 + 27 <= len(dec):
        rl = struct.unpack_from("<H", dec, pos2)[0]
        if rl < 28 or pos2 + rl > len(dec) or dec[pos2 + rl - 1] != 0:
            okall = False; break
        pos2 += rl; nrec += 1
    good = okall and nrec == cn and pos2 == n
    print(f"验证: {nrec}/{cn} 消费 0x{pos2:x}/0x{n:x} -> {'OK' if good else 'FAIL'}")
    if good:
        keys = json.load(open(r"G:\pojie\ai\JiuYinUnpackTool\analysis\keys_norm.json"))
        keys[f"{rsv:04x}"] = key.hex()
        json.dump(keys, open(r"G:\pojie\ai\JiuYinUnpackTool\analysis\keys_norm.json", "w"), indent=1)
        print(f"-> text 密钥 0x{rsv:04x} 已存！")
        pos = 0
        for _ in range(4):
            rl = struct.unpack_from("<H", dec, pos)[0]
            off = struct.unpack_from("<Q", dec, pos + 2)[0]
            print(f"   off=0x{off:08x} {dec[pos+27:pos+rl-1].decode('gbk','replace')}")
            pos += rl
