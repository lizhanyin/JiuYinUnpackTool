# -*- coding: utf-8 -*-
"""text 高效迭代求解：低门槛投票（≥2 票且 ≥1.5 倍次票）+ 前缀和幸存者筛选 + 链式收尾。"""
import struct, collections, json
import numpy as np

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
old_recs = parse_plain(oidx)
name0 = old_recs[0][2]
C = np.frombuffer(nidx, np.uint8)
n = len(C)

# 初始 K：record0 全名 crib + 结构
K = {}
rl0 = 28 + len(name0)
K[0] = int(C[0]) ^ (rl0 & 0xFF)
K[1] = int(C[1]) ^ (rl0 >> 8)
for j in (6, 7, 8, 9, 25, 26):
    K[j % P] = int(C[j])
K[19] = int(C[19]) ^ 0x07
for j, ch in enumerate(name0):
    K[(27 + j) % P] = int(C[27 + j]) ^ ch
votes = collections.defaultdict(collections.Counter)
for r, v in K.items():
    votes[r][v] += 9

def karr():
    kv = np.full(P, -1, np.int32)
    for r, v in K.items():
        kv[r] = v
    return kv

def solid(min_votes=2, ratio=1.5):
    changed = False
    for r, c in votes.items():
        if r in K:
            continue
        t = c.most_common(2)
        if t and t[0][1] >= min_votes and (len(t) == 1 or t[0][1] >= ratio * t[1][1]):
            K[r] = t[0][0]
            changed = True
    return changed

def detect_and_vote():
    kv = karr()
    known = kv >= 0
    det = np.zeros(P, bool)
    for c in range(P):
        if known[(c+6)%P] and known[(c+7)%P] and known[(c+8)%P] and known[(c+9)%P]:
            det[c] = True
    if not det.any():
        return 0
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
    MONTHS = np.zeros(256, bool); MONTHS[1:13] = True
    DAYS = np.zeros(256, bool); DAYS[1:32] = True
    HRS = np.zeros(256, bool); HRS[:24] = True
    MNS = np.zeros(256, bool); MNS[:60] = True
    for o, tbl in ((20, MONTHS), (21, DAYS), (22, HRS), (23, MNS), (24, MNS)):
        chk = known[(p + o) % P]
        if chk.any():
            v = D[p[chk] + o]
            ok = np.ones(len(p), bool)
            ok[chk] = tbl[v]
            p = p[ok]
    for pp in p.tolist():
        c = pp % P
        votes[(c+19) % P][int(C[pp+19]) ^ 0x07] += 2
        votes[(c+25) % P][int(C[pp+25])] += 1
        votes[(c+26) % P][int(C[pp+26])] += 1
    return len(p)

print(f"text: cnt={cn} 初始已知 {len(K)}/{P}")
for it in range(25):
    cnt_starts = detect_and_vote()
    before = len(K)
    solid()
    print(f"  iter {it}: starts={cnt_starts} known={len(K)}/{P}")
    if len(K) == P or not (len(K) > before or cnt_starts > 0):
        break

# 链式收尾（len 可读直读，不可读 NUL 搜索）
p, hops = 0, 0
while p + 27 <= n:
    r0, r1 = p % P, (p + 1) % P
    if r0 in K and r1 in K:
        rl = (int(C[p]) ^ K[r0]) | ((int(C[p+1]) ^ K[r1]) << 8)
        if not (28 <= rl <= 8192) or p + rl > n:
            print(f"链断 @0x{p:x} rl={rl}"); break
    else:
        surv = []
        kv = karr()
        for cand in range(28, min(8193, n - p)):
            q = p + cand - 1
            if q % P in K and (int(C[q]) ^ K[q % P]) != 0:
                continue
            ok = True
            for o in (6, 7, 8, 9):
                rr = (p + cand + o) % P
                if rr in K and (int(C[p + cand + o]) ^ K[rr]) != 0:
                    ok = False; break
            if ok:
                surv.append(cand)
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
            print(f"NUL 冲突 @0x{p:x}"); break
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
    print(f"验证: {nrec}/{cn} 消费 0x{pos2:x}/0x{n:x} -> {'OK' if okall and nrec == cn and pos2 == n else 'FAIL'}")
    if okall and nrec == cn and pos2 == n:
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
