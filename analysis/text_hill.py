# -*- coding: utf-8 -*-
"""text 爬山修复：宽松投票得全 254 残差（少数有毒），
以「从 record0 解析能推进的字节数」为目标，翻转可疑残差至次优票值。"""
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
name0 = parse_plain(oidx)[0][2]
C = np.frombuffer(nidx, np.uint8)
n = len(C)

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

def karr(K):
    kv = np.full(P, -1, np.int32)
    for r, v in K.items():
        kv[r] = v
    return kv

def detect_and_vote(K, votes):
    kv = karr(K)
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
    for pp in p.tolist():
        c = pp % P
        votes[(c+19) % P][int(C[pp+19]) ^ 0x07] += 2
        votes[(c+25) % P][int(C[pp+25])] += 1
        votes[(c+26) % P][int(C[pp+26])] += 1
    return len(p)

def solid(K, votes, min_votes=2, ratio=1.5):
    for r, c in votes.items():
        if r in K:
            continue
        t = c.most_common(2)
        if t and t[0][1] >= min_votes and (len(t) == 1 or t[0][1] >= ratio * t[1][1]):
            K[r] = t[0][0]

for it in range(25):
    s = detect_and_vote(K, votes)
    before = len(K)
    solid(K, votes)
    if len(K) == P:
        break
print(f"宽松解: known={len(K)}/{P}")

def parse_distance(K):
    """从 0 解析，返回 (消费字节数, 记录数, 是否完整)。"""
    if len(K) < P:
        return (0, 0, False)
    key = bytes(K.get(r, 0) for r in range(P))
    tile = np.tile(np.frombuffer(key, np.uint8), n // P + 1)[:n]
    dec = (C ^ tile).tobytes()
    pos, nrec = 0, 0
    while pos + 27 <= n:
        rl = struct.unpack_from("<H", dec, pos)[0]
        if rl < 28 or pos + rl > n or dec[pos + rl - 1] != 0:
            return (pos, nrec, False)
        pos += rl; nrec += 1
    return (pos, nrec, pos == n and nrec == cn)

d0, rec0, full0 = parse_distance(K)
print(f"初始解析距离: 0x{d0:x} ({rec0} 条), 完整={full0}")

# 可疑残差：票数接近者
suspects = []
for r in range(P):
    t = votes[r].most_common(3)
    if len(t) >= 2 and t[0][1] < 5 * t[1][1]:
        alts = [v for v, _ in t[1:3]]
        if alts:
            suspects.append((r, K.get(r), alts))
print(f"可疑残差 {len(suspects)} 个: {[s[0] for s in suspects][:20]}")

# 爬山
best = dict(K)
bd, br, bf = d0, rec0, full0
improved = True
round_ = 0
while improved and not bf:
    improved = False
    round_ += 1
    for r, cur, alts in suspects:
        for alt in alts:
            if best.get(r) == alt:
                continue
            K2 = dict(best)
            K2[r] = alt
            d, rc, f = parse_distance(K2)
            if f or d > bd:
                best, bd, br, bf = K2, d, rc, f
                improved = True
                print(f"  round {round_}: 残差 {r} {cur if cur is not None else '?'}->{alt}, 距离 0x{d:x} ({rc} 条) 完整={f}")
                if f:
                    break
        if bf:
            break
    if round_ > 30:
        break

print(f"\n最终: 0x{bd:x} ({br} 条), 完整={bf}")
if bf:
    key = bytes(best[r] for r in range(P))
    keys = json.load(open(r"G:\pojie\ai\JiuYinUnpackTool\analysis\keys_norm.json"))
    keys[f"{rsv:04x}"] = key.hex()
    json.dump(keys, open(r"G:\pojie\ai\JiuYinUnpackTool\analysis\keys_norm.json", "w"), indent=1)
    print(f"-> text 密钥 0x{rsv:04x} 已存！")
    tile = np.tile(np.frombuffer(key, np.uint8), n // P + 1)[:n]
    dec = (C ^ tile).tobytes()
    pos = 0
    for _ in range(4):
        rl = struct.unpack_from("<H", dec, pos)[0]
        off = struct.unpack_from("<Q", dec, pos + 2)[0]
        print(f"   off=0x{off:08x} {dec[pos+27:pos+rl-1].decode('gbk','replace')}")
        pos += rl
