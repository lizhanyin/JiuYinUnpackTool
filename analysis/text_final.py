# -*- coding: utf-8 -*-
"""text 终版：完整过滤的迭代求解 + 断点局部翻转修复。"""
import struct, collections, json
import numpy as np

NEW = r"F:\Game\Online\9yin\9yin\res\text.package"
OLD = r"F:\Game\Online\9yin\20230423\9yin\res\text.package"
P = 254
MONTHS = np.zeros(256, bool); MONTHS[1:13] = True
DAYS = np.zeros(256, bool); DAYS[1:32] = True
HRS = np.zeros(256, bool); HRS[:24] = True
MNS = np.zeros(256, bool); MNS[:60] = True

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

def solid(K, votes, min_votes=2, ratio=1.5):
    for r, c in votes.items():
        if r in K:
            continue
        t = c.most_common(2)
        if t and t[0][1] >= min_votes and (len(t) == 1 or t[0][1] >= ratio * t[1][1]):
            K[r] = t[0][0]

for it in range(25):
    s = detect_and_vote(K, votes)
    solid(K, votes)
    if len(K) == P:
        break
print(f"宽松解: {len(K)}/{P}")

def parse_distance(K):
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

# 局部翻转修复循环
for repair_round in range(40):
    d, rc, full = parse_distance(K)
    print(f"round {repair_round}: 解析 0x{d:x} ({rc}/{cn}) 完整={full}")
    if full:
        break
    # 断点记录位置 p_break=d：涉及残差 = 该记录的字段
    pb = d
    involved = [(pb) % P, (pb+1) % P]
    # 该记录未知长度——把可能字段都纳入：+6..9,+19,+25,+26 与 NUL 的各种可能太宽，
    # 先只翻 len 两残差与「此前从未被投票约束」的残差
    improved = False
    # 1) len 残差
    for r in set(involved):
        cur = K.get(r)
        base_d = d
        for v in range(256):
            if v == cur:
                continue
            K2 = dict(K); K2[r] = v
            d2, rc2, f2 = parse_distance(K2)
            if f2 or (rc2, d2) > (rc, d):
                K, d, rc, full = K2, d2, rc2, f2
                improved = True
                print(f"   翻转残差 {r}: {cur}->{v}, 记录 {rc2} 距离 0x{d2:x} 完整={f2}")
                if full or f2:
                    break
        if full:
            break
    if full:
        break
    if not improved:
        # 2) 翻可疑票残差
        for r in range(P):
            t = votes[r].most_common(2)
            if len(t) < 2 or t[0][1] >= 5 * t[1][1]:
                continue
            for v, _ in t:
                if K.get(r) == v:
                    continue
                K2 = dict(K); K2[r] = v
                d2, rc2, f2 = parse_distance(K2)
                if f2 or (rc2, d2) > (rc, d):
                    K, d, rc, full = K2, d2, rc2, f2
                    print(f"   翻可疑残差 {r}: ->{v}, 记录 {rc2} 距离 0x{d2:x} 完整={f2}")
                    improved = True
                    if full:
                        break
            if full:
                break
    if full:
        break
    if not improved:
        print("无法继续修复")
        break

d, rc, full = parse_distance(K)
if full:
    key = bytes(K[r] for r in range(P))
    keys = json.load(open(r"G:\pojie\ai\JiuYinUnpackTool\analysis\keys_norm.json"))
    keys[f"{rsv:04x}"] = key.hex()
    json.dump(keys, open(r"G:\pojie\ai\JiuYinUnpackTool\analysis\keys_norm.json", "w"), indent=1)
    print(f"\n-> text 密钥 0x{rsv:04x} 已存！")
    tile = np.tile(np.frombuffer(key, np.uint8), n // P + 1)[:n]
    dec = (C ^ tile).tobytes()
    pos = 0
    for _ in range(4):
        rl = struct.unpack_from("<H", dec, pos)[0]
        off = struct.unpack_from("<Q", dec, pos + 2)[0]
        print(f"   off=0x{off:08x} {dec[pos+27:pos+rl-1].decode('gbk','replace')}")
        pos += rl
else:
    print(f"\n最终仍未完整: 0x{d:x} ({rc}/{cn})")
