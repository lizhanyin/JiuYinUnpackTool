# -*- coding: utf-8 -*-
"""text 合并终版：宽松迭代(带全部过滤) -> 链走验证前缀 -> 前缀约束重建 -> 循环。"""
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

K0 = {}
rl0 = 28 + len(name0)
K0[0] = int(C[0]) ^ (rl0 & 0xFF)
K0[1] = int(C[1]) ^ (rl0 >> 8)
for j in (6, 7, 8, 9, 25, 26):
    K0[j % P] = int(C[j])
K0[19] = int(C[19]) ^ 0x07
for j, ch in enumerate(name0):
    K0[(27 + j) % P] = int(C[27 + j]) ^ ch

def loose_fill(K):
    K = dict(K)
    votes = collections.defaultdict(collections.Counter)
    for r, v in K.items():
        votes[r][v] += 9
    def karr():
        kv = np.full(P, -1, np.int32)
        for r, v in K.items():
            kv[r] = v
        return kv
    for it in range(25):
        kv = karr()
        known = kv >= 0
        det = np.zeros(P, bool)
        for c in range(P):
            if known[(c+6)%P] and known[(c+7)%P] and known[(c+8)%P] and known[(c+9)%P]:
                det[c] = True
        if not det.any():
            break
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
        before = len(K)
        for r, cc in votes.items():
            if r in K:
                continue
            t = cc.most_common(2)
            if t and t[0][1] >= 2 and (len(t) == 1 or t[0][1] >= 1.5 * t[1][1]):
                K[r] = t[0][0]
        if len(K) == P or len(K) == before:
            break
    return K

def chain_positions(K):
    pos, recs = 0, []
    if len(K) < P:
        return recs
    while pos + 27 <= n:
        r0, r1 = pos % P, (pos + 1) % P
        rl = (int(C[pos]) ^ K[r0]) | ((int(C[pos+1]) ^ K[r1]) << 8)
        if not (28 <= rl <= 8192) or pos + rl > n:
            break
        q = pos + rl - 1
        if int(C[q]) ^ K[q % P] != 0:
            break
        bad = False
        for o in (6, 7, 8, 9, 25, 26):
            if pos + rl + o < n and int(C[pos + rl + o]) ^ K[(pos + rl + o) % P] != 0:
                bad = True; break
        if bad:
            break
        recs.append((pos, rl))
        pos += rl
    return recs

def rebuild(recs):
    votes = collections.defaultdict(collections.Counter)
    for pos, rl in recs:
        for o in (6, 7, 8, 9, 25, 26):
            votes[(pos + o) % P][int(C[pos + o])] += 2
        votes[(pos + 19) % P][int(C[pos + 19]) ^ 0x07] += 2
        votes[(pos + rl - 1) % P][int(C[pos + rl - 1])] += 2
        votes[pos % P][int(C[pos]) ^ (rl & 0xFF)] += 3
        votes[(pos + 1) % P][int(C[pos + 1]) ^ ((rl >> 8) & 0xFF)] += 3
    K2 = dict(K0)  # crib 绝对可信
    for r, c in votes.items():
        if r in K0:
            continue
        t = c.most_common(2)
        if len(t) == 1 or t[0][1] >= 2 * t[1][1]:
            K2[r] = t[0][0]
        else:
            K2[r] = t[0][0]  # 有分歧也先取众数（后续验证兜底）
    return K2

def full_verify(K):
    if len(K) < P:
        return False, 0, 0
    key = bytes(K.get(r, 0) for r in range(P))
    tile = np.tile(np.frombuffer(key, np.uint8), n // P + 1)[:n]
    dec = (C ^ tile).tobytes()
    pos, nrec = 0, 0
    while pos + 27 <= n:
        rl = struct.unpack_from("<H", dec, pos)[0]
        if rl < 28 or pos + rl > n or dec[pos + rl - 1] != 0:
            return False, nrec, pos
        pos += rl; nrec += 1
    return (nrec == cn and pos == n), nrec, pos

K = loose_fill(K0)
print(f"宽松填充: {len(K)}/{P}")
for it in range(20):
    recs = chain_positions(K)
    ok, nrec, d = full_verify(K)
    print(f"iter {it}: 链验证 {len(recs)} 条 -> 重建...")
    if ok:
        break
    if len(recs) < 2:
        K = loose_fill(K)  # 重建失败重来
        break_ok = False
        break
    K2 = rebuild(recs)
    # 重建后若完整残差不足，并入宽松值
    for r in range(P):
        if r not in K2 and r in K:
            K2[r] = K[r]
    if K2 == K:
        break
    K = K2

ok, nrec, d = full_verify(K)
print(f"最终: 完整={ok} ({nrec}/{cn}, 0x{d:x})")
if ok:
    key = bytes(K[r] for r in range(P))
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
