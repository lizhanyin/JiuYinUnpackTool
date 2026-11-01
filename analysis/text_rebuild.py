# -*- coding: utf-8 -*-
"""text 重建：用「已验证前缀记录」的精确约束整体重建 K，迭代直到全通。"""
import struct, collections, json
import numpy as np
import importlib.util

# 复用 text_final 的求解与解析函数
spec = importlib.util.spec_from_file_location("tf", r"G:\pojie\ai\JiuYinUnpackTool\analysis\text_final.py")

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

# 初始 K（crib）
K = {}
rl0 = 28 + len(name0)
K[0] = int(C[0]) ^ (rl0 & 0xFF)
K[1] = int(C[1]) ^ (rl0 >> 8)
for j in (6, 7, 8, 9, 25, 26):
    K[j % P] = int(C[j])
K[19] = int(C[19]) ^ 0x07
for j, ch in enumerate(name0):
    K[(27 + j) % P] = int(C[27 + j]) ^ ch

def chain_positions(K):
    """从 0 链走，返回已验证记录 [(pos, rl)] 直到断点。"""
    key = None
    pos, recs = 0, []
    while pos + 27 <= n:
        r0, r1 = pos % P, (pos + 1) % P
        if r0 in K and r1 in K:
            rl = (int(C[pos]) ^ K[r0]) | ((int(C[pos+1]) ^ K[r1]) << 8)
            if not (28 <= rl <= 8192) or pos + rl > n:
                break
            q = pos + rl - 1
            if q % P in K and int(C[q]) ^ K[q % P] != 0:
                break
            # 下一记录结构校验（已知残差处）
            bad = False
            for o in (6, 7, 8, 9, 25, 26):
                rr = (pos + rl + o) % P
                if pos + rl + o < n and rr in K and int(C[pos + rl + o]) ^ K[rr] != 0:
                    bad = True; break
            if bad:
                break
        else:
            break
        recs.append((pos, rl))
        pos += rl
    return recs

def rebuild(recs):
    """从已验证记录重建全部残差（多数票）。"""
    votes = collections.defaultdict(collections.Counter)
    for pos, rl in recs:
        for o in (6, 7, 8, 9, 25, 26):
            votes[(pos + o) % P][int(C[pos + o])] += 2
        votes[(pos + 19) % P][int(C[pos + 19]) ^ 0x07] += 2
        votes[(pos + rl - 1) % P][int(C[pos + rl - 1])] += 2
        votes[pos % P][int(C[pos]) ^ (rl & 0xFF)] += 3
        votes[(pos + 1) % P][int(C[pos + 1]) ^ ((rl >> 8) & 0xFF)] += 3
    K2 = {}
    for r in range(P):
        if r in votes:
            t = votes[r].most_common(2)
            if len(t) == 1 or t[0][1] >= 2 * t[1][1]:
                K2[r] = t[0][0]
    # crib 残差强制（绝对可信）
    for r, v in K.items():
        K2[r] = v
    return K2

def full_verify(K2):
    if len(K2) < P:
        return False, 0
    key = bytes(K2.get(r, 0) for r in range(P))
    tile = np.tile(np.frombuffer(key, np.uint8), n // P + 1)[:n]
    dec = (C ^ tile).tobytes()
    pos, nrec = 0, 0
    while pos + 27 <= n:
        rl = struct.unpack_from("<H", dec, pos)[0]
        if rl < 28 or pos + rl > n or dec[pos + rl - 1] != 0:
            return False, nrec
        pos += rl; nrec += 1
    return (nrec == cn and pos == n), nrec

K = rebuild(chain_positions(K)) if len(K) == P else dict(K)
for it in range(15):
    recs = chain_positions(K)
    ok, nrec = full_verify(K)
    print(f"iter {it}: 已验证 {len(recs)} 条, known={len(K)}/{P}, 全通={ok}")
    if ok:
        break
    K2 = rebuild(recs)
    if K2 == K or len(K2) <= len(K):
        # 尝试放宽重建（取众数不限比例）
        votes = collections.defaultdict(collections.Counter)
        for pos, rl in recs:
            for o in (6, 7, 8, 9, 25, 26):
                votes[(pos + o) % P][int(C[pos + o])] += 2
            votes[(pos + 19) % P][int(C[pos + 19]) ^ 0x07] += 2
            votes[(pos + rl - 1) % P][int(C[pos + rl - 1])] += 2
            votes[pos % P][int(C[pos]) ^ (rl & 0xFF)] += 3
            votes[(pos + 1) % P][int(C[pos + 1]) ^ ((rl >> 8) & 0xFF)] += 3
        K2 = {r: c.most_common(1)[0][0] for r, c in votes.items()}
        for r, v in K.items():
            K2[r] = v
    K = K2

ok, nrec = full_verify(K)
if ok:
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
    print(f"\n仍未全通: known={len(K)}/{P}")
