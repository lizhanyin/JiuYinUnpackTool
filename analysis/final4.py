# -*- coding: utf-8 -*-
"""最终攻坚：
lua  = 与 lua64 逐条配对（名字前缀 lua64\ -> lua\，长度-1），失配处回退字典搜索
text = 字典 + DFS 前瞻（幸存者必须在下一跳仍有字典幸存）"""
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

def parse_plain(idx):
    recs, pos = [], 0
    while pos + 27 <= len(idx):
        rl = struct.unpack_from("<H", idx, pos)[0]
        if rl < 28 or pos + rl > len(idx):
            break
        recs.append((pos, rl, idx[pos + 27:pos + rl - 1]))
        pos += rl
    return recs

def decrypt_idx(nidx, key):
    P = len(key)
    C = np.frombuffer(nidx, np.uint8)
    tile = np.tile(np.frombuffer(key, np.uint8), len(C) // P + 1)[:len(C)]
    return (C ^ tile).tobytes()

class Walker:
    def __init__(self, nidx, P, name0):
        self.C = np.frombuffer(nidx, np.uint8)
        self.n = len(self.C)
        self.P = P
        self.K = {}
        rl0 = 28 + len(name0)
        assert self.put(0, int(self.C[0]) ^ (rl0 & 0xFF))
        assert self.put(1, int(self.C[1]) ^ (rl0 >> 8))
        for j in (6, 7, 8, 9, 25, 26):
            self.put(j, int(self.C[j]))
        self.put(19, int(self.C[19]) ^ 0x07)
        for j, ch in enumerate(name0):
            assert self.put(27 + j, int(self.C[27 + j]) ^ ch), f"crib 冲突 @{j}"
        self.votes = collections.defaultdict(collections.Counter)
        for r, v in list(self.K.items()):
            self.votes[r][v] += 9

    def put(self, r, v):
        r %= self.P
        if r in self.K and self.K[r] != v:
            return False
        self.K[r] = v
        return True

    def learn(self, r, v, w=2):
        r %= self.P
        self.votes[r][v] += w
        t = self.votes[r].most_common(2)
        if t and t[0][1] >= 3 and (len(t) == 1 or t[0][1] >= 3 * t[1][1]):
            self.K[r] = t[0][0]

    def pt(self, pos):
        if pos >= self.n:
            return None
        r = pos % self.P
        return int(self.C[pos]) ^ self.K[r] if r in self.K else None

    def check_name(self, p, nm):
        base = p + 27
        for j, ch in enumerate(nm):
            v = self.pt(base + j)
            if v is not None and v != ch:
                return False
        q = base + len(nm)
        if q >= self.n:
            return False
        v = self.pt(q)
        return v is None or v == 0

    def check_struct(self, p):
        """p 作为记录起点的结构校验（已知残差处）。"""
        if p + 27 > self.n:
            return p >= self.n - 27  # 尾部容忍
        for o in (6, 7, 8, 9, 25, 26):
            v = self.pt(p + o)
            if v is not None and v != 0:
                return False
        v = self.pt(p + 19)
        if v is not None and v != 0x07:
            return False
        return True

    def learn_record(self, p, rl, nm=None):
        for o in (6, 7, 8, 9, 25, 26):
            self.learn(p + o, int(self.C[p + o]))
        self.learn(p + 19, int(self.C[p + 19]) ^ 0x07, w=2)
        if nm is not None:
            for j, ch in enumerate(nm):
                self.learn(p + 27 + j, int(self.C[p + 27 + j]) ^ ch, w=3)
            self.learn(p + 27 + len(nm), int(self.C[p + 27 + len(nm)]), w=2)  # NUL
        self.learn(p + rl - 1, int(self.C[p + rl - 1]), w=1)
        self.learn(p, int(self.C[p]) ^ (rl & 0xFF), w=2)
        self.learn(p + 1, int(self.C[p + 1]) ^ ((rl >> 8) & 0xFF), w=2)

# ============ lua：与 lua64 配对 ============
keys = json.load(open(r"G:\pojie\ai\JiuYinUnpackTool\analysis\keys_norm.json"))
rsvL, cnL, _, nidxL = load_head_index(NEW_ROOT + r"\res\lua.package")
_, _, _, nidx64 = load_head_index(NEW_ROOT + r"\res\lua64.package")
recs64 = parse_plain(decrypt_idx(nidx64, bytes.fromhex(keys["2696"])))
old_recsL = parse_plain(load_head_index(OLD_ROOT + r"\res\lua.package")[3])
dictL = {r[2] for r in old_recsL} | {r[2] for r in recs64}

def solve_lua(P):
    W = Walker(nidxL, P, b"lua\\readme.txt")
    n = W.n
    p = 42  # record0 长度
    i64 = 1
    by_len = collections.defaultdict(list)
    for nm in dictL:
        by_len[len(nm)].append(nm)
    hops = 1
    pair_ok = pair_fallback = 0
    while p + 27 <= n:
        placed = False
        # 尝试与 lua64 记录配对（前缀替换）
        for k in (0, -1, 1, -2, 2):  # 允许少量错位（各自独占条目）
            ii = i64 + k
            if not (0 <= ii < len(recs64)):
                continue
            nm64 = recs64[ii][2]
            nm = b"lua\\" + nm64[len(b"lua64\\"):] if nm64.startswith(b"lua64\\") else None
            if nm is None:
                continue
            rl = 28 + len(nm)
            if W.check_name(p, nm) and W.check_struct(p + rl):
                W.learn_record(p, rl, nm)
                p += rl
                i64 = ii + 1
                placed = True
                pair_ok += 1
                break
        if placed:
            hops += 1
            continue
        # 回退：字典搜索（含 DFS 前瞻 1 层）
        survivors = []
        for nm_len, nms in by_len.items():
            cand = 28 + nm_len
            if cand < 30 or p + cand > n:
                continue
            for nm in nms:
                if W.check_name(p, nm) and W.check_struct(p + cand):
                    # 前瞻：下一跳也须有字典幸存
                    fwd = False
                    for nm_len2, nms2 in by_len.items():
                        c2 = 28 + nm_len2
                        if c2 < 30 or p + cand + c2 > n:
                            continue
                        for nm2 in nms2:
                            if W.check_name(p + cand, nm2) and W.check_struct(p + cand + c2):
                                fwd = True
                                break
                        if fwd:
                            break
                    if fwd:
                        survivors.append((cand, nm))
                    break  # 每长度只取第一个匹配
        if len(survivors) == 1:
            rl, nm = survivors[0]
            W.learn_record(p, rl, nm)
            p += rl
            pair_fallback += 1
            hops += 1
        else:
            return None, f"卡 @0x{p:x} hops={hops} 配对{pair_ok} 回退{pair_fallback} known={len(W.K)}/{P} 幸存{len(survivors)}"
    if len(W.K) < P:
        return None, f"仅 {len(W.K)}/{P}"
    key = bytes(W.K[r] for r in range(P))
    tile = np.tile(np.frombuffer(key, np.uint8), n // P + 1)[:n]
    dec = (W.C ^ tile).tobytes()
    pos2 = nrec = 0
    while pos2 + 27 <= len(dec):
        rl = struct.unpack_from("<H", dec, pos2)[0]
        if rl < 28 or pos2 + rl > len(dec) or dec[pos2 + rl - 1] != 0:
            return None, f"验证断 @0x{pos2:x}"
        pos2 += rl
        nrec += 1
    if nrec != cnL or pos2 != len(dec):
        return None, f"数 {nrec}/{cnL}"
    return key, f"OK {hops} 跳（配对 {pair_ok}，字典 {pair_fallback}）"

print("lua:")
for P in (252, 126, 504):
    key, msg = solve_lua(P)
    print(f"  P={P}: {msg}")
    if key:
        keys[f"{rsvL:04x}"] = key.hex()
        json.dump(keys, open(r"G:\pojie\ai\JiuYinUnpackTool\analysis\keys_norm.json", "w"), indent=1)
        print(f"  -> lua 密钥 0x{rsvL:04x} 已存")
        break

# ============ text：字典 + DFS ============
rsvT, cnT, _, nidxT = load_head_index(NEW_ROOT + r"\res\text.package")
old_recsT = parse_plain(load_head_index(OLD_ROOT + r"\res\text.package")[3])
dictT = sorted({r[2] for r in old_recsT})
name0T = old_recsT[0][2]

def solve_text(P):
    W = Walker(nidxT, P, name0T)
    n = W.n
    p = 28 + len(name0T)
    by_len = collections.defaultdict(list)
    for nm in dictT:
        by_len[len(nm)].append(nm)
    hops = 1
    while p + 27 <= n:
        survivors = []
        for nm_len, nms in by_len.items():
            cand = 28 + nm_len
            if cand < 30 or p + cand > n:
                continue
            for nm in nms:
                if W.check_name(p, nm) and W.check_struct(p + cand):
                    survivors.append((cand, nm))
                    break
        if len(survivors) == 1:
            rl, nm = survivors[0]
            W.learn_record(p, rl, nm)
            p += rl
            hops += 1
            continue
        # 结构回退：字典无命中（新条目）——纯结构搜索
        if len(survivors) == 0:
            structural = []
            for cand in range(30, min(8193, n - p)):
                okc = True
                q = p + cand - 1
                v = W.pt(q)
                if v is not None and v != 0:
                    continue
                for j in range(27, cand - 1):
                    v = W.pt(p + j)
                    if v is not None and not (0x20 <= v < 0x7f or v >= 0x80):
                        okc = False
                        break
                if not okc:
                    continue
                if not W.check_struct(p + cand):
                    continue
                structural.append(cand)
                if len(structural) > 3:
                    break
            if len(structural) == 1:
                rl = structural[0]
                W.learn_record(p, rl)
                p += rl
                hops += 1
                continue
            return None, f"结构回退失败 @0x{p:x} hops={hops} known={len(W.K)}/{P} 结构幸存{structural[:4]}"
        # 歧义 -> 前瞻 2 层 DFS
        best = None
        for cand, nm in survivors[:24]:
            W2 = None
            # 简化前瞻：下一跳唯一字典幸存者
            p2 = p + cand
            sub = []
            for nm_len2, nms2 in by_len.items():
                c2 = 28 + nm_len2
                if c2 < 30 or p2 + c2 > n:
                    continue
                for nm2 in nms2:
                    # 用当前 W 校验（未学习 cand 的 crib——保守）
                    if W.check_name(p2, nm2) and W.check_struct(p2 + c2):
                        sub.append((c2, nm2))
                        break
            if len(sub) == 1 and best is None:
                best = (cand, nm)
        if best is None and len(survivors) > 1:
            return None, f"歧义 @0x{p:x} hops={hops} known={len(W.K)}/{P} 幸存{len(survivors)}"
        if best is None:
            return None, f"无幸存 @0x{p:x} hops={hops} known={len(W.K)}/{P}"
        rl, nm = best
        W.learn_record(p, rl, nm)
        p += rl
        hops += 1
    if len(W.K) < P:
        return None, f"仅 {len(W.K)}/{P}"
    key = bytes(W.K[r] for r in range(P))
    tile = np.tile(np.frombuffer(key, np.uint8), n // P + 1)[:n]
    dec = (W.C ^ tile).tobytes()
    pos2 = nrec = 0
    while pos2 + 27 <= len(dec):
        rl = struct.unpack_from("<H", dec, pos2)[0]
        if rl < 28 or pos2 + rl > len(dec) or dec[pos2 + rl - 1] != 0:
            return None, f"验证断 @0x{pos2:x}"
        pos2 += rl
        nrec += 1
    if nrec != cnT or pos2 != len(dec):
        return None, f"数 {nrec}/{cnT}"
    return key, f"OK {hops} 跳"

print("\ntext:")
for P in (254, 127, 508):
    key, msg = solve_text(P)
    print(f"  P={P}: {msg}")
    if key:
        keys[f"{rsvT:04x}"] = key.hex()
        json.dump(keys, open(r"G:\pojie\ai\JiuYinUnpackTool\analysis\keys_norm.json", "w"), indent=1)
        print(f"  -> text 密钥 0x{rsvT:04x} 已存")
        break

print(f"\nkeys_norm.json: {len(keys)} 个密钥")
