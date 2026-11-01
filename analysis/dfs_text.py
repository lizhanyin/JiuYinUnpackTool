# -*- coding: utf-8 -*-
"""text 终极 DFS：链式走 + 字典排序 + 回溯。
每跳收集全部结构幸存者，按字典完全匹配优先排序，逐个分支深入；死路上溯。"""
import struct, collections, json, sys
import numpy as np

NEW = r"F:\Game\Online\9yin\9yin\res\text.package"
OLD = r"F:\Game\Online\9yin\20230423\9yin\res\text.package"

def load_head_index(path):
    with open(path, "rb") as f:
        head = f.read(0x13)
        rsv, = struct.unpack_from("<H", head, 8)
        cnt, = struct.unpack_from("<I", head, 0x0A)
        idxend, = struct.unpack_from("<I", head, 0x0E)
        f.seek(0x13)
        return rsv, cnt, idxend, f.read(idxend - 0x13)

def _unused():
    pass

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
dict_by_len = collections.defaultdict(list)
for _p, _r, nm in old_recs:
    dict_by_len[len(nm)].append(nm)

C = np.frombuffer(nidx, np.uint8)
n = len(C)

def make_K(P):
    K = {}
    rl0 = 28 + len(name0)
    K[0] = int(C[0]) ^ (rl0 & 0xFF)
    K[1 % P] = int(C[1]) ^ (rl0 >> 8)
    for j in (6, 7, 8, 9, 25, 26):
        K.setdefault(j % P, int(C[j]))
    K[19 % P] = int(C[19]) ^ 0x07
    for j, ch in enumerate(name0):
        K[(27 + j) % P] = int(C[27 + j]) ^ ch
    return K

def run(P, node_budget=30000):
    sys.setrecursionlimit(100000)
    K0 = make_K(P)
    nodes = [0]

    def pt(K, pos):
        if pos >= n:
            return None
        r = pos % P
        return int(C[pos]) ^ K[r] if r in K else None

    def struct_ok(K, p):
        if p + 27 > n:
            return True
        for o in (6, 7, 8, 9, 25, 26):
            v = pt(K, p + o)
            if v is not None and v != 0:
                return False
        v = pt(K, p + 19)
        return v is None or v == 0x07

    def survivors(K, p):
        """返回 [(rl, dict_name_or_None)]，按优先级排序。"""
        r0, r1 = p % P, (p + 1) % P
        out = []
        if r0 in K and r1 in K:
            rl = (int(C[p]) ^ K[r0]) | ((int(C[p + 1]) ^ K[r1]) << 8)
            if 28 <= rl <= 8192 and p + rl <= n:
                v = pt(K, p + rl - 1)
                if (v is None or v == 0) and struct_ok(K, p + rl):
                    out.append((rl, None))
            return out  # len 可读时只考虑该值（错误则回溯）
        cand_list = []
        for cand in range(28, min(8193, n - p)):
            q = p + cand - 1
            v = pt(K, q)
            if v is not None and v != 0:
                continue
            ok = True
            for j in range(27, cand - 1):
                v = pt(K, p + j)
                if v is not None and not (0x20 <= v < 0x7f or v >= 0x80):
                    ok = False
                    break
            if not ok:
                continue
            if not struct_ok(K, p + cand):
                continue
            cand_list.append(cand)
            if len(cand_list) >= 12:
                break
        # 字典完全匹配优先
        ranked = []
        for cand in cand_list:
            nm_len = cand - 28
            hit = None
            for nm in dict_by_len.get(nm_len, []):
                good = True
                for j, ch in enumerate(nm):
                    v = pt(K, p + 27 + j)
                    if v is not None and v != ch:
                        good = False
                        break
                if good:
                    hit = nm
                    break
            ranked.append((0 if hit else 1, cand, hit))
        ranked.sort()
        return [(c, h) for _s, c, h in ranked]

    def learn(K, r, v):
        r %= P
        K[r] = v   # DFS 内直接写（状态已复制）

    def apply_record(K, p, rl, nm):
        for o in (6, 7, 8, 9, 25, 26):
            learn(K, p + o, int(C[p + o]))
        learn(K, p + 19, int(C[p + 19]) ^ 0x07)
        learn(K, p, int(C[p]) ^ (rl & 0xFF))
        learn(K, p + 1, int(C[p + 1]) ^ (rl >> 8))
        if nm is not None:
            for j, ch in enumerate(nm):
                learn(K, p + 27 + j, int(C[p + 27 + j]) ^ ch)
        learn(K, p + rl - 1, int(C[p + rl - 1]))

    def dfs(K, p, hops):
        nodes[0] += 1
        if nodes[0] > node_budget:
            raise RuntimeError("预算耗尽")
        if p + 27 > n:
            return K if len(K) >= P * 0.6 else None  # 允许不满，验证说话
        for rl, nm in survivors(K, p):
            K2 = dict(K)
            apply_record(K2, p, rl, nm)
            res = dfs(K2, p + rl, hops + 1)
            if res is not None:
                return res
        return None

    try:
        Kf = dfs(dict(K0), 28 + len(name0), 1)
    except RuntimeError:
        return None, f"预算耗尽（{nodes[0]} 节点）"
    if Kf is None:
        return None, f"DFS 无解（{nodes[0]} 节点）"
    # 补漏后验证
    key = None
    if len(Kf) == P:
        key = bytes(Kf.get(r, 0) for r in range(P))
    else:
        return None, f"DFS 走通但仅 {len(Kf)}/{P}"
    tile = np.tile(np.frombuffer(key, np.uint8), n // P + 1)[:n]
    dec = (C ^ tile).tobytes()
    pos2 = nrec = 0
    while pos2 + 27 <= len(dec):
        rl = struct.unpack_from("<H", dec, pos2)[0]
        if rl < 28 or pos2 + rl > len(dec) or dec[pos2 + rl - 1] != 0:
            return None, f"验证断 @0x{pos2:x}"
        pos2 += rl
        nrec += 1
    if nrec != cn or pos2 != len(dec):
        return None, f"数 {nrec}/{cn}"
    return key, f"OK（{nodes[0]} 节点）"

for P in (254, 508, 127):
    key, msg = run(P)
    print(f"P={P}: {msg}")
    if key:
        keys = json.load(open(r"G:\pojie\ai\JiuYinUnpackTool\analysis\keys_norm.json"))
        keys[f"{rsv:04x}"] = key.hex()
        json.dump(keys, open(r"G:\pojie\ai\JiuYinUnpackTool\analysis\keys_norm.json", "w"), indent=1)
        print(f"-> text 密钥 0x{rsv:04x} 已存")
        tile = np.tile(np.frombuffer(key, np.uint8), n // P + 1)[:n]
        dec = (C ^ tile).tobytes()
        pos = 0
        for _ in range(4):
            rl = struct.unpack_from("<H", dec, pos)[0]
            off = struct.unpack_from("<Q", dec, pos + 2)[0]
            print(f"   off=0x{off:08x} {dec[pos+27:pos+rl-1].decode('gbk','replace')}")
            pos += rl
        break
