# -*- coding: utf-8 -*-
"""链式求解器：完整名字 crib + 记录链逐跳推进。
每跳：len 可读则读；不可读则 NUL+下条零约束搜索唯一 rl。
每跳学习：len 两残差、NUL 残差、+19/+25/+26（对真起点是精确值）。
对 P 的候选族逐一尝试，全量解析验证。"""
import struct, collections, os
import numpy as np

def load_head_index(path):
    with open(path, "rb") as f:
        head = f.read(0x13)
        flag, = struct.unpack_from("<H", head, 6)
        rsv, = struct.unpack_from("<H", head, 8)
        cnt, = struct.unpack_from("<I", head, 0x0A)
        idxend, = struct.unpack_from("<I", head, 0x0E)
        f.seek(0x13)
        return flag, rsv, cnt, idxend, f.read(idxend - 0x13)

def parse_old(idx):
    recs, pos = [], 0
    while pos + 27 <= len(idx):
        rl = struct.unpack_from("<H", idx, pos)[0]
        nm = idx[pos+27:pos+rl]
        z = nm.find(0)
        recs.append(idx[pos:pos+rl])
        pos += rl
    return recs

def chain_solve(nidx, cnt, name0, P, verbose=False):
    C = np.frombuffer(nidx, np.uint8)
    n = len(C)
    K = {}
    votes = collections.defaultdict(collections.Counter)
    def learn(r, v, w=2):
        r %= P
        votes[r][v] += w
        t = votes[r].most_common(2)
        if t and t[0][1] >= 3 and (len(t) == 1 or t[0][1] >= 3 * t[1][1]):
            K[r] = t[0][0]
    # bootstrap：完整名字
    rl0 = 28 + len(name0)
    learn(0, int(C[0]) ^ (rl0 & 0xFF), 9)
    learn(1, int(C[1]) ^ (rl0 >> 8), 9)
    for j in (6, 7, 8, 9, 25, 26):
        learn(j, int(C[j]), 9)
    learn(19, int(C[19]) ^ 0x07, 9)
    for j, ch in enumerate(name0):
        learn(27 + j, int(C[27 + j]) ^ ch, 9)
    p, hops = 0, 0
    while p + 27 <= n:
        r0, r1 = p % P, (p + 1) % P
        if r0 in K and r1 in K:
            rl = (int(C[p]) ^ K[r0]) | ((int(C[p+1]) ^ K[r1]) << 8)
            if not (28 <= rl <= 8192) or p + rl > n:
                return None, hops, f"len 非法 @0x{p:x} rl={rl}"
        else:
            surv = []
            for cand in range(28, min(8193, n - p)):
                q = p + cand - 1
                rq = q % P
                if rq in K and (int(C[q]) ^ K[rq]) != 0:
                    continue
                okc = True
                for o in range(6, 10):
                    rr = (p + cand + o) % P
                    if rr in K and (int(C[p + cand + o]) ^ K[rr]) != 0:
                        okc = False
                        break
                if okc:
                    surv.append(cand)
                if len(surv) > 2:
                    break
            if len(surv) != 1:
                return None, hops, f"rl 歧义 @0x{p:x}: {surv[:3]} 已知{len(K)}/{P}"
            rl = surv[0]
            learn(r0, int(C[p]) ^ (rl & 0xFF))
            learn(r1, int(C[p+1]) ^ (rl >> 8))
        # 精确学习（真起点）
        learn(p + 19, int(C[p + 19]) ^ 0x07)
        learn(p + 25, int(C[p + 25]))
        learn(p + 26, int(C[p + 26]))
        for o in range(6, 10):
            learn(p + o, int(C[p + o]))
        q = p + rl - 1
        learn(q, int(C[q]), 1)
        if q % P in K and int(C[q]) ^ K[q % P] != 0:
            return None, hops, f"NUL 冲突 @0x{p:x}"
        p += rl
        hops += 1
    if len(K) < P:
        # 尺寸高字节补漏
        samples = collections.defaultdict(collections.Counter)
        pp = 0
        while pp + 27 <= n:
            try:
                rl = (int(C[pp]) ^ K[pp % P]) | ((int(C[pp+1]) ^ K[(pp+1) % P]) << 8)
            except KeyError:
                break
            if not (28 <= rl <= 8192) or pp + rl > n:
                break
            for o in (13, 17):
                samples[(pp + o) % P][int(C[pp + o])] += 1
            pp += rl
        for r in range(P):
            if r not in K and r in samples:
                t = samples[r].most_common(2)
                if t[0][1] >= 3 and (len(t) == 1 or t[0][1] >= 3 * t[1][1]):
                    K[r] = t[0][0]
    if len(K) < P:
        return None, hops, f"仅 {len(K)}/{P} 残差"
    key = bytes(K[r] for r in range(P))
    tile = np.tile(np.frombuffer(key, np.uint8), n // P + 1)[:n]
    dec = (C ^ tile).tobytes()
    pos2 = nrec = 0
    while pos2 + 27 <= len(dec):
        rl = struct.unpack_from("<H", dec, pos2)[0]
        if rl < 28 or pos2 + rl > len(dec) or dec[pos2 + rl - 1] != 0:
            return None, hops, f"验证断 @0x{pos2:x}"
        pos2 += rl
        nrec += 1
    if nrec != cnt or pos2 != len(dec):
        return None, hops, f"数 {nrec}/{cnt}"
    return key, hops, "OK"

def try_package(new_path, old_path, P_list, verbose=True):
    flag, rsv, cnt, idxend, nidx = load_head_index(new_path)
    orecs = parse_old(load_head_index(old_path)[4])
    # crib 候选：旧 record0 名字（完整），然后 12 字节前缀
    name0_full = orecs[0][27:-1]
    cribs = [(name0_full, "全名"), (name0_full[:12], "前12"), (name0_full[:8], "前8")]
    for P in P_list:
        for crib, tag in cribs:
            key, hops, msg = chain_solve(nidx, cnt, crib, P)
            if key is not None:
                if verbose:
                    print(f"  {os.path.basename(new_path)}: P={P} crib={tag} {hops}跳 -> OK")
                return rsv, P, key
            if verbose and tag == "全名" and P == P_list[0]:
                print(f"  尝试 P={P} {tag}: {msg}")
    return None, None, None

if __name__ == "__main__":
    import json
    OLD_ROOT = r"F:\Game\Online\9yin\20230423\9yin"
    NEW_ROOT = r"F:\Game\Online\9yin\9yin"
    cand = {
        "res\\lua.package": [252, 126, 84, 63, 42, 504, 21, 28, 36, 14, 12],
        "res\\lua64.package": [150, 75, 50, 300, 25, 30, 15, 10, 600, 6, 5],
        "res\\map_ini.package": [148, 74, 37, 296, 444, 592, 18, 36, 74*4],
        "res\\text.package": [254, 127, 508, 1016, 63, 62, 31, 254*2],
    }
    keys = json.load(open(r"G:\pojie\ai\JiuYinUnpackTool\analysis\keys.json", encoding="utf-8"))
    for rel, plist in cand.items():
        r = try_package(os.path.join(NEW_ROOT, rel), os.path.join(OLD_ROOT, rel), plist)
        if r[2] is not None:
            rsv, P, key = r
            keys[rel] = dict(rsv=rsv, P=P, key=key.hex())
            print(f"{rel}: P={P} OK")
        else:
            print(f"{rel}: FAIL")
    with open(r"G:\pojie\ai\JiuYinUnpackTool\analysis\keys.json", "w", encoding="utf-8") as f:
        json.dump(keys, f, indent=1)
    print(f"\n累计 {len(keys)} 密钥")
