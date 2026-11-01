# -*- coding: utf-8 -*-
"""最终求解器：周期 P 参数化。
bootstrap(前缀 crib) -> 结构迭代(投票) -> record0 修复 -> 链式走 -> 打分填补 -> 全量验证。"""
import struct, collections, os
import numpy as np

MONTHS = np.zeros(256, bool); MONTHS[1:13] = True
DAYS = np.zeros(256, bool); DAYS[1:32] = True
HOURS = np.zeros(256, bool); HOURS[:24] = True
MINS = np.zeros(256, bool); MINS[:60] = True

def load_head_index(path):
    with open(path, "rb") as f:
        head = f.read(0x13)
        flag, = struct.unpack_from("<H", head, 6)
        rsv, = struct.unpack_from("<H", head, 8)
        cnt, = struct.unpack_from("<I", head, 0x0A)
        idxend, = struct.unpack_from("<I", head, 0x0E)
        f.seek(0x13)
        return flag, rsv, cnt, idxend, f.read(idxend - 0x13)

class Solver:
    def __init__(self, nidx, P):
        self.C = np.frombuffer(nidx, np.uint8)
        self.n = len(self.C)
        self.P = P
        self.K = {}

    def detect(self):
        P, C, K = self.P, self.C, self.K
        n = self.n
        det = np.zeros(P, bool)
        for c in range(P):
            if ((c+6) % P in K and (c+7) % P in K and (c+8) % P in K and (c+9) % P in K):
                det[c] = True
        if not det.any():
            return np.array([], np.int64), det
        p = np.arange(n - 27, dtype=np.int64)
        p = p[det[p % P]]
        if len(p) == 0:
            return p, det
        kv = np.array([K.get(c, -1) for c in range(P)], np.int32)
        z = np.zeros(len(p), bool)
        for o in (6, 7, 8, 9):
            k = kv[(p + o) % P]
            z |= (k < 0) | (C[p + o].astype(np.int32) != k)
        p = p[~z]
        if len(p) == 0:
            return p, det
        for o, want in ((19, 0x07), (25, 0), (26, 0)):
            k = kv[(p + o) % P]
            bad = (k >= 0) & (C[p + o].astype(np.int32) != k)
            p = p[~bad]
        for o, tbl in ((20, MONTHS), (21, DAYS), (22, HOURS), (23, MINS), (24, MINS)):
            k = kv[(p + o) % P]
            bad = np.zeros(len(p), bool)
            m = k >= 0
            if m.any():
                bad[m] = ~tbl[C[p[m] + o]]
            p = p[~bad]
        return p, det

def structural_solve(nidx, cnt, prefix, P, verbose=False):
    S = Solver(nidx, P)
    C, n = S.C, S.n
    # bootstrap
    K = {}
    for j, ch in enumerate(prefix):
        r = (27 + j) % P
        if r in K and K[r] != (int(C[27+j]) ^ ch):
            return None, None
        K[r] = int(C[27+j]) ^ ch
    for j in (6, 7, 8, 9, 25, 26):
        K[j % P] = int(C[j])
    K[19 % P] = int(C[19]) ^ 0x07
    S.K = K
    votes = collections.defaultdict(collections.Counter)
    for r, v in S.K.items():
        votes[r][v] += 9

    def solid():
        for r, c in votes.items():
            if r in S.K:
                continue
            t = c.most_common(2)
            if t and t[0][1] >= 3 and (len(t) == 1 or t[0][1] >= 3 * t[1][1]):
                S.K[r] = t[0][0]

    # 迭代
    for it in range(30):
        starts, det = S.detect()
        for p in starts.tolist():
            c = p % P
            votes[(c+19) % P][int(C[p+19]) ^ 0x07] += 2
            votes[(c+25) % P][int(C[p+25])] += 1
            votes[(c+26) % P][int(C[p+26])] += 1
        if len(S.K) == P:
            break
        before = len(S.K)
        solid()
        if len(S.K) == before and it > 8:
            break
    # record0 修复（NUL 定位）
    for q in range(40, min(151, n)):
        r = q % P
        if r in S.K and (int(C[q]) ^ S.K[r]) == 0:
            ok = all(((j % P) in S.K) and (0x20 <= (int(C[j]) ^ S.K[j % P]) < 0x7f or
                      (int(C[j]) ^ S.K[j % P]) >= 0x80) for j in range(27, q))
            if ok:
                len0 = q + 1
                good = True
                for o in range(6, 10):
                    rr = (len0 + o) % P
                    if rr in S.K and (int(C[len0 + o]) ^ S.K[rr]) != 0:
                        good = False
                        break
                if good:
                    S.K[0] = int(C[0]) ^ (len0 & 0xFF)
                    S.K[1 % P] = int(C[1]) ^ ((len0 >> 8) & 0xFF)
                break
    # 链式走
    p = 0
    hops = 0
    while p + 27 <= n:
        r0, r1 = p % P, (p + 1) % P
        if r0 in S.K and r1 in S.K:
            rl = (int(C[p]) ^ S.K[r0]) | ((int(C[p+1]) ^ S.K[r1]) << 8)
            if not (28 <= rl <= 8192) or p + rl > n:
                break
        else:
            surv = []
            for cand in range(28, min(8193, n - p)):
                q = p + cand - 1
                if q % P in S.K and (int(C[q]) ^ S.K[q % P]) != 0:
                    continue
                okc = True
                for o in range(6, 10):
                    rr = (p + cand + o) % P
                    if rr in S.K and (int(C[p + cand + o]) ^ S.K[rr]) != 0:
                        okc = False
                        break
                if okc:
                    surv.append(cand)
                if len(surv) > 2:
                    break
            if len(surv) != 1:
                break
            rl = surv[0]
            S.K[r0] = int(C[p]) ^ (rl & 0xFF)
            S.K[r1] = int(C[p+1]) ^ ((rl >> 8) & 0xFF)
        q = p + rl - 1
        if q % P not in S.K:
            S.K[q % P] = int(C[q])
        elif int(C[q]) ^ S.K[q % P] != 0:
            break
        p += rl
        hops += 1
    # 缺口打分（+13/+17 期望 0）
    starts, _ = S.detect()
    samples = collections.defaultdict(collections.Counter)
    for ps in starts.tolist():
        for o in (13, 17):
            samples[(ps + o) % P][int(C[ps + o])] += 1
    for r in range(P):
        if r not in S.K and r in samples:
            t = samples[r].most_common(2)
            if t[0][1] >= 3 and (len(t) == 1 or t[0][1] >= 3 * t[1][1]):
                S.K[r] = t[0][0]
    if len(S.K) < P:
        return None, S
    key = bytes(S.K[r] for r in range(P))
    # 全量验证
    tile = np.tile(np.frombuffer(key, np.uint8), n // P + 1)[:n]
    dec = (C ^ tile).tobytes()
    pos = nrec = 0
    while pos + 27 <= len(dec):
        rl = struct.unpack_from("<H", dec, pos)[0]
        if rl < 28 or pos + rl > len(dec) or dec[pos + rl - 1] != 0:
            return None, S
        pos += rl
        nrec += 1
    if nrec != cnt or pos != len(dec):
        return None, S
    return key, S

def pscan(nidx, prefix, pmin=16, pmax=1024):
    """快速 P 扫描：折叠 crib，统计四连零命中。"""
    C = np.frombuffer(nidx, np.uint8)
    n = len(C)
    KS = {}
    for j, ch in enumerate(prefix):
        KS[27 + j] = int(C[27 + j]) ^ ch
    for j in (6, 7, 8, 9, 25, 26):
        KS[j] = int(C[j])
    KS[19] = int(C[19]) ^ 0x07
    pos_arr = np.arange(n - 27, dtype=np.int64)
    res = []
    for P in range(pmin, pmax + 1):
        kmod = np.full(P, -1, np.int32)
        bad = False
        for p_, v in KS.items():
            r = p_ % P
            if kmod[r] >= 0 and kmod[r] != v:
                bad = True
                break
            kmod[r] = v
        if bad:
            continue
        ok = np.ones(len(pos_arr), bool)
        for o in (6, 7, 8, 9):
            k = kmod[(pos_arr + o) % P]
            ok &= (k >= 0) & (C[pos_arr + o].astype(np.int32) == k)
        res.append((int(ok.sum()), P))
    res.sort(reverse=True)
    return res

def crack_package(new_path, prefix, pmax=1024, verbose=True):
    flag, rsv, cnt, idxend, nidx = load_head_index(new_path)
    cands = pscan(nidx, prefix, 16, pmax)
    tried = set()
    for hits, P in cands[:24]:
        fam = set()
        for d in range(1, 290):
            if P % d == 0 and P // d >= 16:
                fam.add(P // d)
        fam.add(P)
        for Pc in sorted(fam, reverse=False):
            if Pc in tried or Pc < 16:
                continue
            tried.add(Pc)
            key, S = structural_solve(nidx, cnt, prefix, Pc)
            if key is not None:
                if verbose:
                    print(f"  {os.path.basename(new_path)}: P={Pc} (scan top={P}) -> OK")
                return rsv, Pc, key
    return None, None, None

if __name__ == "__main__":
    import json
    NEW_ROOT = r"F:\Game\Online\9yin\9yin"
    targets = {
        "res\\lua.package": b"res\\lua\\",
        "res\\lua64.package": b"res\\lua64\\",
        "res\\map_ini.package": b"res\\map\\ini\\",
        "res\\text.package": b"res\\text\\",
    }
    keys = json.load(open(r"G:\pojie\ai\JiuYinUnpackTool\analysis\keys.json", encoding="utf-8"))
    for rel, pref in targets.items():
        rsv, P, key = crack_package(os.path.join(NEW_ROOT, rel), pref)
        if key:
            keys[rel] = dict(rsv=rsv, P=P, key=key.hex())
            print(f"{rel}: P={P} OK")
        else:
            print(f"{rel}: FAIL")
    with open(r"G:\pojie\ai\JiuYinUnpackTool\analysis\keys.json", "w", encoding="utf-8") as f:
        json.dump(keys, f, indent=1)
    print(f"\n累计 {len(keys)} 个密钥 -> analysis/keys.json")
