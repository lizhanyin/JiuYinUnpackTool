# -*- coding: utf-8 -*-
"""求解器 v6（最终版）

v5 基础上：
1. 迭代后用 record0 的 NUL 定位恢复 K[0]/K[1]（长度字段）
2. 缺口填补扩展：+13/+17 尺寸高字节（大概率 0）+ +20..24 时间范围 打分
3. 全量解析终极校验（数量/消费长度/NUL/GBK）
4. 可选：与旧包名字集合对照
"""
import struct, collections, os
import numpy as np

L = 200
MONTHS = np.zeros(256, bool); MONTHS[1:13] = True
DAYS = np.zeros(256, bool); DAYS[1:32] = True
HOURS = np.zeros(256, bool); HOURS[:24] = True
MINS = np.zeros(256, bool); MINS[:60] = True

def load_idx(path):
    with open(path, "rb") as f:
        head = f.read(0x13)
        flag, = struct.unpack_from("<H", head, 6)
        cnt, = struct.unpack_from("<I", head, 0x0A)
        idxend, = struct.unpack_from("<I", head, 0x0E)
        f.seek(0x13)
        return flag, cnt, idxend, f.read(idxend - 0x13)

def parse_old(idx):
    recs, pos = [], 0
    while pos + 27 <= len(idx):
        rl = struct.unpack_from("<H", idx, pos)[0]
        rec = idx[pos:pos+rl]
        nm = rec[27:]
        z = nm.find(0)
        recs.append((pos, rl, nm[:z]))
        pos += rl
    return recs

class Solver:
    def __init__(self, nidx):
        self.C = np.frombuffer(nidx, np.uint8)
        self.n = len(self.C)
        self.K = {}

    def keyarr(self):
        k = np.full(L, -1, np.int16)
        for r, v in self.K.items():
            k[r] = v
        return k

    def decrypt(self):
        k = self.keyarr()
        tile = np.tile(np.where(k >= 0, k, 0).astype(np.uint8), self.n // L + 1)[:self.n]
        return self.C ^ tile, k >= 0

    def detect(self):
        D, known = self.decrypt()
        det = np.zeros(L, bool)
        for c in range(L):
            if known[(c+6)%L] and known[(c+7)%L] and known[(c+8)%L] and known[(c+9)%L]:
                det[c] = True
        if not det.any():
            return np.array([], np.int64), det
        p = np.arange(self.n - 27, dtype=np.int64)
        p = p[det[p % L]]
        if len(p) == 0:
            return p, det
        p = p[(D[p+6] | D[p+7] | D[p+8] | D[p+9]) == 0]
        for o, want in ((19, 0x07), (25, 0), (26, 0)):
            if len(p) == 0:
                break
            chk = known[(p + o) % L]
            if chk.any():
                v = D[p[chk] + o]
                ok = np.ones(len(p), bool)
                ok[chk] = (v == want)
                p = p[ok]
        for o, tbl in ((20, MONTHS), (21, DAYS), (22, HOURS), (23, MINS), (24, MINS)):
            if len(p) == 0:
                break
            chk = known[(p + o) % L]
            if chk.any():
                v = D[p[chk] + o]
                ok = np.ones(len(p), bool)
                ok[chk] = tbl[v]
                p = p[ok]
        return p, det

def bootstrap(S, prefix):
    C = S.C
    K = {}
    for j, ch in enumerate(prefix):
        K[(27 + j) % L] = int(C[27 + j]) ^ ch
    for j in range(6, 10):
        K[j] = int(C[j])
    K[19] = int(C[19]) ^ 0x07
    K[25] = int(C[25])
    K[26] = int(C[26])
    S.K = K

def iterate(S, votes, rounds=25, verbose=False):
    def solid():
        for r, c in votes.items():
            if r in S.K:
                continue
            t = c.most_common(2)
            if t and t[0][1] >= 3 and (len(t) == 1 or t[0][1] >= 3 * t[1][1]):
                S.K[r] = t[0][0]
    for it in range(rounds):
        starts, det = S.detect()
        C = S.C
        for p in starts.tolist():
            c = p % L
            votes[(c+19) % L][int(C[p+19]) ^ 0x07] += 2
            votes[(c+25) % L][int(C[p+25])] += 1
            votes[(c+26) % L][int(C[p+26])] += 1
        solid()
        if len(S.K) == L:
            break
    return starts

def fix_record0(S):
    """record0: 名字 NUL 结尾位置 q ∈ [40,150] 且 q%200 残差已知、解出 0，
    名字区段全可解且可打印 -> len0 = q+1 -> K[0],K[1]。"""
    C = S.C
    for q in range(40, min(151, S.n)):
        r = q % L
        if r not in S.K or (int(C[q]) ^ S.K[r]) != 0:
            continue
        # 名字字节 27..q-1 全部可解且多为可打印
        ok = True
        for j in range(27, q):
            rj = j % L
            if rj not in S.K:
                ok = False
                break
            pt = int(C[j]) ^ S.K[rj]
            if not (0x20 <= pt < 0x7f or pt >= 0x80):
                ok = False
                break
        if not ok:
            continue
        len0 = q + 1
        k0 = int(C[0]) ^ (len0 & 0xFF)
        k1 = int(C[1]) ^ ((len0 >> 8) & 0xFF)
        # 下一记录在 len0 处：其 +6..9 若可解必须为零
        for o in range(6, 10):
            rr = (len0 + o) % L
            if rr in S.K and (int(C[len0 + o]) ^ S.K[rr]) != 0:
                ok = False
                break
        if not ok:
            continue
        if 0 in S.K and S.K[0] != k0:
            print(f"  record0 修复: K[0] {S.K[0]:02x} -> {k0:02x}")
        S.K[0], S.K[1] = k0, k1
        return len0
    return None

def gap_fill_scored(S, starts):
    """对缺失残差打分：o∈{6..9,19,25,26} 精确约束；{13,17} 零优先；{20..24} 范围。"""
    if len(starts) == 0:
        return
    C = S.C
    # 收集 (residue, o) 的密文样本
    samples = collections.defaultdict(list)  # r -> [(o, cipher)]
    for p in starts.tolist():
        for o in (6, 7, 8, 9, 13, 17, 19, 20, 21, 22, 23, 24, 25, 26):
            samples[(p + o) % L].append((o, int(C[p + o])))
    for r in range(L):
        if r in S.K or r not in samples:
            continue
        best, bestscore = None, None
        scores = []
        for c in range(256):
            sc = 0.0
            for o, ci in samples[r]:
                pt = ci ^ c
                if o in (6, 7, 8, 9, 19, 25, 26):
                    sc += (3.0 if pt == (0x07 if o == 19 else 0) else -3.0)
                elif o in (13, 17):
                    sc += (1.0 if pt == 0 else -0.2)
                elif o == 20:
                    sc += (1.0 if 1 <= pt <= 12 else -2.0)
                elif o == 21:
                    sc += (1.0 if 1 <= pt <= 31 else -2.0)
                elif o == 22:
                    sc += (1.0 if pt <= 23 else -2.0)
                else:
                    sc += (1.0 if pt <= 59 else -2.0)
            scores.append((sc, c))
        scores.sort(reverse=True)
        if scores[0][0] > scores[1][0] + 3.0:
            S.K[r] = scores[0][1]

def full_parse(S, cnt):
    k = S.keyarr()
    if (k < 0).any():
        return None, f"缺 {int((k<0).sum())} 残差"
    tile = np.tile(k.astype(np.uint8), S.n // L + 1)[:S.n]
    dec = (S.C ^ tile).tobytes()
    pos, nrec = 0, 0
    recs = []
    while pos + 27 <= len(dec):
        rl = struct.unpack_from("<H", dec, pos)[0]
        if rl < 28 or pos + rl > len(dec):
            return dec, f"解析失败 @0x{pos:x} rl={rl}（已 {nrec}/{cnt}）"
        if dec[pos + rl - 1] != 0:
            return dec, f"记录 {nrec} @0x{pos:x} 缺 NUL（len={rl}）"
        recs.append(dec[pos:pos+rl])
        pos += rl
        nrec += 1
    if nrec != cnt or pos != len(dec):
        return dec, f"数量 {nrec}/{cnt} 或消费 {pos:#x}/{len(dec):#x} 不符"
    return dec, "OK"

def chain_walk(S, verbose=False):
    """从 record0 逐条走完索引：每条记录学 NUL 残差 + 头部约束样本。
    len 残差未知时用 NUL+下条零约束搜索唯一幸存 rl。"""
    C = S.C
    n = S.n
    samples = collections.defaultdict(collections.Counter)
    def learn(r, v, w=1):
        samples[r][v] += w
    p = 0
    hops = 0
    while p + 27 <= n:
        r0, r1 = p % L, (p + 1) % L
        if r0 in S.K and r1 in S.K:
            rl = (int(C[p]) ^ S.K[r0]) | ((int(C[p+1]) ^ S.K[r1]) << 8)
            if not (28 <= rl <= 8192) or p + rl > n:
                return hops, f"len 非法 @0x{p:x}: {rl}", samples
        else:
            # 搜索唯一幸存 rl
            survivors = []
            for cand in range(28, min(8193, n - p)):
                q = p + cand - 1
                rq = q % L
                if rq in S.K:
                    if int(C[q]) ^ S.K[rq] != 0:
                        continue
                # 下一条零约束
                good = True
                for o in range(6, 10):
                    rr = (p + cand + o) % L
                    if rr in S.K and (int(C[p + cand + o]) ^ S.K[rr]) != 0:
                        good = False
                        break
                if good:
                    survivors.append(cand)
                if len(survivors) > 3:
                    break
            if len(survivors) != 1:
                return hops, f"rl 搜索歧义 @0x{p:x}: {survivors[:4]}", samples
            rl = survivors[0]
            S.K[r0] = int(C[p]) ^ (rl & 0xFF)
            S.K[r1] = int(C[p+1]) ^ ((rl >> 8) & 0xFF)
        # NUL 学习
        q = p + rl - 1
        if q % L not in S.K:
            S.K[q % L] = int(C[q])
        elif int(C[q]) ^ S.K[q % L] != 0:
            return hops, f"NUL 冲突 @0x{p:x}", samples
        # 头部约束样本（用于缺口残差打分）
        for o in (13, 17):
            samples[(p + o) % L][int(C[p + o])] += 1       # 期望 pt=0
        p += rl
        hops += 1
    return hops, ("EOF" if p == n else f"尾部 0x{p:x} != 0x{n:x}"), samples

def chain_gap_scores(S, samples):
    """用链式样本（+13/+17 期望 0）确定缺失残差。"""
    for r in range(L):
        if r in S.K or r not in samples:
            continue
        c = samples[r]
        if not c:
            continue
        t = c.most_common(2)
        if t[0][1] >= 3 and (len(t) == 1 or t[0][1] >= 3 * t[1][1]):
            S.K[r] = t[0][0]

def solve(new_path, old_path=None, verbose=True):
    _, ncnt, idxend, nidx = load_idx(new_path)
    S = Solver(nidx)

    # ---- 引导 ----
    prefixes = []
    if old_path:
        orecs = parse_old(load_idx(old_path)[3])
        if orecs:
            prefixes.append(bytes(orecs[0][2][:16]))
    stem = os.path.basename(new_path).rsplit(".", 1)[0].lower()
    toks = stem.split("_")
    prefixes.append(("res\\" + toks[0] + "\\").encode())
    if len(toks) >= 2:
        prefixes.append(("res\\" + toks[0] + "\\" + toks[1] + "\\").encode())
    prefixes.append(b"res\\")
    used = None
    for pref in prefixes:
        if len(pref) < 8:
            continue
        bootstrap(S, pref)
        starts, _ = S.detect()
        if verbose:
            print(f"  前缀 {pref!r}: 起点 {len(starts)}")
        if len(starts) >= 3:
            used = pref
            break
    if used is None:
        return None, None, "前缀引导失败"
    if verbose:
        print(f"引导: {used!r} -> {len(S.K)} 残差")

    votes = collections.defaultdict(collections.Counter)
    for r, v in S.K.items():
        votes[r][v] += 9
    starts = iterate(S, votes, verbose=verbose)
    if verbose:
        print(f"迭代后: {len(S.K)}/200")

    # record0 长度字段修复
    if 0 not in S.K or 1 not in S.K:
        len0 = fix_record0(S)
        if verbose:
            print(f"record0 修复: len0={len0}, 已知 {len(S.K)}/200")
    # 若已解出但可能错误，也再校验一次（fix_record0 幂等，只在通过校验时覆盖）
    fix_record0(S)

    # 链式走索引（精确学习优先）
    hops, cwmsg, cw_samples = chain_walk(S, verbose)
    if verbose:
        print(f"链式走 {hops} 跳: {cwmsg}, 已知 {len(S.K)}/200")
    chain_gap_scores(S, cw_samples)

    # 缺口打分填补（最后手段）
    if len(S.K) < L:
        starts2, _ = S.detect()
        gap_fill_scored(S, starts2)
        if verbose:
            print(f"缺口填补后: {len(S.K)}/200")

    dec, msg = full_parse(S, ncnt)
    if msg != "OK":
        return None, S, msg
    key = S.keyarr().astype(np.uint8).tobytes()
    return key, S, "OK"

if __name__ == "__main__":
    import time
    NEW = r"G:\pojie\ai\JiuYinUnpackTool\res\new\ini.package"
    OLD = r"G:\pojie\ai\JiuYinUnpackTool\res\old\ini.package"
    t0 = time.time()
    key, S, msg = solve(NEW, OLD)
    print(f"\n[{time.time()-t0:.1f}s] 结果: {msg}")
    if key:
        print("KEY:", key.hex())
        _, ncnt, idxend, nidx = load_idx(NEW)
        tile = np.tile(np.frombuffer(key, np.uint8), len(nidx)//L + 1)[:len(nidx)]
        dec = (np.frombuffer(nidx, np.uint8) ^ tile).tobytes()
        pos, recs = 0, []
        while pos + 27 <= len(dec):
            rl = struct.unpack_from("<H", dec, pos)[0]
            recs.append(dec[pos:pos+rl]); pos += rl
        def show(rec):
            off = struct.unpack_from("<Q", rec, 2)[0]
            raw, comp = struct.unpack_from("<II", rec, 10)
            return f"off=0x{off:08x} raw={raw:8d} comp={comp:7d} name={rec[27:-1].decode('gbk','replace')}"
        for r in recs[:5]:
            print(" ", show(r))
        print("  ...")
        for r in recs[-3:]:
            print(" ", show(r))
        orecs = parse_old(load_idx(OLD)[3])
        oldnames = {r[2] for r in orecs}
        newnames = {r[27:-1] for r in recs}
        inter = oldnames & newnames
        print(f"\n名字集合：旧 {len(oldnames)} / 新 {len(newnames)} / 交集 {len(inter)}"
              f"（旧保留 {len(inter)*100//len(oldnames)}%，新增 {len(newnames)-len(inter)}）")
