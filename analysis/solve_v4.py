# -*- coding: utf-8 -*-
"""结构性密钥求解器 v4（numpy 向量化）

流程：
1. crib 候选 = 旧包全部记录名；对每个候选构造 K 假设，
   用「+6..+9 四连零在覆盖类上的命中数」打分——错误 crib 的名字残差是垃圾，
   命中数趋近 0；正确 crib 会命中间隔 ~55 字节的真起点。取最优 crib。
2. 迭代扩张：检测（全类向量化）-> 影子判别 -> 残差多数票 -> 固化。
3. 终极验证：整索引解密、逐记录解析、数量与消费长度精确匹配。
"""
import struct, collections
import numpy as np

L = 200
MONTHS = np.zeros(256, bool); MONTHS[1:13] = True
DAYS = np.zeros(256, bool); DAYS[1:32] = True
HOURS = np.zeros(256, bool); HOURS[:24] = True
MINS = np.zeros(256, bool); MINS[:60] = True

def load_idx(path):
    with open(path, "rb") as f:
        head = f.read(0x13)
        cnt, = struct.unpack_from("<I", head, 0x0A)
        idxend, = struct.unpack_from("<I", head, 0x0E)
        f.seek(0x13)
        return cnt, idxend, f.read(idxend - 0x13)

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
        self.votes = collections.defaultdict(collections.Counter)

    def keyarr(self):
        k = np.full(L, -1, np.int16)
        for r, v in self.K.items():
            k[r] = v
        return k

    def decrypt(self):
        k = self.keyarr()
        assert (k >= 0).all(), f"缺 {int((k<0).sum())} 个残差"
        tile = np.tile(k.astype(np.uint8), self.n // L + 1)[:self.n]
        return self.C ^ tile

    def detect(self):
        """向量化起点检测。返回 (起点数组, 各类可检测布尔)。"""
        k = self.keyarr()
        known = k >= 0
        # 类 c 可检测：c+6..c+9 残差全部已知
        det_classes = np.zeros(L, bool)
        for c in range(L):
            if known[(c+6)%L] and known[(c+7)%L] and known[(c+8)%L] and known[(c+9)%L]:
                det_classes[c] = True
        if not det_classes.any():
            return np.array([], np.int64), det_classes
        # 解密（未知残差用 0x100 标记位区分：这里先解出，未知位置值无意义但检查会跳过）
        ku = np.where(known, k, 0).astype(np.uint8)
        tile = np.tile(ku, self.n // L + 1)[:self.n]
        D = self.C ^ tile
        p_all = np.arange(self.n - 27, dtype=np.int64)
        cls = (p_all % L)
        mask_cls = det_classes[cls]
        p_cand = p_all[mask_cls]
        if len(p_cand) == 0:
            return np.array([], np.int64), det_classes
        d6 = D[p_cand + 6] | D[p_cand + 7] | D[p_cand + 8] | D[p_cand + 9]
        keep = d6 == 0
        p_cand = p_cand[keep]
        if len(p_cand) == 0:
            return np.array([], np.int64), det_classes
        # +19 = 0x07（若已知）
        r19 = ((p_cand + 19) % L)
        chk = known[r19]
        if chk.any():
            v = D[p_cand[chk] + 19]
            ok = np.ones(len(p_cand), bool)
            ok[chk] = (v == 0x07)
            p_cand = p_cand[ok]
            if len(p_cand) == 0:
                return np.array([], np.int64), det_classes
        # +25/+26 = 0（若已知）
        for o in (25, 26):
            r = ((p_cand + o) % L)
            chk = known[r]
            if chk.any():
                v = D[p_cand[chk] + o]
                ok = np.ones(len(p_cand), bool)
                ok[chk] = (v == 0)
                p_cand = p_cand[ok]
                if len(p_cand) == 0:
                    return np.array([], np.int64), det_classes
        # +20..24 范围（若已知）
        for o, tbl in ((20, MONTHS), (21, DAYS), (22, HOURS), (23, MINS), (24, MINS)):
            r = ((p_cand + o) % L)
            chk = known[r]
            if chk.any():
                v = D[p_cand[chk] + o]
                ok = np.ones(len(p_cand), bool)
                ok[chk] = tbl[v]
                p_cand = p_cand[ok]
                if len(p_cand) == 0:
                    return np.array([], np.int64), det_classes
        return p_cand, det_classes

    def learn(self, r, v, w=1):
        self.votes[r][v] += w

    def solid(self):
        for r, c in self.votes.items():
            if r in self.K:
                continue
            top2 = c.most_common(2)
            if top2 and top2[0][1] >= 3 and (len(top2) == 1 or top2[0][1] >= 3 * top2[1][1]):
                self.K[r] = top2[0][0]

    def learn_from(self, starts):
        if len(starts) == 0:
            return
        C = self.C
        for p in starts.tolist():
            c = p % L
            self.learn((c + 19) % L, int(C[p + 19]) ^ 0x07, w=2)
            self.learn((c + 25) % L, int(C[p + 25]))
            self.learn((c + 26) % L, int(C[p + 26]))
            r0, r1 = c, (c + 1) % L
            if r0 in self.K and r1 in self.K:
                rl = (int(C[p]) ^ self.K[r0]) | ((int(C[p + 1]) ^ self.K[r1]) << 8)
                if 28 <= rl <= 8192 and p + rl <= self.n:
                    self.learn((p + rl - 1) % L, int(C[p + rl - 1]))

def crib_score(S, K):
    """给定 crib 产生的 K 假设，统计覆盖类上的四连零命中数。"""
    S.K = dict(K)
    starts, dc = S.detect()
    return len(starts), int(dc.sum())

def solve(old_path, new_path, verbose=True, max_iter=30):
    ocnt, _, oidx = load_idx(old_path)
    ncnt, idxend, nidx = load_idx(new_path)
    orecs = parse_old(oidx)
    S = Solver(nidx)
    C = S.C

    # ---- crib 选择：按名字长度降序（长名覆盖残差多），验证命中数 ----
    cands = sorted(orecs, key=lambda r: -len(r[2]))
    best = None
    for idx_i, (pos, rl, nm) in enumerate(cands[:400]):
        if not nm or len(nm) + 28 >= L:
            continue
        rl0 = 28 + len(nm)
        K = {0: int(C[0]) ^ (rl0 & 0xFF), 1: int(C[1]) ^ (rl0 >> 8),
             19: int(C[19]) ^ 0x07, 25: int(C[25]), 26: int(C[26])}
        for j in range(6, 10):
            K[j] = int(C[j])
        for j, ch in enumerate(nm):
            K[(27 + j) % L] = int(C[27 + j]) ^ ch
        hits, ndc = crib_score(Solver(nidx), K)
        if hits >= 5:
            best = (K, hits, nm, idx_i)
            if verbose:
                print(f"crib 命中：旧记录@{pos} name={nm[:40]!r} 四连零命中={hits}")
            break
        if verbose and idx_i < 5:
            print(f"  crib#{idx_i} {nm[:30]!r} 命中={hits} -> 弃")
    if best is None:
        return None, None, "所有 crib 候选均无命中（新 record0 名字不在旧包中？）"
    K = best[0]
    S.K = dict(K)
    for r, v in K.items():
        S.votes[r][v] += 5

    # ---- 迭代扩张 ----
    for it in range(max_iter):
        starts, dc = S.detect()
        S.learn_from(starts)
        S.solid()
        if verbose:
            print(f"iter {it}: 可检测类={int(dc.sum())} 起点={len(starts)} 已知={len(S.K)}/200")
        if len(S.K) == L:
            break
    if len(S.K) < L:
        return None, S, f"仅解出 {len(S.K)}/200 残差"
    # ---- 终极验证 ----
    try:
        D = S.decrypt()
    except AssertionError as e:
        return None, S, str(e)
    dec = D.tobytes()
    pos, nrec = 0, 0
    while pos + 27 <= len(dec):
        rl = struct.unpack_from("<H", dec, pos)[0]
        if rl < 28 or pos + rl > len(dec):
            return None, S, f"解析失败 @0x{pos:x} rl={rl}（已 {nrec}/{ncnt}）"
        if dec[pos + rl - 1] != 0:
            return None, S, f"记录 {nrec} 缺 NUL"
        pos += rl
        nrec += 1
    if nrec != ncnt or pos != len(dec):
        return None, S, f"数量 {nrec}/{ncnt} 或消费 {pos:#x}/{len(dec):#x} 不符"
    return S.keyarr().astype(np.uint8).tobytes(), S, "OK"

if __name__ == "__main__":
    import sys, time
    OLD = r"G:\pojie\ai\JiuYinUnpackTool\res\old\ini.package"
    NEW = r"G:\pojie\ai\JiuYinUnpackTool\res\new\ini.package"
    t0 = time.time()
    key, S, msg = solve(OLD, NEW)
    print(f"\n[{time.time()-t0:.1f}s] 结果: {msg}")
    if key:
        print("KEY:", key.hex())
        ncnt, idxend, nidx = load_idx(NEW)
        tile = np.tile(np.frombuffer(key, np.uint8), len(nidx)//L + 1)[:len(nidx)]
        dec = (np.frombuffer(nidx, np.uint8) ^ tile).tobytes()
        pos, recs = 0, []
        while pos + 27 <= len(dec):
            rl = struct.unpack_from("<H", dec, pos)[0]
            recs.append(dec[pos:pos+rl]); pos += rl
        def show(rec):
            off = struct.unpack_from("<Q", rec, 2)[0]
            raw, comp = struct.unpack_from("<II", rec, 10)
            ts = struct.unpack_from("<H", rec, 18)[0]
            return f"off=0x{off:08x} raw={raw:8d} comp={comp:7d} ts={ts} name={rec[27:-1].decode('gbk','replace')}"
        for r in recs[:5]:
            print(" ", show(r))
        print("  ...")
        for r in recs[-3:]:
            print(" ", show(r))
        orecs = parse_old(load_idx(OLD)[2])
        oldnames = {r[2] for r in orecs}
        newnames = {r[27:-1] for r in recs}
        inter = oldnames & newnames
        print(f"\n名字集合：旧 {len(oldnames)} / 新 {len(newnames)} / 交集 {len(inter)}"
              f"（旧保留 {len(inter)*100//len(oldnames)}%，新增 {len(newnames)-len(inter)}）")
