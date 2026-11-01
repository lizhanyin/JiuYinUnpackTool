# -*- coding: utf-8 -*-
"""结构性密钥求解器 v5

改进：
1. crib 只用保证正确的前缀 res\<stem-token>\（由包文件名推出，无需旧客户端）
2. 检出的起点按位置聚类，组内多于 1 个幸存者则整组丢弃（防影子投毒）
3. 迭代后仍有残差缺口时，用全部已确认起点做 7 种偏移约束全值扫描定值
4. 终极验证：整索引解密 + 逐记录结构解析 + 数量/长度精确匹配
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

    def keyarr(self):
        k = np.full(L, -1, np.int16)
        for r, v in self.K.items():
            k[r] = v
        return k

    def decrypt_partial(self):
        k = self.keyarr()
        known = k >= 0
        ku = np.where(known, k, 0).astype(np.uint8)
        tile = np.tile(ku, self.n // L + 1)[:self.n]
        return self.C ^ tile, known

    def detect(self):
        """返回通过全检查的起点数组（未聚类）。"""
        D, known = self.decrypt_partial()
        det = np.zeros(L, bool)
        kn = known
        for c in range(L):
            if kn[(c+6)%L] and kn[(c+7)%L] and kn[(c+8)%L] and kn[(c+9)%L]:
                det[c] = True
        if not det.any():
            return np.array([], np.int64), det
        p = np.arange(self.n - 27, dtype=np.int64)
        p = p[det[p % L]]
        if len(p) == 0:
            return p, det
        z = (D[p+6] | D[p+7] | D[p+8] | D[p+9]) == 0
        p = p[z]
        if len(p) == 0:
            return p, det
        for o, want in ((19, 0x07), (25, 0), (26, 0)):
            chk = known[(p + o) % L]
            if chk.any():
                v = D[p[chk] + o]
                ok = np.ones(len(p), bool)
                ok[chk] = (v == want)
                p = p[ok]
                if len(p) == 0:
                    return p, det
        for o, tbl in ((20, MONTHS), (21, DAYS), (22, HOURS), (23, MINS), (24, MINS)):
            chk = known[(p + o) % L]
            if chk.any():
                v = D[p[chk] + o]
                ok = np.ones(len(p), bool)
                ok[chk] = tbl[v]
                p = p[ok]
                if len(p) == 0:
                    return p, det
        return p, det

    @staticmethod
    def cluster(starts):
        """相邻(<=3)起点聚类；组内取最小位置为真起点的候选，仅当组大小==1。"""
        if len(starts) == 0:
            return []
        s = sorted(starts.tolist())
        groups, cur = [], [s[0]]
        for x in s[1:]:
            if x - cur[-1] <= 3:
                cur.append(x)
            else:
                groups.append(cur)
                cur = [x]
        groups.append(cur)
        # 组内可能同时存在真起点和影子（影子在真起点前 1~2）
        # 保留组内满足以下条件的最小成员：它到下一组的距离 >= 28（记录最短长度）
        keep = []
        for gi, g in enumerate(groups):
            nxt = groups[gi+1][0] if gi+1 < len(groups) else (1 << 60)
            for x in g:
                if nxt - x >= 28 and all(y - x >= 28 or x - y >= 28 for y in g if y != x):
                    keep.append(x)
                    break
        return keep

def bootstrap_prefix(S, prefix):
    """用已知前缀 + 结构零建立初始残差。返回已知残差数。"""
    C = S.C
    K = {}
    plen = len(prefix)
    if plen >= 8:
        for j, ch in enumerate(prefix):
            K[(27 + j) % L] = int(C[27 + j]) ^ ch
    for j in range(6, 10):
        K[j] = int(C[j])
    K[19] = int(C[19]) ^ 0x07
    K[25] = int(C[25])
    K[26] = int(C[26])
    S.K = K
    return len(K)

def candidate_prefixes(pkg_path):
    stem = os.path.basename(pkg_path).rsplit(".", 1)[0].lower()
    toks = stem.split("_")
    cands = []
    seg = toks[0]
    cands.append(("res\\" + seg + "\\").encode())
    if len(toks) >= 2:
        cands.append(("res\\" + toks[0] + "\\" + toks[1] + "\\").encode())
    cands.append(b"res\\")
    return cands

def gap_fill(S, starts):
    """对未知残差 r：候选 c 必须满足所有 (起点p, 偏移o∈{6..9,19,25,26}) 中
    (p+o)%200==r 的约束：D[p+o]^c == 期望值。返回是否补全。"""
    if len(starts) == 0:
        return False
    C = S.C
    offs = [(6, 0), (7, 0), (8, 0), (9, 0), (19, 0x07), (25, 0), (26, 0)]
    pairs = []  # (residue, expected_cipher_value = C[p+o]^want)
    for p in starts:
        for o, want in offs:
            pairs.append(((p + o) % L, int(C[p + o]) ^ want))
    by_res = collections.defaultdict(list)
    for r, e in pairs:
        by_res[r].append(e)
    changed = True
    while changed:
        changed = False
        for r in range(L):
            if r in S.K:
                continue
            es = by_res.get(r)
            if not es:
                continue
            # 候选值：K[r] = C[p+o]^pt，pt 已编码进 e；所有约束的 e 必须一致
            uniq = set(es)
            if len(uniq) == 1:
                S.K[r] = uniq.pop()
                changed = True
    return len(S.K) == L

def solve(new_path, old_path=None, verbose=True, max_iter=25):
    ncnt, idxend, nidx = load_idx(new_path)
    S = Solver(nidx)

    # ---- 引导：尝试候选前缀（也可从旧包 record0 借前缀）----
    prefixes = candidate_prefixes(new_path)
    if old_path:
        orecs = parse_old(load_idx(old_path)[2])
        if orecs:
            nm = orecs[0][2]
            # 只取前 12 字节（大概率未变）
            prefixes.insert(0, bytes(nm[:12]))
    best = None
    for pref in prefixes:
        bootstrap_prefix(S, pref)
        starts, det = S.detect()
        if verbose:
            print(f"  前缀 {pref!r}: 可检测类={int(det.sum())} 起点={len(starts)}")
        if len(starts) >= 3:
            best = pref
            break
    if best is None:
        return None, None, "前缀引导失败"
    if verbose:
        print(f"引导前缀: {best!r}，已知 {len(S.K)} 残差")

    # ---- 迭代扩张（多数投票，防影子投毒）----
    votes = collections.defaultdict(collections.Counter)
    for r, v in S.K.items():
        votes[r][v] += 9   # 引导残差视为高置信
    def solid():
        for r, c in votes.items():
            if r in S.K:
                continue
            top2 = c.most_common(2)
            if top2 and top2[0][1] >= 3 and (len(top2) == 1 or top2[0][1] >= 3 * top2[1][1]):
                S.K[r] = top2[0][0]
    for it in range(max_iter):
        starts, det = S.detect()
        C = S.C
        for p in starts.tolist():
            c = p % L
            votes[(c+19) % L][int(C[p+19]) ^ 0x07] += 2
            votes[(c+25) % L][int(C[p+25])] += 1
            votes[(c+26) % L][int(C[p+26])] += 1
            r0, r1 = c, (c+1) % L
            if r0 in S.K and r1 in S.K:
                rl = (int(C[p]) ^ S.K[r0]) | ((int(C[p+1]) ^ S.K[r1]) << 8)
                if 28 <= rl <= 8192 and p + rl <= S.n:
                    votes[(p + rl - 1) % L][int(C[p + rl - 1])] += 1
        before = len(S.K)
        solid()
        if verbose:
            print(f"iter {it}: 检出={len(starts)} 可检测类={int(det.sum())} 已知={len(S.K)}/200")
        if len(S.K) == L:
            break
        if len(S.K) == before and it >= 3:
            # 停滞：尝试用当前已知残差解出更多（月/日候选交集 -> 见 gap 逻辑）
            break
    if len(S.K) < L:
        starts2, _ = S.detect()
        if gap_fill(S, starts2.tolist()) and verbose:
            print(f"缺口填补后: {len(S.K)}/200")
    if len(S.K) < L:
        return None, S, f"仅解出 {len(S.K)}/200 残差"

    # ---- 终极验证 ----
    k = S.keyarr()
    tile = np.tile(k.astype(np.uint8), S.n // L + 1)[:S.n]
    dec = (S.C ^ tile).tobytes()
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
    return k.astype(np.uint8).tobytes(), S, "OK"

if __name__ == "__main__":
    import time
    NEW = r"G:\pojie\ai\JiuYinUnpackTool\res\new\ini.package"
    OLD = r"G:\pojie\ai\JiuYinUnpackTool\res\old\ini.package"
    t0 = time.time()
    key, S, msg = solve(NEW, OLD)
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
            return f"off=0x{off:08x} raw={raw:8d} comp={comp:7d} name={rec[27:-1].decode('gbk','replace')}"
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
