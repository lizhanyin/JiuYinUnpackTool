# -*- coding: utf-8 -*-
"""结构性密钥求解器 v3

针对 v2 的修正：
- 小偏移记录零串超过 4 字节 -> 真起点 q 产生影子候选 q-1/q-2。
  判别：影子在 +19(=0x07)/+25/+26 检查上会命中 comp 高位/秒/分字段，几乎必挂。
- 候选按位置聚类（相距<=3），仅从通过全检查的聚类学习；
- 学习改为按残差多数投票，进一步抗噪；
- 每轮扫描限制在可判定类（残差 4 连续已知），随知识增长自然扩张。
"""
import struct, collections, sys

L = 200
MONTHS = set(range(1, 13))
DAYS = set(range(1, 32))
HOURS = set(range(24))
MINS = set(range(60))

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
        recs.append(dict(pos=pos, len=rl, name=nm[:z]))
        pos += rl
    return recs

class Solver:
    def __init__(self, nidx):
        self.nidx = nidx
        self.n = len(nidx)
        self.K = {}
        self.votes = collections.defaultdict(collections.Counter)  # 残差 -> Counter

    def learn(self, r, v, w=1):
        """投票式学习；当多数票明确时固化。"""
        r %= L
        self.votes[r][v] += w
        c = self.votes[r]
        top2 = c.most_common(2)
        if len(top2) == 1 or top2[0][1] >= top2[1][1] * 3 and top2[0][1] >= 3:
            self.K[r] = top2[0][0]

    def solid(self):
        """把已满足多数票的残差固化。"""
        for r, c in self.votes.items():
            if r in self.K:
                continue
            top2 = c.most_common(2)
            if top2 and (len(top2) == 1 or top2[0][1] >= 3 * top2[1][1]) and top2[0][1] >= 3:
                self.K[r] = top2[0][0]

    # ---- 起点检测 ----
    def detect(self):
        """返回 (确认起点列表, 影子被拒数)。检测条件：
        1) +6..+9 残差全已知且为 0（4 连零）
        2) +19 残差已知时必须 == 0x07
        3) +25/+26 残差已知时必须 == 0
        4) +20..24 残差已知时必须在合法范围
        """
        K = self.K
        nidx = self.nidx
        n = self.n
        # 预计算可检测的类
        classes = []
        for c in range(L):
            rs = [(c + 6 + j) % L for j in range(4)]
            if all(r in K for r in rs):
                classes.append(c)
        clsset = set(classes)
        cands = []
        rejected_shadow = 0
        for p in range(n - 27):
            c = p % L
            if c not in clsset:
                continue
            base = p - c  # 对齐后的锚
            ok = True
            for j in range(4):
                if nidx[p + 6 + j] != K[(c + 6 + j) % L]:
                    ok = False
                    break
            if not ok:
                continue
            # 影子判别
            r19 = (c + 19) % L
            if r19 in K and (nidx[p + 19] ^ K[r19]) != 0x07:
                rejected_shadow += 1
                continue
            bad = False
            for o in (25, 26):
                r = (c + o) % L
                if r in K and nidx[p + o] != K[r]:
                    bad = True
                    break
            if bad:
                rejected_shadow += 1
                continue
            for o, allowed in ((20, MONTHS), (21, DAYS), (22, HOURS), (23, MINS), (24, MINS)):
                r = (c + o) % L
                if r in K and (nidx[p + o] ^ K[r]) not in allowed:
                    bad = True
                    break
            if bad:
                rejected_shadow += 1
                continue
            cands.append(p)
        return cands, rejected_shadow, classes

    def learn_from(self, starts):
        for p in starts:
            c = p % L
            self.learn((c + 19) % L, self.nidx[p + 19] ^ 0x07, w=2)   # 0x07 确定
            self.learn((c + 25) % L, self.nidx[p + 25])                # extra=0
            self.learn((c + 26) % L, self.nidx[p + 26])
            r0, r1 = c, (c + 1) % L
            if r0 in self.K and r1 in self.K:
                rl = (self.nidx[p] ^ self.K[r0]) | ((self.nidx[p + 1] ^ self.K[r1]) << 8)
                if 28 <= rl <= 8192 and p + rl <= self.n:
                    self.learn((p + rl - 1) % L, self.nidx[p + rl - 1], w=1)  # NUL

    def key_or_none(self):
        if len(self.K) < L:
            return None
        return bytes(self.K[r] for r in range(L))

def bootstrap(S, orecs, nidx, verbose):
    """假设新 record0 的名字 == 某旧记录的名字。"""
    for i, rec in enumerate(orecs):
        nm = rec["name"]
        if not nm:
            continue
        rl0 = 28 + len(nm)
        if rl0 >= L:
            continue
        K = {}
        K[0] = nidx[0] ^ (rl0 & 0xFF)
        K[1] = nidx[1] ^ ((rl0 >> 8) & 0xFF)
        for j in range(6, 10):
            K[j] = nidx[j]
        K[19] = nidx[19] ^ 0x07
        K[25] = nidx[25]
        K[26] = nidx[26]
        for j, ch in enumerate(nm):
            r = (27 + j) % L
            if r in K and K[r] != (nidx[27 + j] ^ ch):
                K = None
                break
            K[r] = nidx[27 + j] ^ ch
        if K is None:
            continue
        # 内部一致性 OK；还需影子自检：K[19] 处的 0x07 与名字若覆盖残差19一致（27+j>=200不可能）
        S.K = K
        for r, v in K.items():
            S.votes[r][v] += 5
        if verbose:
            print(f"引导：旧记录 #{i} name={nm[:40]!r} -> {len(K)} 残差")
        return True
    return False

def solve(old_path, new_path, verbose=True, max_iter=40):
    ocnt, _, oidx = load_idx(old_path)
    ncnt, idxend, nidx = load_idx(new_path)
    orecs = parse_old(oidx)
    S = Solver(nidx)
    if not bootstrap(S, orecs, nidx, verbose):
        return None, None, "引导失败（旧记录名均不匹配新 record0）"
    for it in range(max_iter):
        starts, rej, classes = S.detect()
        S.learn_from(starts)
        S.solid()
        if verbose:
            print(f"iter {it}: 可检测类={len(classes)} 起点={len(starts)} 影子拒绝={rej} 已知={len(S.K)}/200")
        if len(S.K) == L:
            break
    key = S.key_or_none()
    if key is None:
        return None, S, f"仅解出 {len(S.K)}/200 残差"
    # 全量验证
    dec = bytes(c ^ key[i % L] for i, c in enumerate(nidx))
    pos, nrec = 0, 0
    while pos + 27 <= len(dec):
        rl = struct.unpack_from("<H", dec, pos)[0]
        if rl < 28 or pos + rl > len(dec):
            return key, S, f"解析失败 @0x{pos:x} rl={rl} (已解析 {nrec}/{ncnt})"
        nm = dec[pos + 27:pos + rl]
        if nm[-1] != 0:
            return key, S, f"记录 {nrec} 缺 NUL 结尾"
        pos += rl
        nrec += 1
    if nrec != ncnt or pos != len(dec):
        return key, S, f"数量 {nrec}/{ncnt} 或消费 {pos:#x}/{len(dec):#x} 不符"
    return key, S, "OK"

if __name__ == "__main__":
    OLD = r"G:\pojie\ai\JiuYinUnpackTool\res\old\ini.package"
    NEW = r"G:\pojie\ai\JiuYinUnpackTool\res\new\ini.package"
    key, S, msg = solve(OLD, NEW)
    print(f"\n结果: {msg}")
    if key:
        print("KEY:", key.hex())
        # 抽样打印前 5 条与最后 3 条
        ncnt, idxend, nidx = load_idx(NEW)
        dec = bytes(c ^ key[i % L] for i, c in enumerate(nidx))
        pos, nrec = 0, 0
        recs = []
        while pos + 27 <= len(dec):
            rl = struct.unpack_from("<H", dec, pos)[0]
            recs.append(dec[pos:pos+rl]); pos += rl
        def show(rec):
            off = struct.unpack_from("<Q", rec, 2)[0]
            raw, comp = struct.unpack_from("<II", rec, 10)
            name = rec[27:-1].decode("gbk", "replace")
            return f"off=0x{off:08x} raw={raw:8d} comp={comp:7d} name={name}"
        for r in recs[:5]:
            print(" ", show(r))
        print("  ...")
        for r in recs[-3:]:
            print(" ", show(r))
        # 与旧包名字集合对比
        orecs = parse_old(load_idx(OLD)[2])
        oldnames = {r["name"] for r in orecs}
        newnames = {r[:-1] for r in recs}
        inter = oldnames & newnames
        print(f"\n名字集合：旧 {len(oldnames)}，新 {len(newnames)}，交集 {len(inter)}"
              f"（旧保留 {len(inter)*100//len(oldnames)}%，新增 {len(newnames)-len(inter)}）")
