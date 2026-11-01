# -*- coding: utf-8 -*-
"""结构性密钥求解器 v2

约束模型（每条记录起点 p，明文字节 pt[i] = nidx[i] ^ K[i%200]）：
  pt[p+6..p+10) == 0            u64 数据偏移高 4 字节（确定）
  pt[p+13] == 0 (弱)            raw_size 高字节（<16MB 时为 0）
  pt[p+17] == 0 (弱)            comp_size 高字节
  pt[p+19] == 0x07              年份 202x 的高字节（确定）
  pt[p+20] ∈ 1..12              月
  pt[p+21] ∈ 1..31              日
  pt[p+22] ∈ 0..23              时
  pt[p+23] ∈ 0..59              分
  pt[p+24] ∈ 0..59              秒
  pt[p+25..p+27) == 0           extra（.package 确定；.patch 可能非 0 → 不用）
  pt[p+rl-1] == 0               名字 NUL
  pt[p+27..p+rl-1)              GBK 文件名（多为可打印 ASCII）

流程：旧记录名 crib 引导 -> 起点检测（零约束严格校验）-> +19/+25/+26 学习
     -> 链式推进 -> 月/日/时/分/秒候选集交集 -> 补漏 -> 全量解析验证
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

def parse_old(idx, is_patch=False):
    recs = []
    pos = 0
    while pos + 27 <= len(idx):
        rl = struct.unpack_from("<H", idx, pos)[0]
        rec = idx[pos:pos+rl]
        nm = rec[27:]
        z = nm.find(0)
        extra = struct.unpack_from("<H", rec, 25)[0]
        recs.append(dict(pos=pos, len=rl, name=nm[:z], extra=extra,
                         raw=struct.unpack_from("<I", rec, 10)[0],
                         comp=struct.unpack_from("<I", rec, 14)[0],
                         ts=rec[18:25]))
        pos += rl
    return recs

class Solver:
    def __init__(self, nidx):
        self.nidx = nidx
        self.n = len(nidx)
        self.K = {}                      # 残差 -> 确定值
        self.cand = {r: set(range(256)) for r in range(L)}  # 候选集

    def pt(self, i):
        return self.nidx[i] ^ self.K[i % L]

    def fix(self, r, v, why=""):
        r %= L
        if r in self.K:
            if self.K[r] != v:
                raise AssertionError(f"冲突 残差{r}: {self.K[r]:02x} vs {v:02x} ({why})")
            return
        self.K[r] = v
        self.cand[r] = {v}

    def restrict(self, r, allowed, why=""):
        """把残差 r 的候选集限制为 allowed（按明文取值集合反推）"""
        r %= L
        newc = {self.nidx[q] ^ p for q in self.samples[r] for p in (0,)}  # placeholder
        # 直接实现：候选 c 必须对所有样本样本样本... 见下

    def detect_starts(self, min_tests=6):
        """扫描所有位置找记录起点：已知残差的全部约束必须满足，
        且至少 min_tests 个零约束被检验。"""
        res = []
        K = self.K
        nidx = self.nidx
        n = self.n
        # 预计算每个 p 需要检查的零位置（残差已知的）
        zero_offs = [6, 7, 8, 9, 25, 26]
        for p in range(0, n - 27):
            known = 0
            ok = True
            base = p % L
            for o in zero_offs:
                r = (base + o) % L
                if r in K:
                    known += 1
                    if nidx[p + o] != K[r]:
                        ok = False
                        break
            if not ok or known < 4:
                continue
            # 附加：+19 = 0x07（若残差已知）
            r19 = (base + 19) % L
            if r19 in K:
                known += 1
                if (nidx[p + 19] ^ K[r19]) != 0x07:
                    continue
            # 月（若已知残差且已确定）
            for o, allowed in ((20, MONTHS), (21, DAYS), (22, HOURS), (23, MINS), (24, MINS)):
                r = (base + o) % L
                if r in K and (nidx[p + o] ^ K[r]) not in allowed:
                    ok = False
                    break
            if not ok:
                continue
            res.append(p)
        return res

    def learn_from_starts(self, starts):
        """从已确认起点学习新残差：+19 恒 0x07；+25/+26 恒 0；
        +20..24 用候选集交集。"""
        for p in starts:
            self.fix(p + 19, self.nidx[p + 19] ^ 0x07, f"ts19@{p}")
            self.fix(p + 25, self.nidx[p + 25], f"extra25@{p}")
            self.fix(p + 26, self.nidx[p + 26], f"extra26@{p}")
        # 时间字段候选交集
        for o, allowed in ((20, MONTHS), (21, DAYS), (22, HOURS), (23, MINS), (24, MINS)):
            by_res = collections.defaultdict(set)
            for p in starts:
                q = p + o
                by_res[q % L] |= {self.nidx[q] ^ v for v in allowed}
            for r, c in by_res.items():
                if r not in self.K:
                    self.cand[r] &= c

    def learn_nul_from_chain(self, starts):
        """起点 p 若 p,p+1 残差已知 => 记录长 => 末尾 NUL 学习 + 下一起点验证。"""
        learned = 0
        for p in starts:
            r0, r1 = p % L, (p + 1) % L
            if r0 not in self.K or r1 not in self.K:
                continue
            rl = (self.nidx[p] ^ self.K[r0]) | ((self.nidx[p + 1] ^ self.K[r1]) << 8)
            if not (28 <= rl <= 8192) or p + rl > self.n:
                continue
            q = p + rl - 1
            try:
                self.fix(q, self.nidx[q], f"NUL@{p}")
                learned += 1
            except AssertionError:
                pass
        return learned

    def fill_by_candidates(self):
        """候选集唯一时确定。"""
        for r in range(L):
            if r not in self.K and len(self.cand[r]) == 1:
                self.K[r] = self.cand[r].pop()

    def verify_full(self, cnt):
        """全量解密并解析验证。"""
        key = [self.K.get(r) for r in range(L)]
        if any(v is None for v in key):
            return None, f"缺 {sum(1 for v in key if v is None)} 个残差"
        key = bytes(key)
        dec = bytes(c ^ key[i % L] for i, c in enumerate(self.nidx))
        pos = 0
        nrec = 0
        names = []
        while pos + 27 <= len(dec):
            rl = struct.unpack_from("<H", dec, pos)[0]
            if rl < 28 or pos + rl > len(dec):
                return key, f"解析失败 @0x{pos:x} rl={rl} ({nrec}/{cnt})"
            rec = dec[pos:pos+rl]
            off = struct.unpack_from("<Q", rec, 2)[0]
            raw, comp = struct.unpack_from("<II", rec, 10)
            nm = rec[27:]
            z = nm.find(0)
            if z != rl - 28:
                return key, f"名字NUL位置不对 @0x{pos:x}"
            names.append(nm[:z])
            pos += rl
            nrec += 1
        if nrec != cnt or pos != len(dec):
            return key, f"数量不符 {nrec}/{cnt} 或长度 {pos:#x}/{len(dec):#x}"
        return key, "OK"

def solve(old_path, new_path, verbose=True):
    ocnt, _, oidx = load_idx(old_path)
    ncnt, idxend, nidx = load_idx(new_path)
    orecs = parse_old(oidx)
    S = Solver(nidx)

    # --- 引导：假设新 record0 == 某个旧记录（名字+结构零+0x07+len）---
    booted = False
    for i, rec in enumerate(orecs[:3000]):
        nm = rec["name"]
        if any(b >= 0x80 for b in nm):
            continue
        rl0 = 28 + len(nm)
        try:
            S.fix(0, nidx[0] ^ (rl0 & 0xFF), "len0lo")
            S.fix(1, nidx[1] ^ (rl0 >> 8), "len0hi")
            for j in range(6, 10):
                S.fix(j, nidx[j], "zero")
            S.fix(19, nidx[19] ^ 0x07, "ts19")
            S.fix(25, nidx[25], "extra")
            S.fix(26, nidx[26], "extra")
            for j, ch in enumerate(nm):
                S.fix(27 + j, nidx[27 + j] ^ ch, "name")
        except AssertionError:
            # 回滚
            S = Solver(nidx)
            continue
        booted = True
        if verbose:
            print(f"引导成功：旧记录 #{i} name={nm[:36]!r}，已知 {len(S.K)} 残差")
        break
    if not booted:
        return None, None, "引导失败"

    # --- 迭代传播 ---
    for it in range(40):
        starts = S.detect_starts()
        S.learn_from_starts(starts)
        S.learn_nul_from_chain(starts)
        S.fill_by_candidates()
        if verbose:
            print(f"iter {it}: starts={len(starts)} known={len(S.K)}/200")
        if len(S.K) == 200:
            break
        if len(S.K) < 30 and it > 5:
            break
    key, msg = S.verify_full(ncnt)
    return key, S, msg

if __name__ == "__main__":
    OLD = r"F:\Game\Online\9yin\20230423\9yin\res\eff.package"
    NEW = r"F:\Game\Online\9yin\9yin\res\eff.package"
    _, _, oi = load_idx(OLD)
    _, _, ni = load_idx(NEW)
    TRUE = bytes(a ^ b for a, b in zip(oi, ni))[:200]

    key, S, msg = solve(OLD, NEW)
    print(f"\n验证: {msg}")
    if key:
        wrong = [(r, hex(key[r]), hex(TRUE[r])) for r in range(200) if key[r] != TRUE[r]]
        print("与真密钥比对:", "完全一致！" if not wrong else f"{len(wrong)} 个错误: {wrong[:10]}")
