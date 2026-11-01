# -*- coding: utf-8 -*-
"""结构性密钥求解器：仅凭"新包密文 + 旧包已知明文crib + 记录结构约束"恢复 200 字节循环 XOR 密钥。
先在 eff 上自验证（答案已知），然后用于 ini。

原理：
- 索引区连续 XOR 200 字节循环密钥（已由 eff/icon 验证）
- 记录 0 起始位置 = 0（已知）
- 每条记录 +6..+9 恒 0（u64 偏移高 4 字节），+25..+26 恒 0（extra，.package）
- 记录 +27 起是 NUL 结尾 GBK 文件名（绝大多数纯 ASCII 0x20..0x7E）
- 用已知密钥残差扫描全索引找其它记录起点，逐步补全 200 个残差
"""
import struct, collections, sys

def load_idx(path):
    with open(path, "rb") as f:
        head = f.read(0x13)
        cnt, = struct.unpack_from("<I", head, 0x0A)
        idxend, = struct.unpack_from("<I", head, 0x0E)
        f.seek(0x13)
        return cnt, idxend, f.read(idxend - 0x13)

def parse_old(idx):
    recs = []
    pos = 0
    while pos + 27 <= len(idx):
        rl = struct.unpack_from("<H", idx, pos)[0]
        rec = idx[pos:pos+rl]
        nm = rec[27:]
        z = nm.find(0)
        recs.append(dict(pos=pos, len=rl, name=nm[:z]))
        pos += rl
    return recs

L = 200

def solve(old_path, new_path, verbose=True):
    ocnt, _, oidx = load_idx(old_path)
    ncnt, idxend, nidx = load_idx(new_path)
    orecs = parse_old(oidx)

    key = {}  # residue -> byte value

    def learn(r, v, src):
        r %= L
        if r in key and key[r] != v:
            if verbose:
                print(f"  !! conflict at residue {r}: {key[r]:02x} vs {v:02x} (src {src})")
            return False
        if r not in key:
            key[r] = v
        return True

    # --- 阶段 0：用旧记录名作为 record0 crib 引导 ---
    boot_ok = False
    for cand_i in range(min(20, len(orecs))):
        nm = orecs[cand_i]["name"]
        rl0 = 28 + len(nm)
        # 假设新 record0 与旧记录 cand_i 相同（名字部分）
        # K[27+j] = new[27+j] ^ nm[j]
        k = dict(key)
        ok = True
        for j, ch in enumerate(nm):
            r = (27 + j) % L
            v = nidx[27 + j] ^ ch
            if r in k and k[r] != v:
                ok = False
                break
            k[r] = v
        if not ok:
            continue
        # record0 长度字段：K[0..2) = new[0..2) ^ rl0_le（若 rl0<200 则残差 0,1）
        k[0] = nidx[0] ^ (rl0 & 0xFF)
        k[1] = nidx[1] ^ ((rl0 >> 8) & 0xFF)
        # +6..9 零，+25..26 零
        for j in range(6, 10):
            k[j] = nidx[j]
        for j in (25, 26):
            k[j] = nidx[j]
        key = k
        boot_ok = True
        if verbose:
            print(f"引导：旧记录 #{cand_i} name={nm[:30]!r}... -> 残差 {len(key)} 个已知")
        break
    if not boot_ok:
        print("引导失败：前 20 个旧记录名均不匹配")
        return None, None

    # --- 阶段 1：迭代扫描记录起点 ---
    for round_ in range(8):
        before = len(key)
        # 1a. 扫描所有位置 p，若 (p+6..p+9) 和 (p+25,p+26) 残差已知则校验零
        #     收集通过校验的记录起点
        starts = []
        n = len(nidx)
        for p in range(0, n - 27):
            rs = [ (p+6)%L, (p+7)%L, (p+8)%L, (p+9)%L ]
            if not all(r in key for r in rs):
                continue
            if any(nidx[p+6+j] != key[(p+6+j)%L] for j in range(4)):
                continue
            # extra=0（若残差已知）
            r25, r26 = (p+25)%L, (p+26)%L
            extra_ok = True
            for j, r in ((25,r25),(26,r26)):
                if r in key and nidx[p+j] != key[r]:
                    extra_ok = False
            if not extra_ok:
                continue
            starts.append(p)
        if verbose:
            print(f"round {round_}: 扫描到 {len(starts)} 个候选记录起点")
        # 1b. 对每个起点，尝试解出长度并学习新残差
        for p in starts:
            r0, r1 = p % L, (p+1) % L
            if r0 in key and r1 in key:
                rl = nidx[p] ^ key[r0] | ((nidx[p+1] ^ key[r1]) << 8)
                if 28 <= rl <= 4096 and p + rl <= n:
                    # 名名区 NUL 与 ASCII 约束
                    ok = True
                    for j in range(rl - 27):
                        r = (p + 27 + j) % L
                        b = nidx[p + 27 + j]
                        if r in key:
                            pt = b ^ key[r]
                            if j == rl - 28:
                                if pt != 0: ok = False; break
                            elif not (0x20 <= pt < 0x7f or pt >= 0x80):
                                ok = False; break
                    if ok:
                        # 学：NUL 位置 + 名字区（纯ASCII部分）通过统计收敛
                        # NUL at p+rl-1
                        learn(p + rl - 1, nidx[p + rl - 1], f"NUL@{p}")
        # 1c. 名字区 ASCII 约束投票未知残差
        for p in starts:
            pass
        # 用所有起点之后 27.. 的 ASCII 先验：对每个未知残差 r 收集
        # 它在名字区出现的样本，候选值必须使全部样本解出 <0x80
        cands = {r: set(range(256)) for r in range(L) if r not in key}
        for r in list(cands):
            samples = []
            for p in range(n):
                pass
            break
        # 直接进入下一轮之前，用 starts 学到的 NUL 残差扩展后重扫
        if len(key) == before:
            if verbose:
                print(f"round {round_}: 无新增残差（共 {len(key)}/200），停止")
            break

    return key, nidx

def ascii_vote(key, nidx, starts):
    """对未知残差用 ASCII 约束（名字区）+ 已知区上下文推断。"""
    n = len(nidx)
    for it in range(6):
        unknown = [r for r in range(L) if r not in key]
        if not unknown:
            break
        # 找高置信名字区：起点 p（已知）后 27.. 直到 NUL（用已知残差判断）
        name_regions = []
        for p in starts:
            r0, r1 = p % L, (p+1) % L
            if r0 not in key or r1 not in key:
                continue
            rl = nidx[p] ^ key[r0] | ((nidx[p+1] ^ key[r1]) << 8)
            if 28 <= rl <= 4096 and p + rl <= n:
                name_regions.append((p + 27, p + rl - 1))
        cand_sets = {r: None for r in unknown}
        votes = {r: collections.Counter() for r in unknown}
        for (s, e) in name_regions:
            for q in range(s, e):
                r = q % L
                if r in key:
                    continue
                # ASCII 假设：pt = nidx[q]^K <0x7f，且大多 >=0x20；GBK 双字节>=0x80 少数
                votes[r][nidx[q]]  # 记录密文字节
        # 对每个未知残差：候选 K 值 = c 使得大多数样本 c^nidx[q] 为 ASCII 可打印
        for r in unknown:
            samples = []
            for (s, e) in name_regions:
                for q in range(s, e):
                    if q % L == r:
                        samples.append(nidx[q])
            if not samples:
                continue
            best, bestscore = None, -1
            for c in range(256):
                score = sum(1 for s_ in samples if 0x20 <= (s_ ^ c) < 0x7f)
                if score > bestscore:
                    bestscore, best = score, c
            frac = bestscore / len(samples)
            if frac >= 0.90 and len(samples) >= 8:
                key[r] = best
        # 若仍有未知残差，进入下一轮（starts 会增多）
        if all(r in key for r in range(L)):
            break
        # 重新扫描 starts
        starts = rescan(key, nidx)
    return key

def rescan(key, nidx):
    n = len(nidx)
    starts = []
    for p in range(0, n - 27):
        rs = [(p+6+j) % L for j in range(4)]
        if all(r in key for r in rs):
            if all(nidx[p+6+j] == key[(p+6+j)%L] for j in range(4)):
                starts.append(p)
    return starts

if __name__ == "__main__":
    OLD = r"F:\Game\Online\9yin\20230423\9yin\res\eff.package"
    NEW = r"F:\Game\Online\9yin\9yin\res\eff.package"
    # 已知真密钥（用于验证）
    _, _, oi = load_idx(OLD)
    _, _, ni = load_idx(NEW)
    TRUEKEY = bytes(a ^ b for a, b in zip(oi, ni))[:200]

    key, nidx = solve(OLD, NEW, verbose=True)
    if key is None:
        sys.exit(1)
    starts = rescan(key, nidx)
    print(f"\n引导+零约束后已知残差 {len(key)}/200，候选起点 {len(starts)}")
    key = ascii_vote(key, nidx, starts)
    print(f"ASCII 投票后已知残差 {len(key)}/200")
    bad = [(r, f"{key[r]:02x}", f"{TRUEKEY[r]:02x}") for r in sorted(key) if key[r] != TRUEKEY[r]]
    print("错误残差:", bad if bad else "无！全部正确" if len(key) == 200 else f"(还有 {200-len(key)} 个未解)")
    for r in range(L):
        if r not in key:
            print(f"  未解残差 {r}: 真值 {TRUEKEY[r]:02x}")
