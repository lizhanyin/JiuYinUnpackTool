# -*- coding: utf-8 -*-
"""map_ini 定向破解：37/74/148 周期 + 强化链式走。

关键改进（针对此前失败点）：
1. P 优先试最小（37）：残差少、每残差样本多
2. rl 搜索带最小记录长度（名字 >= 12 字符 → rl >= 40）——直接杀死 [28,29,30] 假幸存者
3. 名字区校验：可解残差处必须解出可打印字符；开头尽量匹配 "res\\"
4. crib 长度自适应：12..40 逐级试，pscan 命中数上升则接受
5. 每跳失败即回溯（深度限制），全量解析终审
"""
import struct, collections
import numpy as np

NEW = r"F:\Game\Online\9yin\9yin\res\map_ini.package"
OLD = r"F:\Game\Online\9yin\20230423\9yin\res\map_ini.package"

def load_head_index(path):
    with open(path, "rb") as f:
        head = f.read(0x13)
        rsv, = struct.unpack_from("<H", head, 8)
        cnt, = struct.unpack_from("<I", head, 0x0A)
        idxend, = struct.unpack_from("<I", head, 0x0E)
        f.seek(0x13)
        return rsv, cnt, idxend, f.read(idxend - 0x13)

def old_first_name(oidx):
    rl = struct.unpack_from("<H", oidx, 0)[0]
    nm = oidx[27:rl]
    return nm[:nm.find(0)]

def pscan_hits(C, KS, P):
    """已知绝对位置 KS{pos:val} 折叠 mod P 后的四连零命中数。"""
    n = len(C)
    kmod = {}
    for p_, v in KS.items():
        r = p_ % P
        if r in kmod and kmod[r] != v:
            return -1
        kmod[r] = v
    kv = np.full(P, -1, np.int32)
    for r, v in kmod.items():
        kv[r] = v
    pos = np.arange(n - 27, dtype=np.int64)
    ok = np.ones(len(pos), bool)
    for o in (6, 7, 8, 9):
        k = kv[(pos + o) % P]
        ok &= (k >= 0) & (C[pos + o].astype(np.int32) == k)
    return int(ok.sum())

rn, cn, en, nidx = load_head_index(NEW)
ro, co, eo, oidx = load_head_index(OLD)
C = np.frombuffer(nidx, np.uint8)
n = len(C)
name0_old = old_first_name(oidx)
print(f"map_ini: cnt={cn} idxlen=0x{n:x} rsv=0x{rn:04x}  旧rec0名={name0_old[:44]!r}")

# ---- crib 长度自适应（P=148 族下命中数应随正确 crib 增长而增长）----
base_KS = lambda L: {**{j: int(C[j]) for j in (6, 7, 8, 9, 25, 26)},
                     19: int(C[19]) ^ 0x07,
                     **{27 + j: int(C[27 + j]) ^ ch for j, ch in enumerate(name0_old[:L])}}
best_L, best_hits = 12, -1
for L in range(12, min(41, len(name0_old)) + 1):
    hits = pscan_hits(C, base_KS(L), 148)
    tag = ""
    if hits >= best_hits:
        if hits > best_hits:
            tag = " <- 更长 crib 仍成立"
        best_L, best_hits = L, hits
    else:
        tag = " (命中下降，名字在更早处分叉)"
        break
    print(f"  crib len={L}: P=148 命中 {hits}{tag}")
crib = name0_old[:best_L]
print(f"采用 crib 长度 {best_L}: {crib!r}")

MIN_RL = 40  # 名字 >= 12 字符（实测 map_ini 名字均为 res\map\ini\... 长路径）

def chain(P, verbose=False):
    K = {}
    for j, ch in enumerate(crib):
        r = (27 + j) % P
        if r in K and K[r] != (int(C[27 + j]) ^ ch):
            return None, "引导冲突"
        K[r] = int(C[27 + j]) ^ ch
    for j in (6, 7, 8, 9, 25, 26):
        K.setdefault(j % P, int(C[j]))
    K[19 % P] = int(C[19]) ^ 0x07
    votes = collections.defaultdict(collections.Counter)
    def learn(r, v, w=2):
        r %= P
        votes[r][v] += w
        t = votes[r].most_common(2)
        if t and t[0][1] >= 3 and (len(t) == 1 or t[0][1] >= 3 * t[1][1]):
            K[r] = t[0][0]
    for r, v in K.items():
        votes[r][v] += 9

    def name_ok(p, rl):
        """名字区校验：可解残差处必须可打印；NUL 位置残差已知时必须为 0。"""
        q = p + rl - 1
        if q >= n:
            return False
        rq = q % P
        if rq in K and (int(C[q]) ^ K[rq]) != 0:
            return False
        for j in range(27, rl - 1):
            r = (p + j) % P
            if r in K:
                pt = int(C[p + j]) ^ K[r]
                if not (0x20 <= pt < 0x7f or pt >= 0x80):
                    return False
        return True

    def next_zeros_ok(p1):
        for o in range(6, 10):
            r = (p1 + o) % P
            if r in K and (int(C[p1 + o]) ^ K[r]) != 0:
                return False
        return True

    p, hops = 0, 0
    while p + 27 <= n:
        r0, r1 = p % P, (p + 1) % P
        if r0 in K and r1 in K:
            rl = (int(C[p]) ^ K[r0]) | ((int(C[p + 1]) ^ K[r1]) << 8)
            if not (MIN_RL <= rl <= 8192) or p + rl > n or not name_ok(p, rl) or not next_zeros_ok(p + rl):
                return None, f"len 非法 @0x{p:x} rl={rl} (hops={hops}, known={len(K)}/{P})"
        else:
            surv = []
            for cand in range(MIN_RL, min(8193, n - p)):
                if not name_ok(p, cand):
                    continue
                if not next_zeros_ok(p + cand):
                    continue
                surv.append(cand)
                if len(surv) > 2:
                    break
            if len(surv) != 1:
                return None, f"rl 歧义 @0x{p:x}: {surv[:3]} (known={len(K)}/{P})"
            rl = surv[0]
            learn(r0, int(C[p]) ^ (rl & 0xFF))
            learn(r1, int(C[p + 1]) ^ ((rl >> 8) & 0xFF))
        for o in (6, 7, 8, 9, 25, 26):
            learn(p + o, int(C[p + o]))
        learn(p + 19, int(C[p + 19]) ^ 0x07, w=2)
        learn(p + rl - 1, int(C[p + rl - 1]), w=1)
        p += rl
        hops += 1
    if len(K) < P:
        return None, f"链走完但仅 {len(K)}/{P} 残差"
    key = bytes(K[r] for r in range(P))
    tile = np.tile(np.frombuffer(key, np.uint8), n // P + 1)[:n]
    dec = (C ^ tile).tobytes()
    pos2 = nrec = 0
    while pos2 + 27 <= len(dec):
        rl = struct.unpack_from("<H", dec, pos2)[0]
        if rl < 28 or pos2 + rl > len(dec) or dec[pos2 + rl - 1] != 0:
            return None, f"验证断 @0x{pos2:x} ({nrec})"
        pos2 += rl
        nrec += 1
    if nrec != cn or pos2 != len(dec):
        return None, f"数 {nrec}/{cn}"
    return key, f"OK {hops} 跳"

for P in (37, 74, 148, 296):
    key, msg = chain(P)
    print(f"P={P}: {msg}")
    if key:
        print("KEY:", key.hex())
        tile = np.tile(np.frombuffer(key, np.uint8), n // P + 1)[:n]
        dec = (C ^ tile).tobytes()
        pos, recs = 0, []
        while pos + 27 <= len(dec):
            rl = struct.unpack_from("<H", dec, pos)[0]
            recs.append(dec[pos:pos + rl]); pos += rl
        def show(rec):
            off = struct.unpack_from("<Q", rec, 2)[0]
            raw, comp = struct.unpack_from("<II", rec, 10)
            return f"off=0x{off:08x} raw={raw:8d} comp={comp:7d} {rec[27:-1].decode('gbk','replace')}"
        for r in recs[:4]:
            print("  ", show(r))
        print("   ...")
        for r in recs[-2:]:
            print("  ", show(r))
        # 存入密钥表
        import json
        keys = json.load(open(r"G:\pojie\ai\JiuYinUnpackTool\analysis\keys_norm.json"))
        keys[f"{rn:04x}"] = key.hex()
        json.dump(keys, open(r"G:\pojie\ai\JiuYinUnpackTool\analysis\keys_norm.json", "w"), indent=1)
        # 同步 jiuyin-keys.txt
        lines = []
        for k in sorted(keys):
            lines.append(f"{k}={keys[k]}")
        open(r"G:\pojie\ai\JiuYinUnpackTool\jiuyin-keys.txt", "w", encoding="utf-8").write(
            "# jiuyin-unpack index-encryption key table (flag=4 packages)\n"
            "# format: key_id(hex,u16 @header 0x08)=key hex(cyclic XOR, minimal period)\n"
            + "\n".join(lines) + "\n")
        print(f"\n密钥已写入 keys_norm.json 与 jiuyin-keys.txt（现 {len(keys)} 个）")
        break
