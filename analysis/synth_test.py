# -*- coding: utf-8 -*-
"""合成测试：用与真实包相同的统计特征生成索引 + 已知密钥加密，
运行 v5 求解流程，逐残差对比真值，定位投票缺陷。"""
import struct, random, collections
import numpy as np
import importlib.util

spec = importlib.util.spec_from_file_location("sv5", r"G:\pojie\ai\JiuYinUnpackTool\analysis\solve_v5.py")
sv5 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sv5)
L = 200

random.seed(42)
TRUE_KEY = bytes(random.randrange(256) for _ in range(L))

# 生成 1500 条记录，统计特征仿 ini.package：
# 偏移 < 20MB（大多 < 16MB），raw/comp < 16MB，ts 年 2013..2026
names = []
recs = b""
FILE_SIZE = 0x13a2ee6
for i in range(1500):
    name = f"res\\ini\\npc\\sub{i%7}\\fb{i:06d}.ini".encode()
    off = random.randrange(0x1000, 0x1400000)
    raw = random.randrange(10, 0x1000000)
    comp = random.randrange(8, max(9, raw))
    year = random.randrange(2013, 2027)
    mon = random.randrange(1, 13)
    day = random.randrange(1, 29)
    hour = random.randrange(0, 24)
    minut = random.randrange(0, 60)
    sec = random.randrange(0, 60)
    rec = struct.pack("<HQII", 28 + len(name), off, raw, comp)
    rec += struct.pack("<H", year) + bytes([mon, day, hour, minut, sec])
    rec += struct.pack("<H", 0)
    rec += name + b"\x00"
    recs += rec
idx = bytes(c ^ TRUE_KEY[i % L] for i, c in enumerate(recs))
print(f"合成索引 {len(idx)} 字节, {len(recs)} 条记录")

# ---- 跑求解流程（照搬 solve 的迭代部分，但加逐残差校验）----
S = sv5.Solver(idx)
sv5.bootstrap_prefix(S, b"res\\ini\\")
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

for it in range(30):
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
    solid()
    if len(S.K) == L:
        break

wrong = {r: (S.K[r], TRUE_KEY[r]) for r in S.K if S.K[r] != TRUE_KEY[r]}
missing = [r for r in range(L) if r not in S.K]
print(f"已知 {len(S.K)}/200, 错误 {len(wrong)}, 缺失 {len(missing)}")
print("错误残差 (求解值, 真值):", dict(list(wrong.items())[:20]))
print("缺失:", missing)

# 对错误残差：检查其票分布
for r in list(wrong)[:6]:
    tv = TRUE_KEY[r]
    print(f"  残差 {r}: 票={votes[r].most_common(4)} 真值票数={votes[r][tv]}")

# 真实起点统计：谁在给错误残差投票？
if wrong:
    r0_ = list(wrong)[0]
    cls = (r0_ - 19) % L
    starts, _ = S.detect()
    cl_starts = [p for p in starts.tolist() if p % L == cls]
    print(f"\n残差 {r0_} 的 +19 投票类 = {cls}，该类检出起点 {len(cl_starts)} 个")
    # 真实边界
    bounds = set()
    pos = 0
    while pos + 27 <= len(recs):
        rl = struct.unpack_from("<H", recs, pos)[0]
        bounds.add(pos)
        pos += rl
    for p in cl_starts[:10]:
        tag = "真" if p in bounds else ("影子" if (p+1 in bounds or p+2 in bounds) else "假")
        print(f"  p={p} ({tag}) +19字节位置={p+19} 明文应为={[recs[p+19]]} 投票值={int(S.C[p+19])^0x07}")
