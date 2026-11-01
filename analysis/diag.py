# -*- coding: utf-8 -*-
"""诊断：执行 v5 流程，检查残差置信度与 record0。"""
import struct, collections
import numpy as np
import importlib.util

spec = importlib.util.spec_from_file_location("sv5", r"G:\pojie\ai\JiuYinUnpackTool\analysis\solve_v5.py")
sv5 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sv5)

NEW = r"G:\pojie\ai\JiuYinUnpackTool\res\new\ini.package"
L = 200
ncnt, idxend, nidx = sv5.load_idx(NEW)
S = sv5.Solver(nidx)
sv5.bootstrap_prefix(S, b"res\\ini\\npc\\")
votes = collections.defaultdict(collections.Counter)
for r, v in S.K.items():
    votes[r][v] += 9

def solid():
    for r, c in votes.items():
        if r in S.K:
            continue
        top2 = c.most_common(2)
        if top2 and top2[0][1] >= 3 and (len(top2) == 1 or top2[0][1] >= 3 * top2[1][1]):
            S.K[r] = top2[0][0]

for it in range(10):
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

print("已知残差:", len(S.K))
print("缺失:", [r for r in range(L) if r not in S.K])
sus = []
for r in range(L):
    c = votes[r]
    if len(c) > 1:
        t = c.most_common(2)
        if t[0][1] < 3 * t[1][1]:
            sus.append((r, t[:2]))
print("低置信:", sus[:15])

k = S.keyarr()
tile = np.tile(np.where(k >= 0, k, 0).astype(np.uint8), S.n // L + 1)[:S.n]
D = (S.C ^ tile).tobytes()
rl = struct.unpack_from("<H", D, 0)[0]
print("record0 len =", rl, " K[0]=", S.K.get(0), " K[1]=", S.K.get(1))
print("record0 头 60B:", D[:60].hex(" "))
if 28 <= rl <= 300:
    print("record0 name:", D[27:rl-1])
# 检查 K[0]/K[1] 是否从未被投票
print("votes[0]:", votes[0].most_common(3), " votes[1]:", votes[1].most_common(3))
