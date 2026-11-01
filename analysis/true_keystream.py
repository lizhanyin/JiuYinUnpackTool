# -*- coding: utf-8 -*-
"""读取 ini 真实密钥流：新前 N 条记录若与旧包相同，则
K_true[pos] = C_new[pos] ^ pt_old[pos]。逐记录推导，自相关找周期。"""
import struct
import importlib.util
spec = importlib.util.spec_from_file_location("sv6", r"G:\pojie\ai\JiuYinUnpackTool\analysis\solve_v6.py")
sv6 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sv6)

OLD = r"G:\pojie\ai\JiuYinUnpackTool\res\old\ini.package"
NEW = r"G:\pojie\ai\JiuYinUnpackTool\res\new\ini.package"
_, ocnt, _, oidx = sv6.load_idx(OLD)
_, ncnt, _, nidx = sv6.load_idx(NEW)

# 旧前 N 条记录（假定新旧同序同内容）
N = 400
osegs = []
pos = 0
for _ in range(N):
    if pos + 27 > len(oidx):
        break
    rl = struct.unpack_from("<H", oidx, pos)[0]
    osegs.append((pos, rl))
    pos += rl
print(f"旧前 {len(osegs)} 条记录，覆盖 0x{pos:x} 字节")

# 候选密钥流：逐段 C_new ^ pt_old
seg_len = sum(rl for _, rl in osegs)
KS = bytearray(seg_len)
for p, rl in osegs:
    for j in range(rl):
        KS[p + j] = nidx[p + j] ^ oidx[p + j]

# 自相关：找周期 P 使 KS[i]==KS[i+P] 的比例高
n = len(KS)
print(f"\n密钥流长度 {n}")
results = []
for P in range(50, 4001):
    m = n - P
    if m < 200:
        break
    eq = sum(1 for i in range(m) if KS[i] == KS[i + P])
    results.append((eq / m, P))
results.sort(reverse=True)
for frac, P in results[:10]:
    print(f"  P={P}: 匹配率 {frac:.4f}")

# 也检查与已知 K[0..199] 的一致性（前 200 字节）
best_P = results[0][1]
print(f"\n最佳周期 {best_P}")
# 打印密钥流前 256 字节
print("KS[0:256]:")
for i in range(0, 256, 32):
    print(f"  {i:04x}: {bytes(KS[i:i+32]).hex(' ')}")
# 200 周期段对比
print("\nKS[0:64] vs KS[200:264] 相同字节数:",
      sum(1 for i in range(64) if KS[i] == KS[200 + i]))
print("KS[0:64] vs KS[best_P:best_P+64] 相同字节数:",
      sum(1 for i in range(64) if KS[i] == KS[best_P + i]))
