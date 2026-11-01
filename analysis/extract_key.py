# -*- coding: utf-8 -*-
"""提取 196 字节循环 XOR 密钥，检查整段密钥流的一致性。"""
import struct, collections

OLD = r"F:\Game\Online\9yin\20230423\9yin\res\eff.package"
NEW = r"F:\Game\Online\9yin\9yin\res\eff.package"

def load_index(path):
    with open(path, "rb") as f:
        f.seek(0x13)
        return f.read(0xe7c - 0x13)

ks = bytes(a ^ b for a, b in zip(load_index(OLD), load_index(NEW)))
n = len(ks)
L = 196

# 每个同余类内的众数及一致性
key = bytearray(L)
consist = [0.0] * L
for r in range(L):
    vals = ks[r::L]
    if not vals:
        continue
    c = collections.Counter(vals)
    v, cnt = c.most_common(1)[0]
    key[r] = v
    consist[r] = cnt / len(vals)

total = sum(consist) / L
print(f"period={L} overall consistency: {total:.4f}")
bad = [(r, f"{consist[r]:.2f}") for r in range(L) if consist[r] < 0.99]
print("inconsistent residue classes:", bad[:20], "..." if len(bad) > 20 else "")
print("key (196 bytes):")
for i in range(0, L, 32):
    row = bytes(key[i:i+32])
    print(f"  {i:04x}: {row.hex(' ')}  {''.join(chr(c) if 32 <= c < 127 else '.' for c in row)}")

# 找出密钥流中不符合周期的前缀区段（即明文不同的区段）
run_ok = ks[: L]
print("\nfirst-period keystream matches key:", run_ok == bytes(key))
# 逐段（每 196B 一段）检查
seg = (n + L - 1) // L
for s in range(seg):
    chunk = ks[s*L:(s+1)*L]
    kk = bytes(key[:len(chunk)])
    diffpos = [i for i in range(len(chunk)) if chunk[i] != kk[i]]
    print(f"segment {s} (abs 0x{0x13 + s*L:04x}): {'OK' if not diffpos else f'{len(diffpos)} diff at rel ' + str(diffpos[:8])}")
