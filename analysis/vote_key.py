# -*- coding: utf-8 -*-
"""结构化已知明文投票：
- 解析旧包索引的记录边界（record lens）
- 假设 A：密钥按绝对位置循环（pos % L）
- 假设 B：密钥按记录内相对位置循环（每条记录重置，j % L）
已知明文来源：文件名字节 + u64 偏移高 4 字节恒 0 + 小尺寸的高位字节 0 + extra=0。
对每个密钥下标收集票数，取众数。"""
import struct, collections

OLD = r"F:\Game\Online\9yin\20230423\9yin\res\eff.package"
NEW = r"F:\Game\Online\9yin\9yin\res\eff.package"
IDX_LEN = 0xe7c - 0x13

def load(path):
    with open(path, "rb") as f:
        f.seek(0x13)
        return f.read(IDX_LEN)

old, new = load(OLD), load(NEW)
ks = bytes(a ^ b for a, b in zip(old, new))

# 解析旧索引记录
recs = []
pos = 0
while pos + 27 <= IDX_LEN:
    rl = struct.unpack_from("<H", old, pos)[0]
    recs.append((pos, rl))
    pos += rl
assert pos == IDX_LEN, hex(pos)
print(f"records: {len(recs)}")

L = 196
def vote(hypothesis):
    # votes[key_index][value] = count
    votesA = [collections.Counter() for _ in range(L)]
    votesB = [collections.Counter() for _ in range(L)]
    for (start, rl) in recs:
        rec = old[start:start+rl]
        known = {}  # rec-relative j -> plaintext byte
        for j in (6, 7, 8, 9):          # u64 高 4 字节恒 0
            known[j] = 0
        raw = struct.unpack_from("<I", rec, 10)[0]
        comp = struct.unpack_from("<I", rec, 14)[0]
        if raw < 0x10000:
            known[12] = 0; known[13] = 0
        if comp < 0x10000:
            known[16] = 0; known[17] = 0
        known[25] = 0; known[26] = 0    # extra u16 = 0（普通包）
        name = rec[27:]
        nul = name.index(0)
        for j, b in enumerate(name[:nul]):
            known[27 + j] = b           # 文件名字节
        for j, pt in known.items():
            if start + j >= IDX_LEN:
                continue
            c = ks[start + j]
            votesA[(start + j) % L][c] += 1
            votesB[j % L][c] += 1
    return votesA, votesB

votesA, votesB = vote(None)
for name, votes in (("A: 绝对位置 mod L", votesA), ("B: 记录内位置 mod L", votesB)):
    strong = 0
    for r in range(L):
        if not votes[r]:
            continue
        v, c = votes[r].most_common(1)[0]
        tot = sum(votes[r].values())
        if c >= 3 and c / tot >= 0.9:
            strong += 1
    print(f"假设 {name}: 强一致密钥字节 {strong}/{L}")

# 输出假设 A 的密钥（若强）
def dump_key(votes, label):
    key = bytearray(L)
    strong = 0
    for r in range(L):
        if votes[r]:
            v, c = votes[r].most_common(1)[0]
            key[r] = v
            tot = sum(votes[r].values())
            if c >= 3 and c / tot >= 0.9:
                strong += 1
        else:
            key[r] = 0
    print(f"\n{label}: strong={strong}/{L}")
    for i in range(0, L, 32):
        row = bytes(key[i:i+32])
        print(f"  {i:04x}: {row.hex(' ')}  {''.join(chr(c) if 32 <= c < 127 else '.' for c in row)}")
    return bytes(key)

keyA = dump_key(votesA, "假设A密钥")
keyB = dump_key(votesB, "假设B密钥")

# 用假设 A 密钥解密新索引前几个记录，看结构
print("\n用假设A解密新索引前 3 条记录:")
dec = bytes(c ^ keyA[i % L] for i, c in enumerate(new))
pos = 0
for k in range(3):
    rl = struct.unpack_from("<H", dec, pos)[0]
    rec = dec[pos:pos+rl]
    off = struct.unpack_from("<Q", rec, 2)[0]
    raw, comp = struct.unpack_from("<II", rec, 10)
    ts = rec[18:25].hex()
    print(f"  rec#{k} len={rl} off=0x{off:x} raw={raw} comp={comp} ts={ts} name={rec[27:].split(b'0')[0][:40]!r}")
    pos += rl
