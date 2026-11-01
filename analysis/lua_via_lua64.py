# -*- coding: utf-8 -*-
"""1) zlib 抽查验证 map_ini / lua64 新密钥
2) 用 lua64 已解密索引作已知明文攻击 lua（同名同序假设，掩码=名字/NUL/零/len）"""
import struct, collections, json, zlib
import numpy as np

OLD_ROOT = r"F:\Game\Online\9yin\20230423\9yin"
NEW_ROOT = r"F:\Game\Online\9yin\9yin"

def load_head_index(path):
    with open(path, "rb") as f:
        head = f.read(0x13)
        rsv, = struct.unpack_from("<H", head, 8)
        cnt, = struct.unpack_from("<I", head, 0x0A)
        idxend, = struct.unpack_from("<I", head, 0x0E)
        f.seek(0x13)
        return rsv, cnt, idxend, f.read(idxend - 0x13)

def decrypt_idx(nidx, key):
    P = len(key)
    C = np.frombuffer(nidx, np.uint8)
    tile = np.tile(np.frombuffer(key, np.uint8), len(C) // P + 1)[:len(C)]
    return (C ^ tile).tobytes()

def parse_dec(dec):
    recs, pos = [], 0
    while pos + 27 <= len(dec):
        rl = struct.unpack_from("<H", dec, pos)[0]
        if rl < 28 or pos + rl > len(dec) or dec[pos + rl - 1] != 0:
            return None
        recs.append((pos, dec[pos:pos + rl]))
        pos += rl
    return recs

keys = json.load(open(r"G:\pojie\ai\JiuYinUnpackTool\analysis\keys_norm.json"))

# ---- 1) zlib 验证 ----
for rel, khex in (("res\\map_ini.package", keys["c694"]), ("res\\lua64.package", keys["2696"])):
    rsv, cnt, en, nidx = load_head_index(NEW_ROOT + "\\" + rel.replace("res\\", "res\\"))
    p = NEW_ROOT + "\\" + rel.replace("res\\", "res\\")
    p = p.replace("res\\\\", "res\\")
    # 直接拼路径
    p = NEW_ROOT + rel.replace("res\\", "\\res\\") if False else None
    p = NEW_ROOT + "\\" + rel  # rel 形如 res\map_ini.package → F:\...\9yin\res\map_ini.package
    rsv, cnt, en, nidx = load_head_index(p)
    dec = decrypt_idx(nidx, bytes.fromhex(khex))
    recs = parse_dec(dec)
    whole = open(p, "rb").read()
    ok = fail = 0
    for pos, rec in recs[:40] + recs[-40:]:
        off = struct.unpack_from("<Q", rec, 2)[0]
        raw, comp = struct.unpack_from("<II", rec, 10)
        try:
            d = zlib.decompress(whole[off:off + comp])
            assert len(d) == raw
            ok += 1
        except Exception:
            fail += 1
    print(f"{rel}: 解析 {len(recs)}/{cnt} 条，zlib 抽查 {ok} OK / {fail} FAIL")

# ---- 2) lua 攻击：lua64 明文作 crib ----
rsv64, cnt64, _, nidx64 = load_head_index(NEW_ROOT + r"\res\lua64.package")
dec64 = decrypt_idx(nidx64, bytes.fromhex(keys["2696"]))
recs64 = parse_dec(dec64)
print(f"\nlua64 解析 {len(recs64)} 条（首名: {recs64[0][1][27:-1][:40]!r}）")

rsvL, cntL, _, nidxL = load_head_index(NEW_ROOT + r"\res\lua.package")
n = min(len(nidxL), len(dec64))
ks = np.frombuffer(bytes(a ^ b for a, b in zip(nidxL[:n], dec64[:n])), np.uint8)
# 掩码：名字+NUL（27..rl）、零（6..9,25,26）、len 字节（0..1，同名同长）
mask = np.zeros(n, bool)
for pos, rec in recs64:
    if pos + len(rec) > n:
        break
    mask[pos:pos + 2] = True     # len（名字相同 → 记录长相同）
    mask[pos+6:pos+10] = True
    mask[pos+25:pos+27] = True
    mask[pos+27:pos+len(rec)] = True
print(f"lua vs lua64: 对齐 {n} 字节，掩码 {int(mask.sum())}")

idx = np.nonzero(mask)[0]
res = []
for P in range(16, 4200):
    a = idx[idx + P < n]
    b = a + P
    both = a[mask[b]]
    if len(both) < 200:
        continue
    eq = np.count_nonzero(ks[both] == ks[both + P])
    res.append((eq / len(both), P))
res.sort(reverse=True)
print("lua 掩码自相关 top6:", [(round(r, 4), P) for r, P in res[:6]])

votes = collections.defaultdict(collections.Counter)
for pos, rec in recs64:
    if pos + len(rec) > n:
        break
    for j in [0, 1] + list(range(6, 10)) + [25, 26] + list(range(27, len(rec))):
        if mask[pos + j]:
            votes[(pos + j) % P][int(ks[pos + j])] += 1

def try_key(P):
    votes2 = collections.defaultdict(collections.Counter)
    for pos, rec in recs64:
        if pos + len(rec) > n:
            break
        for j in [0, 1] + list(range(6, 10)) + [25, 26] + list(range(27, len(rec))):
            votes2[(pos + j) % P][int(ks[pos + j])] += 1
    if any(len(votes2[r]) == 0 for r in range(P)):
        return None
    key = bytes(votes2[r].most_common(1)[0][0] for r in range(P))
    dec = decrypt_idx(nidxL, key)
    recs = parse_dec(dec)
    if recs and len(recs) == cntL:
        return key
    return None

for rate, P in res[:30]:
    fam = sorted(set([P] + [P // d for d in range(2, 80) if P % d == 0 and P // d >= 16]), reverse=True)
    for Pc in fam:
        key = try_key(Pc)
        if key:
            keys[f"{rsvL:04x}"] = key.hex()
            json.dump(keys, open(r"G:\pojie\ai\JiuYinUnpackTool\analysis\keys_norm.json", "w"), indent=1)
            print(f"\nlua 破解：P={Pc} (scan P={P})！密钥 0x{rsvL:04x} 已存")
            # 展示
            dec = decrypt_idx(nidxL, key)
            rr = parse_dec(dec)
            for pos, rec in rr[:4]:
                off = struct.unpack_from("<Q", rec, 2)[0]
                print(f"   off=0x{off:08x} {rec[27:-1].decode('gbk','replace')}")
            raise SystemExit(0)
print("\nlua 仍失败")
