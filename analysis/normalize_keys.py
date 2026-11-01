# -*- coding: utf-8 -*-
"""密钥表规范化：最小周期化 + rsv 一致性校验。
同时用旧包前几条记录名作备选 crib，给 lua 等顽固包最后的机会。"""
import struct, os, json
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

def minimal_period(key):
    P = len(key)
    for d in range(1, P + 1):
        if P % d == 0 and all(key[i] == key[i % d] for i in range(P)):
            return d
    return P

def parse_dec(dec, cnt):
    pos, nrec = 0, 0
    while pos + 27 <= len(dec):
        rl = struct.unpack_from("<H", dec, pos)[0]
        if rl < 28 or pos + rl > len(dec) or dec[pos + rl - 1] != 0:
            return None
        pos += rl
        nrec += 1
    return nrec if (nrec == cnt and pos == len(dec)) else None

keys = json.load(open(r"G:\pojie\ai\JiuYinUnpackTool\analysis\keys.json", encoding="utf-8"))
print(f"载入 {len(keys)} 密钥")

# 1) 最小周期化 + 重新验证
norm = {}
for rel, ent in sorted(keys.items()):
    key = bytes.fromhex(ent["key"])
    P0 = minimal_period(key)
    key0 = key[:P0]
    rsv, cnt, idxend, nidx = load_head_index(os.path.join(NEW_ROOT, rel))
    tile = np.tile(np.frombuffer(key0, np.uint8), len(nidx)//P0 + 1)[:len(nidx)]
    dec = (np.frombuffer(nidx, np.uint8) ^ tile).tobytes()
    nrec = parse_dec(dec, cnt)
    status = "OK" if nrec == cnt else f"FAIL({nrec}/{cnt})"
    print(f"{rel:<30} rsv=0x{rsv:04x} P={ent['P']}->{P0} {status}")
    if nrec == cnt:
        norm.setdefault(f"{rsv:04x}", key0.hex())

# 2) rsv 冲突检查
print(f"\n唯一 rsv 数: {len(norm)}")
json.dump(norm, open(r"G:\pojie\ai\JiuYinUnpackTool\analysis\keys_norm.json", "w"), indent=1)
print("规范密钥表 -> analysis/keys_norm.json (键为 rsv 4 位十六进制)")
