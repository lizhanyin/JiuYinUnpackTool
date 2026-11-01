# -*- coding: utf-8 -*-
"""批量破解：对每个 flag=4 包，用旧包做已知明文前缀。
ks = old_idx ^ new_idx；自相关找密钥周期；列众数校正；全量解析验证。"""
import struct, collections, os
import numpy as np

OLD_ROOT = r"F:\Game\Online\9yin\20230423\9yin"
NEW_ROOT = r"F:\Game\Online\9yin\9yin"

def load_head_index(path):
    with open(path, "rb") as f:
        head = f.read(0x13)
        flag, = struct.unpack_from("<H", head, 6)
        rsv, = struct.unpack_from("<H", head, 8)
        cnt, = struct.unpack_from("<I", head, 0x0A)
        idxend, = struct.unpack_from("<I", head, 0x0E)
        f.seek(0x13)
        return flag, rsv, cnt, idxend, f.read(idxend - 0x13)

def find_period(ks):
    """自相关：返回 (best_rate, best_P, 次优)"""
    a = np.frombuffer(ks, np.uint8)
    n = len(a)
    res = []
    for P in range(16, 4097):
        m = n - P
        if m < 400:
            break
        eq = np.count_nonzero(a[:m] == a[P:])
        res.append((eq / m, P))
    res.sort(reverse=True)
    return res[0], res[1] if len(res) > 1 else (0, 0)

def column_mode_key(ks, P):
    """按列众数提取密钥（容忍少数记录不同的污染）"""
    a = np.frombuffer(ks, np.uint8)
    usable = (len(a) // P) * P
    if usable == 0:
        return None
    m = a[:usable].reshape(-1, P)
    key = np.zeros(P, np.uint8)
    for c in range(P):
        vals, counts = np.unique(m[:, c], return_counts=True)
        key[c] = vals[np.argmax(counts)]
    return key.tobytes()

def decrypt(idx, key):
    L = len(key)
    tile = np.tile(np.frombuffer(key, np.uint8), len(idx) // L + 1)[:len(idx)]
    return (np.frombuffer(idx, np.uint8) ^ tile).tobytes()

def parse(dec, cnt):
    pos, nrec = 0, 0
    while pos + 27 <= len(dec):
        rl = struct.unpack_from("<H", dec, pos)[0]
        if rl < 28 or pos + rl > len(dec):
            return nrec, pos, f"@0x{pos:x} rl={rl}"
        if dec[pos + rl - 1] != 0:
            return nrec, pos, f"rec{nrec} 缺NUL @0x{pos:x}"
        pos += rl
        nrec += 1
    return nrec, pos, None if (nrec == cnt and pos == len(dec)) else f"数量 {nrec}/{cnt} 消费 0x{pos:x}/0x{len(dec):x}"

results = {}
pkgs = []
for dirpath, _, files in os.walk(NEW_ROOT):
    for f in files:
        if f.lower().endswith(".package"):
            rel = os.path.relpath(os.path.join(dirpath, f), NEW_ROOT)
            op = os.path.join(OLD_ROOT, rel)
            if os.path.exists(op):
                fn, rn, cn, en, nidx = load_head_index(os.path.join(dirpath, f))
                if fn == 4:
                    pkgs.append((rel, op, os.path.join(dirpath, f), cn, nidx, rn))

print(f"flag=4 且旧包存在: {len(pkgs)} 个\n")
ok_keys = {}
for rel, op, np_, cn, nidx, rn in sorted(pkgs):
    fo, ro, co, eo, oidx = load_head_index(op)
    m = min(len(oidx), len(nidx))
    ks = bytes(a ^ b for a, b in zip(oidx[:m], nidx[:m]))
    (r1, P1), (r2, _) = find_period(ks)
    if r1 < 0.5:
        print(f"{rel:<28} rsv=0x{rn:04x} 最佳周期 {P1} 匹配率仅 {r1:.2f} -> 前缀记录已变，跳过")
        continue
    key = column_mode_key(ks, P1)
    nrec, pos, err = parse(decrypt(nidx, key), cn)
    if err is None:
        # 严格列一致性
        a = np.frombuffer(ks[: (len(ks)//P1)*P1], np.uint8).reshape(-1, P1)
        agree = np.mean([np.mean(a[:, c] == key[c]) for c in range(P1)])
        print(f"{rel:<28} rsv=0x{rn:04x} P={P1:<5} 匹配率={r1:.3f} 列一致={agree:.3f} -> OK ({nrec} 条)")
        ok_keys[rel] = (rn, P1, key.hex())
    else:
        # 试试次优周期或更长前缀校正
        fixed = False
        for P2 in {P1, P1 // 2 if P1 % 2 == 0 else 0}:
            if P2 < 16:
                continue
            key2 = column_mode_key(ks, P2)
            nrec2, pos2, err2 = parse(decrypt(nidx, key2), cn)
            if err2 is None:
                print(f"{rel:<28} rsv=0x{rn:04x} P={P2} (修正) -> OK ({nrec2} 条)")
                ok_keys[rel] = (rn, P2, key2.hex())
                fixed = True
                break
        if not fixed:
            print(f"{rel:<28} rsv=0x{rn:04x} P={P1} 匹配率={r1:.3f} -> 解析失败: {err}")

print(f"\n成功: {len(ok_keys)}/{len(pkgs)}")
import json
with open(r"G:\pojie\ai\JiuYinUnpackTool\analysis\keys.json", "w") as f:
    json.dump(ok_keys, f, indent=1)
print("密钥已存 analysis/keys.json")
