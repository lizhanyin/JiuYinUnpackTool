# -*- coding: utf-8 -*-
"""对每个新旧成对的包：用旧明文索引 XOR 新密文索引，检测周期 200 提取各包密钥。
并检查 rsv 字段与密钥的关系。"""
import struct, os

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

def longest_run_at_L(ks, L):
    run = best = 0
    for i in range(len(ks) - L):
        run = run + 1 if ks[i] == ks[i + L] else 0
        best = max(best, run)
    return best

def safe(b):
    return b.decode("gbk", "replace").encode("unicode_escape").decode("ascii")[:60]

keys = {}
old_pkgs = []
for dirpath, _, files in os.walk(OLD_ROOT):
    for f in files:
        if f.lower().endswith(".package"):
            old_pkgs.append(os.path.join(dirpath, f))

print(f"{'package':<28} {'oldcnt':>7} {'newcnt':>7} {'run@200':>8}  key-derived")
for op in sorted(old_pkgs):
    rel = os.path.relpath(op, OLD_ROOT)
    np_ = os.path.join(NEW_ROOT, rel)
    if not os.path.exists(np_):
        continue
    fo, ro, co, eo, oidx = load_head_index(op)
    fn, rn, cn, en, nidx = load_head_index(np_)
    if fn != 4:
        continue
    m = min(len(oidx), len(nidx))
    ks = bytes(a ^ b for a, b in zip(oidx[:m], nidx[:m]))
    run = longest_run_at_L(ks, 200)
    key = None
    if run >= 200:  # 至少一个完整周期可信
        key = ks[:200]
        keys[rel] = (rn, key)
        # 验证：解密新索引能走多远
        dec = bytes(c ^ key[i % 200] for i, c in enumerate(nidx))
        pos = nrec = 0
        while pos + 27 <= len(dec):
            rl = struct.unpack_from("<H", dec, pos)[0]
            if rl < 28 or pos + rl > len(dec):
                break
            pos += rl
            nrec += 1
        ok = "OK" if nrec == cn and pos == len(dec) else f"partial({nrec}/{cn},0x{pos:x}/0x{len(dec):x})"
        print(f"{rel:<28} {co:>7} {cn:>7} {run:>8}  {ok}")
    else:
        print(f"{rel:<28} {co:>7} {cn:>7} {run:>8}  (no full period)")

# rsv 与密钥的关系检查
print("\n== rsv vs key ==")
import collections
for rel, (rsv, key) in keys.items():
    s = sum(key) & 0xFFFF
    x = 0
    for b in key:
        x ^= b
    print(f"{rel:<28} rsv=0x{rsv:04x} sum(key)&FFFF=0x{s:04x} xor(key)=0x{x:02x} key[:8]={key[:8].hex()}")
