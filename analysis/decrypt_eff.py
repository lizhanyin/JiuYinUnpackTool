# -*- coding: utf-8 -*-
"""用 eff 包前 503 字节周期性提取 200 字节密钥，解密全部包验证。"""
import struct

def load_index(path):
    with open(path, "rb") as f:
        head = f.read(0x13)
        cnt, = struct.unpack_from("<I", head, 0x0A)
        idxend, = struct.unpack_from("<I", head, 0x0E)
        f.seek(0x13)
        return cnt, idxend, f.read(idxend - 0x13)

OLD_EFF = r"F:\Game\Online\9yin\20230423\9yin\res\eff.package"
NEW_EFF = r"F:\Game\Online\9yin\9yin\res\eff.package"

_, _, oidx = load_index(OLD_EFF)
_, _, nidx = load_index(NEW_EFF)
ks = bytes(a ^ b for a, b in zip(oidx, nidx))
KEY = ks[:200]
print("KEY (200 bytes):")
for i in range(0, 200, 32):
    row = KEY[i:i+32]
    print(f"  {i:04x}: {row.hex(' ')}  {''.join(chr(c) if 32 <= c < 127 else '.' for c in row)}")

def decrypt(idx, key):
    return bytes(c ^ key[i % len(key)] for i, c in enumerate(idx))

def try_parse(dec, cnt, label):
    n = len(dec)
    pos = 0
    ok = 0
    names = []
    while pos + 27 <= n:
        rl = struct.unpack_from("<H", dec, pos)[0]
        if rl < 28 or pos + rl > n:
            print(f"  {label}: FAIL at pos 0x{pos:x} bad record len {rl}")
            return None
        rec = dec[pos:pos+rl]
        off = struct.unpack_from("<Q", rec, 2)[0]
        raw, comp = struct.unpack_from("<II", rec, 10)
        nm = rec[27:]
        z = nm.find(0)
        if z < 0:
            print(f"  {label}: FAIL no NUL in name at 0x{pos:x}")
            return None
        names.append(nm[:z])
        if ok < 3:
            print(f"    rec#{ok} len={rl} off=0x{off:x} raw={raw} comp={comp} ts={rec[18:25].hex()} name={nm[:z].decode('gbk','replace')}")
        ok += 1
        pos += rl
    print(f"  {label}: parsed {ok} records (expect {cnt}), consumed 0x{pos:x}/{n:#x} -> {'OK' if ok == cnt and pos == n else 'MISMATCH'}")
    return names

print("\n== 解密新 eff 索引 ==")
cnt, _, _ = load_index(NEW_EFF)
names_eff = try_parse(decrypt(nidx, KEY), cnt, "eff")

# 试 ini.package（另一个包，rsv 不同）
NEW_INI = r"G:\pojie\ai\JiuYinUnpackTool\res\new\ini.package"
OLD_INI = r"G:\pojie\ai\JiuYinUnpackTool\res\old\ini.package"
cnt, idxend, nini = load_index(NEW_INI)
print(f"\n== 用同一密钥试新 ini (cnt={cnt}) ==")
try_parse(decrypt(nini, KEY), cnt, "ini-same-key")

# ini 的已知明文：旧 ini 索引前若干条记录可能未变 -> 用旧明文 XOR 新密文看是否重现 KEY
_, _, oini = load_index(OLD_INI)
ks2 = bytes(a ^ b for a, b in zip(oini, nini))
match = sum(1 for i in range(min(200, len(ks2))) if ks2[i] == KEY[i])
print(f"\nini old^new 前 200 字节与 eff 密钥吻合数: {match}/200")
# 也检查 ini 自身周期性前缀
for L in (200,):
    run = best = 0
    for i in range(len(ks2) - L):
        run = run + 1 if ks2[i] == ks2[i + L] else 0
        best = max(best, run)
    print(f"ini keystream L={L} 最长相等 run: {best}")
