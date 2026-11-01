# -*- coding: utf-8 -*-
"""用 60 字节密钥全量验证 ini 索引。"""
import struct
import numpy as np

KEY60 = bytes.fromhex(
    '23aa67753dd57541ce568b76267acad90e502ef3b62856f95fcd135dcd82b230'
    '6abd0a3e3aa544e8834d6dbf38aebde52966a524ed339acb8b2ea44d')

def load(path):
    with open(path, "rb") as f:
        head = f.read(0x13)
        cnt = struct.unpack_from("<I", head, 0x0A)[0]
        idxend = struct.unpack_from("<I", head, 0x0E)[0]
        f.seek(0x13)
        return cnt, idxend, f.read(idxend - 0x13)

def decrypt(idx, key):
    L = len(key)
    tile = np.tile(np.frombuffer(key, np.uint8), len(idx) // L + 1)[:len(idx)]
    return (np.frombuffer(idx, np.uint8) ^ tile).tobytes()

def parse(dec, cnt):
    pos, nrec, recs, bad = 0, 0, [], None
    while pos + 27 <= len(dec):
        rl = struct.unpack_from("<H", dec, pos)[0]
        if rl < 28 or pos + rl > len(dec):
            bad = f"@0x{pos:x} rl={rl}"
            break
        if dec[pos + rl - 1] != 0:
            bad = f"rec{nrec} 缺NUL @0x{pos:x}"
            break
        recs.append(dec[pos:pos + rl])
        pos += rl
        nrec += 1
    return nrec, pos, recs, bad

cnt, idxend, nidx = load(r"G:\pojie\ai\JiuYinUnpackTool\res\new\ini.package")
dec = decrypt(nidx, KEY60)
nrec, pos, recs, bad = parse(dec, cnt)
print(f"解析 {nrec} 条（声明 {cnt}），消费 0x{pos:x}/0x{len(dec):x}，错误: {bad}")

def show(rec):
    off = struct.unpack_from("<Q", rec, 2)[0]
    raw, comp = struct.unpack_from("<II", rec, 10)
    return (f"off=0x{off:08x} raw={raw:8d} comp={comp:7d} ts={rec[18:25].hex()} "
            f"{rec[27:-1].decode('gbk','replace')}")

for r in recs[:6]:
    print(" ", show(r))
print("  ...")
for r in recs[-3:]:
    print(" ", show(r))

ocnt, oidxend, oidx = load(r"G:\pojie\ai\JiuYinUnpackTool\res\old\ini.package")
_, _, orecs, _ = parse(oidx, ocnt)
oldnames = {r[27:-1] for r in orecs}
newnames = {r[27:-1] for r in recs}
inter = oldnames & newnames
print(f"\n名字：旧 {len(oldnames)} / 新 {len(newnames)} / 交集 {len(inter)}"
      f"（保留 {len(inter)*100//len(oldnames)}%，新增 {len(newnames)-len(inter)}）")
# 数据块抽查：头 3 条 + 最后 1 条 zlib 解压验证
import zlib
with open(r"G:\pojie\ai\JiuYinUnpackTool\res\new\ini.package", "rb") as f:
    whole = f.read()
ok = fail = 0
for r in recs[:50] + recs[-50:]:
    off = struct.unpack_from("<Q", r, 2)[0]
    raw, comp = struct.unpack_from("<II", r, 10)
    blob = whole[off:off + comp]
    try:
        data = zlib.decompress(blob)
        assert len(data) == raw
        ok += 1
    except Exception as e:
        fail += 1
        print("  解压失败:", show(r), e)
print(f"zlib 抽查: {ok} 成功 / {fail} 失败")
