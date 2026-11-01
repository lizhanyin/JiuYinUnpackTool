# -*- coding: utf-8 -*-
"""最终清点：全部 flag=4 包 vs 密钥表；缺的自动攻坚；zlib 终验。"""
import struct, collections, json, zlib, os
import numpy as np

OLD_ROOT = r"F:\Game\Online\9yin\20230423\9yin"
NEW_ROOT = r"F:\Game\Online\9yin\9yin"
MONTHS = np.zeros(256, bool); MONTHS[1:13] = True
DAYS = np.zeros(256, bool); DAYS[1:32] = True
HRS = np.zeros(256, bool); HRS[:24] = True
MNS = np.zeros(256, bool); MNS[:60] = True

def load_head_index(path):
    with open(path, "rb") as f:
        head = f.read(0x13)
        flag, = struct.unpack_from("<H", head, 6)
        rsv, = struct.unpack_from("<H", head, 8)
        cnt, = struct.unpack_from("<I", head, 0x0A)
        idxend, = struct.unpack_from("<I", head, 0x0E)
        f.seek(0x13)
        return flag, rsv, cnt, idxend, f.read(idxend - 0x13)

def parse_plain(idx):
    recs, pos = [], 0
    while pos + 27 <= len(idx):
        rl = struct.unpack_from("<H", idx, pos)[0]
        if rl < 28 or pos + rl > len(idx):
            break
        recs.append((pos, rl, idx[pos + 27:pos + rl - 1]))
        pos += rl
    return recs

keys = json.load(open(r"G:\pojie\ai\JiuYinUnpackTool\analysis\keys_norm.json"))
print(f"密钥表: {len(keys)} 个")

# 扫描新客户端
flag4 = []
for dirpath, _, files in os.walk(NEW_ROOT):
    for f in files:
        if f.lower().endswith(".package"):
            p = os.path.join(dirpath, f)
            flag, rsv, cnt, idxend, _ = load_head_index(p)
            if flag == 4:
                flag4.append((os.path.relpath(p, NEW_ROOT), rsv, cnt, idxend))
print(f"flag=4 包: {len(flag4)} 个")
have, miss = [], []
for rel, rsv, cnt, idxend in sorted(flag4):
    (have if f"{rsv:04x}" in keys else miss).append((rel, rsv, cnt))
print(f"密钥表覆盖: {len(have)}，缺: {len(miss)}")
for rel, rsv, cnt in miss:
    print(f"  缺: {rel} rsv=0x{rsv:04x} cnt={cnt}")

# zlib 终验 lua / text
for rel in (r"res\lua.package", r"res\text.package"):
    p = NEW_ROOT + "\\" + rel
    flag, rsv, cnt, idxend, nidx = load_head_index(p)
    key = bytes.fromhex(keys[f"{rsv:04x}"])
    P = len(key)
    C = np.frombuffer(nidx, np.uint8)
    tile = np.tile(np.frombuffer(key, np.uint8), len(C) // P + 1)[:len(C)]
    dec = (C ^ tile).tobytes()
    recs = parse_plain(dec)
    whole = open(p, "rb").read()
    ok = fail = 0
    for pos, rl, nm in recs[:50] + recs[-50:]:
        off = struct.unpack_from("<Q", dec, pos + 2)[0]
        raw, comp = struct.unpack_from("<II", dec, pos + 10)
        try:
            d = zlib.decompress(whole[off:off + comp])
            assert len(d) == raw
            ok += 1
        except Exception:
            fail += 1
    print(f"zlib 终验 {rel}: {len(recs)}/{cnt} 条, 抽查 {ok} OK / {fail} FAIL")

# 对缺失包攻坚（无旧包 -> 文件名前缀 crib + 宽松迭代 + 链 + 重建）
def solve_generic(nidx, cn, crib, P):
    C = np.frombuffer(nidx, np.uint8)
    n = len(C)
    K0 = {}
    for j, ch in enumerate(crib):
        K0[(27 + j) % P] = int(C[27 + j]) ^ ch
    for j in (6, 7, 8, 9, 25, 26):
        K0[j % P] = int(C[j])
    K0[19] = int(C[19]) ^ 0x07
    # rl0 未知 -> 由链的 NUL 搜索补
    def karr(K):
        kv = np.full(P, -1, np.int32)
        for r, v in K.items():
            kv[r] = v
        return kv
    def loose_fill(K):
        K = dict(K)
        votes = collections.defaultdict(collections.Counter)
        for r, v in K.items():
            votes[r][v] += 9
        for it in range(25):
            kv = karr(K)
            known = kv >= 0
            det = np.zeros(P, bool)
            for c in range(P):
                if known[(c+6)%P] and known[(c+7)%P] and known[(c+8)%P] and known[(c+9)%P]:
                    det[c] = True
            if not det.any():
                break
            tile = np.tile(np.where(known, kv, 0).astype(np.uint8), n // P + 1)[:n]
            D = C ^ tile
            p = np.arange(n - 27, dtype=np.int64)
            p = p[det[p % P]]
            p = p[(D[p+6] | D[p+7] | D[p+8] | D[p+9]) == 0]
            for o, want in ((19, 0x07), (25, 0), (26, 0)):
                chk = known[(p + o) % P]
                if chk.any():
                    v = D[p[chk] + o]
                    ok2 = np.ones(len(p), bool)
                    ok2[chk] = (v == want)
                    p = p[ok2]
            for o, tbl in ((20, MONTHS), (21, DAYS), (22, HRS), (23, MNS), (24, MNS)):
                chk = known[(p + o) % P]
                if chk.any():
                    v = D[p[chk] + o]
                    ok2 = np.ones(len(p), bool)
                    ok2[chk] = tbl[v]
                    p = p[ok2]
            for pp in p.tolist():
                c = pp % P
                votes[(c+19) % P][int(C[pp+19]) ^ 0x07] += 2
                votes[(c+25) % P][int(C[pp+25])] += 1
                votes[(c+26) % P][int(C[pp+26])] += 1
            before = len(K)
            for r, cc in votes.items():
                if r in K:
                    continue
                t = cc.most_common(2)
                if t and t[0][1] >= 2 and (len(t) == 1 or t[0][1] >= 1.5 * t[1][1]):
                    K[r] = t[0][0]
            if len(K) == P or len(K) == before:
                break
        return K
    def full_verify(K):
        if len(K) < P:
            return False, 0
        key = bytes(K.get(r, 0) for r in range(P))
        tile = np.tile(np.frombuffer(key, np.uint8), n // P + 1)[:n]
        dec = (C ^ tile).tobytes()
        pos, nrec = 0, 0
        while pos + 27 <= n:
            rl = struct.unpack_from("<H", dec, pos)[0]
            if rl < 28 or pos + rl > n or dec[pos + rl - 1] != 0:
                return False, nrec
            pos += rl; nrec += 1
        return (nrec == cn and pos == n), nrec
    K = loose_fill(K0)
    return K, full_verify(K)

if miss:
    print("\n攻坚无密钥包：")
    for rel, rsv, cnt in miss:
        p = NEW_ROOT + "\\" + rel
        flag, _r, _c, idxend, nidx = load_head_index(p)
        stem = os.path.basename(rel).rsplit(".", 1)[0].lower()
        toks = stem.split("_")
        cribs = [(f"res\\{toks[0]}\\{toks[1]}\\" if len(toks) > 1 else f"res\\{toks[0]}\\".encode()).encode(),
                 (f"res\\{toks[0]}\\" + (toks[1] + "\\") if False else f"res\\{toks[0]}\\".encode() + toks[1].encode() + b"\\"),
                 f"res\\{toks[0]}\\".encode()]
        for crib in cribs:
            if len(crib) < 8:
                continue
            best = None
            for P in range(16, 2049):
                if P < len(crib) + 28:
                    continue
                K, (ok, nrec) = solve_generic(nidx, cnt, crib, P)
                if ok:
                    keys[f"{rsv:04x}"] = bytes(K[r] for r in range(P)).hex()
                    print(f"  {rel}: P={P} crib={crib!r} -> OK")
                    best = P
                    break
            if best:
                break
        else:
            print(f"  {rel}: FAIL")
    json.dump(keys, open(r"G:\pojie\ai\JiuYinUnpackTool\analysis\keys_norm.json", "w"), indent=1)

print(f"\n最终密钥: {len(keys)} 个")
