# -*- coding: utf-8 -*-
"""配对-字典走：破解 lua / text。
字典 = 旧包全部名字（lua 额外并入 lua64 新包名字）。
每跳优先配对旧记录；失败则按"名字长度 + 可解残差字节必须匹配字典条目"消歧，
字典命中则用整条名字做 crib 学习全部名字残差。"""
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

def parse_plain(idx):
    recs, pos = [], 0
    while pos + 27 <= len(idx):
        rl = struct.unpack_from("<H", idx, pos)[0]
        if rl < 28 or pos + rl > len(idx):
            break
        recs.append((pos, rl, idx[pos + 27:pos + rl - 1]))
        pos += rl
    return recs

def decrypt_idx(nidx, key):
    P = len(key)
    C = np.frombuffer(nidx, np.uint8)
    tile = np.tile(np.frombuffer(key, np.uint8), len(C) // P + 1)[:len(C)]
    return (C ^ tile).tobytes()

def paired_walk(nidx, cn, name0, P, dict_names, min_rl=34, verbose=False):
    C = np.frombuffer(nidx, np.uint8)
    n = len(C)
    K = {}
    def put(r, v):
        r %= P
        if r in K and K[r] != v:
            return False
        K[r] = v
        return True
    rl0 = 28 + len(name0)
    if not (put(0, int(C[0]) ^ (rl0 & 0xFF)) and put(1, int(C[1]) ^ (rl0 >> 8))):
        return None, "len0 冲突"
    for j in (6, 7, 8, 9, 25, 26):
        put(j, int(C[j]))
    put(19, int(C[19]) ^ 0x07)
    for j, ch in enumerate(name0):
        if not put(27 + j, int(C[27 + j]) ^ ch):
            return None, "名字 crib 冲突"
    votes = collections.defaultdict(collections.Counter)
    def learn(r, v, w=2):
        r %= P
        votes[r][v] += w
        t = votes[r].most_common(2)
        if t and t[0][1] >= 3 and (len(t) == 1 or t[0][1] >= 3 * t[1][1]):
            K[r] = t[0][0]
    for r, v in list(K.items()):
        votes[r][v] += 9

    # 按长度分桶的字典
    by_len = collections.defaultdict(list)
    for nm in dict_names:
        by_len[len(nm)].append(nm)

    def check_name(p, nm):
        """在 p 处假设名字 nm：已知残差处必须匹配；NUL；返回冲突数。"""
        bad = 0
        base = p + 27
        for j, ch in enumerate(nm):
            r = (base + j) % P
            if r in K:
                if (int(C[base + j]) ^ K[r]) != ch:
                    bad += 1
                    if bad > 0:
                        return bad
        q = p + 27 + len(nm)
        if q >= n:
            return 99
        rq = q % P
        if rq in K and (int(C[q]) ^ K[rq]) != 0:
            return bad + 1
        return 0

    def next_ok(p1):
        if p1 + 27 > n:
            return True
        for o in range(6, 10):
            r = (p1 + o) % P
            if r in K and (int(C[p1 + o]) ^ K[r]) != 0:
                return False
        r19 = (p1 + 19) % P
        if r19 in K and (int(C[p1 + 19]) ^ K[r19]) != 0x07:
            return False
        return True

    p, hops, dict_hits = 0, 0, 0
    while p + 27 <= n:
        r0, r1 = p % P, (p + 1) % P
        rl = None
        if r0 in K and r1 in K:
            rl = (int(C[p]) ^ K[r0]) | ((int(C[p + 1]) ^ K[r1]) << 8)
            if not (min_rl <= rl <= 8192) or p + rl > n:
                rl = None
        if rl is not None:
            nm_len = rl - 28
            # 名字必须匹配字典中同长条目（已知残差处）
            ok = False
            for nm in by_len.get(nm_len, []):
                if check_name(p, nm) == 0:
                    ok = True
                    break
            if not ok or not next_ok(p + rl):
                rl = None
        if rl is None:
            # 搜索：字典条目 + 长度组合
            survivors = []
            for nm_len, nms in by_len.items():
                cand = 28 + nm_len
                if cand < min_rl or p + cand > n:
                    continue
                for nm in nms:
                    if check_name(p, nm) == 0 and next_ok(p + cand):
                        survivors.append((cand, nm))
                        break
                if len(survivors) > 3:
                    break
            if len(survivors) == 1:
                rl, nm_hit = survivors[0]
                dict_hits += 1
                for j, ch in enumerate(nm_hit):
                    learn(p + 27 + j, int(C[p + 27 + j]) ^ ch, w=3)
            elif len(survivors) == 0:
                return None, f"无幸存 @0x{p:x} (known={len(K)}/{P} hops={hops})"
            else:
                return None, f"歧义 @0x{p:x}: {[(c, nm[:20]) for c, nm in survivors[:4]]} (known={len(K)}/{P})"
        for o in (6, 7, 8, 9, 25, 26):
            learn(p + o, int(C[p + o]))
        learn(p + 19, int(C[p + 19]) ^ 0x07, w=2)
        learn(p + rl - 1, int(C[p + rl - 1]), w=1)
        p += rl
        hops += 1
        if verbose and hops % 400 == 0:
            print(f"    hops={hops} known={len(K)}/{P} dict_hits={dict_hits}")
    if len(K) < P:
        return None, f"仅 {len(K)}/{P}"
    key = bytes(K[r] for r in range(P))
    tile = np.tile(np.frombuffer(key, np.uint8), n // P + 1)[:n]
    dec = (C ^ tile).tobytes()
    pos2 = nrec = 0
    while pos2 + 27 <= len(dec):
        rl = struct.unpack_from("<H", dec, pos2)[0]
        if rl < 28 or pos2 + rl > len(dec) or dec[pos2 + rl - 1] != 0:
            return None, f"验证断 @0x{pos2:x} ({nrec})"
        pos2 += rl
        nrec += 1
    if nrec != cn or pos2 != len(dec):
        return None, f"数 {nrec}/{cn}"
    return key, f"OK {hops} 跳, 字典命中 {dict_hits}"

# ============ lua ============
keys = json.load(open(r"G:\pojie\ai\JiuYinUnpackTool\analysis\keys_norm.json"))
rsvL, cnL, _, nidxL = load_head_index(NEW_ROOT + r"\res\lua.package")
old_recsL = parse_plain(load_head_index(OLD_ROOT + r"\res\lua.package")[3])
dictL = {r[2] for r in old_recsL}
# 并入 lua64 新包名字（已破解）
rsv64, cn64, _, nidx64 = load_head_index(NEW_ROOT + r"\res\lua64.package")
dec64 = decrypt_idx(nidx64, bytes.fromhex(keys["2696"]))
dictL |= {r[2] for r in parse_plain(dec64)}
name0L = old_recsL[0][2]
print(f"lua: cnt={cnL} 字典 {len(dictL)} 个名字")
for P in (252, 126, 504, 84):
    key, msg = paired_walk(nidxL, cnL, name0L, P, dictL)
    print(f"  P={P}: {msg}")
    if key:
        keys[f"{rsvL:04x}"] = key.hex()
        json.dump(keys, open(r"G:\pojie\ai\JiuYinUnpackTool\analysis\keys_norm.json", "w"), indent=1)
        print(f"  -> lua 密钥 0x{rsvL:04x} 已存")
        break

# ============ text ============
rsvT, cnT, _, nidxT = load_head_index(NEW_ROOT + r"\res\text.package")
old_recsT = parse_plain(load_head_index(OLD_ROOT + r"\res\text.package")[3])
dictT = {r[2] for r in old_recsT}
name0T = old_recsT[0][2]
print(f"\ntext: cnt={cnT} 字典 {len(dictT)} 个名字")
for P in (254, 127, 508):
    key, msg = paired_walk(nidxT, cnT, name0T, P, dictT)
    print(f"  P={P}: {msg}")
    if key:
        keys[f"{rsvT:04x}"] = key.hex()
        json.dump(keys, open(r"G:\pojie\ai\JiuYinUnpackTool\analysis\keys_norm.json", "w"), indent=1)
        print(f"  -> text 密钥 0x{rsvT:04x} 已存")
        break

print(f"\nkeys_norm.json: {len(keys)} 个密钥")
