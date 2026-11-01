# -*- coding: utf-8 -*-
"""调试 map_ini@P=148：逐步执行看卡点。"""
import struct, collections
import numpy as np
import importlib.util
spec = importlib.util.spec_from_file_location("sf", r"G:\pojie\ai\JiuYinUnpackTool\analysis\solve_final.py")
sf = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sf)

NEW = r"F:\Game\Online\9yin\9yin\res\map_ini.package"
flag, rsv, cnt, idxend, nidx = sf.load_head_index(NEW)
print(f"cnt={cnt} idxend=0x{idxend:x} idxlen=0x{len(nidx):x}")

for P in (37, 74, 148, 296):
    S = sf.Solver(nidx, P)
    C, n = S.C, S.n
    prefix = b"res\\map\\ini\\"
    K = {}
    for j, ch in enumerate(prefix):
        K[(27 + j) % P] = int(C[27 + j]) ^ ch
    for j in (6, 7, 8, 9, 25, 26):
        K[j % P] = int(C[j])
    K[19 % P] = int(C[19]) ^ 0x07
    S.K = K
    votes = collections.defaultdict(collections.Counter)
    for r, v in S.K.items():
        votes[r][v] += 9
    def solid():
        for r, c in votes.items():
            if r in S.K:
                continue
            t = c.most_common(2)
            if t and t[0][1] >= 3 and (len(t) == 1 or t[0][1] >= 3 * t[1][1]):
                S.K[r] = t[0][0]
    hist = []
    for it in range(30):
        starts, det = S.detect()
        for p in starts.tolist():
            c = p % P
            votes[(c+19) % P][int(C[p+19]) ^ 0x07] += 2
            votes[(c+25) % P][int(C[p+25])] += 1
            votes[(c+26) % P][int(C[p+26])] += 1
        if len(S.K) == P:
            break
        solid()
        hist.append((len(starts), len(S.K)))
    print(f"P={P}: 迭代 (起点,已知) {hist[:6]} ... {hist[-3:]}  最终 {len(S.K)}/{P}")
    if len(S.K) == P:
        key = bytes(S.K[r] for r in range(P))
        tile = np.tile(np.frombuffer(key, np.uint8), n // P + 1)[:n]
        dec = (C ^ tile).tobytes()
        print("  前 96 字节:", dec[:96])
        print("  名字区:", dec[27:80])
        pos = nrec = 0
        while pos + 27 <= len(dec):
            rl = struct.unpack_from("<H", dec, pos)[0]
            if rl < 28 or pos + rl > len(dec):
                print(f"  解析断 @0x{pos:x} rl={rl} ({nrec})"); break
            pos += rl; nrec += 1
        else:
            print(f"  解析 {nrec}/{cnt} 消费 0x{pos:x}")
        break
