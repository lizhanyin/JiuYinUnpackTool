# -*- coding: utf-8 -*-
"""复现 solve 并检查失败状态。"""
import struct
import numpy as np
import importlib.util
spec = importlib.util.spec_from_file_location("sv6", r"G:\pojie\ai\JiuYinUnpackTool\analysis\solve_v6.py")
sv6 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sv6)
L = 200

key, S, msg = sv6.solve(r"G:\pojie\ai\JiuYinUnpackTool\res\new\ini.package",
                        r"G:\pojie\ai\JiuYinUnpackTool\res\old\ini.package", verbose=True)
print("msg:", msg)
missing = [r for r in range(L) if r not in S.K]
print("缺失:", missing)
k = S.keyarr()
tile = np.tile(np.where(k >= 0, k, 0).astype(np.uint8), S.n // L + 1)[:S.n]
D = (S.C ^ tile).tobytes()
print("\nD[0:320]:")
for i in range(0, 320, 32):
    row = D[i:i+32]
    print(f"{i:04x}: {row.hex(' ')}  {''.join(chr(c) if 32<=c<127 else '.' for c in row)}")
pos = 0
hop = 0
while pos + 27 <= 320:
    rl = struct.unpack_from("<H", D, pos)[0]
    print(f"rec@0x{pos:x} len={rl} 残差{pos%200},{(pos+1)%200}{'缺失' if pos%200 in missing or (pos+1)%200 in missing else ''}")
    if rl < 28 or pos + rl > len(D):
        break
    pos += rl
    hop += 1
