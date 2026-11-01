# -*- coding: utf-8 -*-
"""验证新客户端 Lua 字节码解密：
1. 提取新密钥（签名锚点）
2. 取 lua.package / lua64.package 的 .lua 条目
3. 用 lua.rs 的逐字段 XOR 算法（Python 复刻）解密
4. 校验：恰好消费 + chunkname 可读 + opcode 合法
"""
import struct, zlib, json
import numpy as np

def extract_key(path, sig=b"abcd464fghfgfjhf"):
    data = open(path, "rb").read()
    i = data.find(sig)
    if i < 0:
        return None
    end = i
    while end < len(data) and 0x20 <= data[end] <= 0x7e:
        end += 1
    return data[i:end]

def load_head_index(path):
    with open(path, "rb") as f:
        head = f.read(0x13)
        rsv, = struct.unpack_from("<H", head, 8)
        cnt, = struct.unpack_from("<I", head, 0x0A)
        idxend, = struct.unpack_from("<I", head, 0x0E)
        f.seek(0x13)
        return rsv, cnt, idxend, f.read(idxend - 0x13)

def get_entries(path, key):
    rsv, cnt, idxend, nidx = load_head_index(path)
    P = len(key)
    C = np.frombuffer(nidx, np.uint8)
    tile = np.tile(np.frombuffer(key, np.uint8), len(C) // P + 1)[:len(C)]
    dec = (C ^ tile).tobytes()
    pos, out = 0, []
    while pos + 27 <= len(dec):
        rl = struct.unpack_from("<H", dec, pos)[0]
        off = struct.unpack_from("<Q", dec, pos + 2)[0]
        raw, comp = struct.unpack_from("<II", dec, pos + 10)
        out.append((dec[pos + 27:pos + rl - 1].decode("gbk", "replace"), off, raw, comp))
        pos += rl
    return out

# ---- lua.rs 算法复刻 ----
def lua_decrypt(data, key):
    """逐字段 XOR，字段各自从密钥 0 开始。返回 (明文, 错误)。"""
    if data[:4] != b"\x1bLua" or data[4] != 0x51:
        return None, "非 Lua5.1 头"
    s_int, s_size_t, s_instr, s_number = data[7], data[8], data[9], data[10]
    if s_int != 4 or s_size_t not in (4, 8) or s_instr != 4 or s_number != 8:
        return None, f"宽度异常 int={s_int} size_t={s_size_t}"
    out = bytearray(data)
    p = 12
    n = len(out)
    K = len(key)
    def field(m):
        nonlocal p
        if p + m > n:
            raise ValueError(f"越界 需{m} 剩{n-p}")
        for i in range(m):
            out[p + i] ^= key[i % K]
        p += m
    def u32():
        field(4)
        return struct.unpack_from("<I", out, p - 4)[0]
    def usize(m):
        field(m)
        return int.from_bytes(out[p - m:p], "little")
    def load_string():
        ln = usize(s_size_t)
        if ln == 0:
            return
        if ln > n - p:
            raise ValueError(f"串长 {ln} 越界")
        field(ln)
    def load_function(depth):
        nonlocal p
        if depth > 250:
            raise ValueError("嵌套过深")
        load_string()                      # source
        field(4); field(4)                 # linedefined/lastlinedefined
        field(1); field(1); field(1); field(1)  # nups/numparams/is_vararg/maxstack
        sizecode = u32()
        if sizecode * 4 > n - p:
            raise ValueError(f"sizecode={sizecode}")
        field(sizecode * 4)
        sizek = u32()
        if sizek > n - p:
            raise ValueError(f"sizek={sizek}")
        for _ in range(sizek):
            field(1)
            tag = out[p - 1]
            if tag == 0:
                pass
            elif tag == 1:
                field(1)
            elif tag == 3:
                field(8)
            elif tag == 4:
                load_string()
            else:
                raise ValueError(f"tag {tag}")
        sizep = u32()
        if sizep > (n - p) // 24:
            raise ValueError(f"sizep={sizep}")
        for _ in range(sizep):
            load_function(depth + 1)
        sizelineinfo = u32()
        if sizelineinfo * 4 > n - p:
            raise ValueError(f"sizelineinfo={sizelineinfo}")
        field(sizelineinfo * 4)
        sizelocvars = u32()
        if sizelocvars > (n - p) // 10:
            raise ValueError("sizelocvars")
        for _ in range(sizelocvars):
            load_string(); field(4); field(4)
        nupvalues = u32()
        if nupvalues > (n - p) // 5:
            raise ValueError("nupvalues")
        for _ in range(nupvalues):
            load_string()
    try:
        load_function(0)
    except ValueError as e:
        return None, str(e)
    if p != n:
        return None, f"未恰好消费 {p}/{n}"
    return bytes(out), None

keys = json.load(open(r"G:\pojie\ai\JiuYinUnpackTool\analysis\keys_norm.json"))
new_key = extract_key(r"F:\Game\Online\9yin\9yin\updater_\fxupdate.exe")
print(f"新密钥: {len(new_key)} 字节")

for pkg, idx_key in ((r"F:\Game\Online\9yin\9yin\res\lua.package", "96fc"),
                     (r"F:\Game\Online\9yin\9yin\res\lua64.package", "2696")):
    entries = get_entries(pkg, bytes.fromhex(keys[idx_key]))
    whole = open(pkg, "rb").read()
    luas = [e for e in entries if e[0].endswith(".lua")]
    print(f"\n{pkg.split(chr(92))[-1]}: {len(luas)} 个 .lua 条目（共 {len(entries)}）")
    ok = fail = 0
    first_fail = None
    for name, off, raw, comp in luas[:60]:
        data = zlib.decompress(whole[off:off + comp])
        dec, err = lua_decrypt(data, new_key)
        if dec is not None:
            ok += 1
            if ok == 1:
                # chunkname = 第一个字符串（size_t 前缀后）
                s_sz = data[8]
                ln = int.from_bytes(dec[12:12 + s_sz], "little")
                chunk = dec[12 + s_sz:12 + s_sz + ln - 1]
                print(f"  首个解密: {name} chunkname={chunk[:48]!r}")
        else:
            fail += 1
            if first_fail is None:
                first_fail = (name, err, data[:12].hex(" "))
    print(f"  前 60 条: {ok} 成功 / {fail} 失败")
    if first_fail:
        print(f"  首个失败: {first_fail[0]} 原因={first_fail[1]} 头12={first_fail[2]}")
