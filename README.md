# jiuyin-unpack

九阴真经（9yinjh）`.package` / `.patch` 资源包命令行解包工具，纯 Rust 实现。

- **PCK0 v15 容器**：明文索引 + 逐条目标准 zlib，直接解包
- **索引加密格式（标志 4）**：索引区逐字节循环 XOR，密钥长度不定（实测
  24..251 字节）；通过密钥表（`jiuyin-keys.txt`）解密，31/35 个加密包已破解
- **Lua 字节码去混淆**：`.lua` 条目内的 Lua 5.1 dump 被逐字段 XOR，本工具按
  ldump.c 的字段粒度精确还原为标准 Lua 5.1 字节码
- **密钥静态提取**：直接从启动器/客户端 exe 的明文区读取 XOR 密钥，**无需启动游戏**
- 进度条、多线程并行解包、防路径穿越、拒绝向包所在目录（游戏目录）输出

## 用法

```text
jiuyin-unpack <PACKAGE> [OPTIONS]
jiuyin-unpack --all-packages <游戏安装目录> [OPTIONS]
jiuyin-unpack --all-patches <游戏安装目录> [OPTIONS]

参数：
  <PACKAGE>              .package 或 .patch 文件路径（三选一）

选项：
  --all-packages <DIR>   递归解包该目录下所有 .package 文件
  --all-patches <DIR>    递归解包该目录下所有 .patch 文件（两者可同时指定）
  -o, --output <DIR>     输出目录（单包默认：./<包名>_unpacked；
                         批量默认：./<目录名>_packages|patches_unpacked）
  -l, --launcher <EXE>   用于提取解密密钥的启动器/客户端 exe
                         （默认自动探测：../updater_/fxupdate.exe →
                          ../updater/fxupdate.exe → ../bin64/fxgame.exe）
      --keys <FILE>      索引加密格式（标志 4）的密钥表，每行 "ID=hex"
                         （默认探测 exe 目录 / 当前目录下的 jiuyin-keys.txt）
      --list             仅列出条目（路径、压缩/原始大小、时间戳、目标包名）
      --no-lua-decrypt   跳过 Lua 字节码解密，写出原始数据
  -j, --jobs <N>         并行线程数（默认：运行时逻辑 CPU 核数，自动适配；
                         实际线程数会在解包开始时打印）
```

多线程说明：条目解压/解密/写出按 rayon 线程池并行，每个工作线程持有独立的
包文件句柄（读 I/O 无全局锁）；包与包之间在批量模式下按顺序推进。

示例：

```bash
# 列出包内条目（只读）
jiuyin-unpack --list "D:\游戏蜗牛\9yinjh\res\eff.package"

# 解包到指定目录（密钥自动从启动器提取）
jiuyin-unpack "D:\游戏蜗牛\9yinjh\res\lua.package" -o D:\out\lua

# 批量：解包安装目录下全部 .package（递归，统一进度条，按相对路径分目录）
jiuyin-unpack --all-packages "D:\游戏蜗牛\9yinjh" -o D:\out\all

# 批量：解包全部 .patch（可同时指定 --all-packages 一起跑）
jiuyin-unpack --all-patches "D:\游戏蜗牛\9yinjh\patch" -o D:\out\patches

# 指定另一个密钥来源
jiuyin-unpack "D:\游戏蜗牛\9yinjh\updater_\updater_lua.package" -l "D:\游戏蜗牛\9yinjh\bin64\fxgame.exe" -o D:\out\ulua
```

`.patch` 条目携带目标包名（如 `res\share.package`），输出组织为
`<out>/<目标包名>/<条目路径>`；散文件（如 `version.ini`）直接落在 `<out>` 下。
批量模式按包文件在扫描根目录下的**相对路径**分目录（如
`out/res/lua.package/...`、`out/patch/xxx.patch/...`），因此
`updater\` 与 `updater_\` 下的同名包不会互相覆盖；个别包解析失败会跳过并在
汇总中计数，不影响其余包。

## 格式分析

### PCK0 容器（.package 与 .patch 通用）

```text
头部 19 字节（条目区从 0x13 开始）:
  0x00  char[4]  魔数 "PCK0"
  0x04  u16      版本 = 15
  0x06  u16      标志：0 = 明文索引；4 = 索引区整体加密（新格式，见下节）
  0x08  u16      密钥 ID：明文格式恒 0；标志 4 时标识所用的循环 XOR 密钥
                 （同批更新的包共享同一密钥/ID，如 eff 与 icon 同为 0xA3C8）
  0x0A  u32      条目数
  0x0E  u32      索引结束偏移（= 数据区起点）
  0x12  u8       0

条目（变长，连续排列，靠 u16 记录总长推进）:
  +0   u16   记录总长 = 27 + len(文件名)+1 (+ len(包名)+1，仅 .patch)
  +2   u64   数据绝对偏移
  +10  u32   原始大小（解压后）
  +14  u32   压缩大小
  +18  7B    时间戳（u16 LE 年 + 月/日/时/分/秒）
  +25  u16   扩展：普通包恒 0；.patch 为 0（散文件）或 len(文件名)+1（后跟目标包名）
  +27  NUL 串  文件名（GBK，反斜杠路径）
  可选 NUL 串  目标包名（仅 .patch，扩展≠0 时）

数据区：逐条目独立的标准 zlib 流（78 9C），无容器层加密。
```

### 索引加密格式（标志 4，2026-05 起的补丁与 2026-09 起的 .package）

索引区（0x13 至索引结束偏移）整体被加密，数据块仍为明文 zlib。头部本身
（版本/标志/密钥 ID/条目数/索引结束偏移）不加密。

**加密方式：索引区逐字节循环 XOR，密钥长度不定**（实测 24..251 字节，
如 ini 为 60 字节、eff/icon 为 200 字节、gui 为 251 字节）。头部 0x08 处的
u16 是密钥 ID——同批更新的包共享同一密钥。密钥不以明文存在于任何客户端
二进制中（`fxpackage.dll` 经 Themida 加壳），但可通过已知明文攻击完整恢复：

1. **新旧包对比法（已用于提取 31/35 个包的密钥）**：游戏更新通常只追加条目，
   新旧版本索引的前若干条记录明文相同。`旧索引 XOR 新索引` 的前缀即密钥流，
   自相关求出周期（即密钥长度），按列取众数得密钥；
2. **结构约束法（无需旧包）**：记录结构高度可预测——偏移高 4 字节恒 0、
   年份高字节恒 0x07、extra 恒 0、文件名 NUL 结尾且多为可打印 ASCII。
   以 `res\<包名>\` 前缀做 crib 引导，结合记录起点检测与逐跳链式推进，
   可约束传播解出全部密钥字节（对新旧记录重排、数据区重写的包仍有效，
   但 4 个包 lua/lua64/map_ini/text 尚未攻克）。

密钥表 `jiuyin-keys.txt`（随仓库提供，25 个密钥）覆盖当前客户端除
lua(0x96FC)、lua64(0x2696)、map_ini(0xC694)、text(0xF9FE) 外的全部加密包。
密钥随游戏轮换，更新后需按上述方法重新提取。

### Lua 5.1 字节码 XOR 层（唯一加密）

`.lua` 条目 zlib 解压后为 Lua 5.1 dump：前 12 字节头明文
（`\x1bLuaQ` + 各字段宽度，offset 8 = sizeof(size_t)：游戏端 4、更新器端 8），
其后内容**逐字段 XOR**：

- 每个独立 dump 字段（对应 ldump.c 的一次 Dump 调用）各自从密钥下标 0 开始；
- 指令数组 / 行号数组整块算一个字段，不在元素间重置；
- 字符串的 size_t 前缀与内容是两个独立字段；
- 常量的 tag 与数据、4 个栈信息 byte 均各自为独立字段。

### 密钥来源（无需启动游戏）

523 字节可打印 ASCII 的 C 字符串（NUL 结尾），静态存在于：

| 文件 | 偏移 |
|---|---|
| `updater_\fxupdate.exe`（及 `updater\` 同名文件） | 0x4EE40（.rdata） |
| `bin64\fxgame.exe` | 0x64530 |

两处逐字节一致。工具以 16 字节签名锚点定位后向后取整串；签名未命中时
退化为取文件中最长可打印串（应对密钥轮换），并由 undump 结构校验把关。

## 实测记录（2026-11-01，新客户端）

新客户端 41 个 `.package` 使用索引加密格式（标志 4），17 个仍为明文格式：

| 包 | 密钥 ID | 密钥长 | 条目 | 结果 |
|---|---|---|---|---|
| `res/ini.package` | 0x4A3C | 60 | 18548 | 全部成功（旧条目 100% 保留 + 730 新增），18548/18548 解包 |
| `res/eff.package` / `res/icon.package` | 0xA3C8 | 200 | 79 / 25332 | 索引解密 + 全量解析验证通过 |
| `res/gui.package` / `res/gui_language.package` | 0x5BFB | 251 | 23526 / 22124 | 同上 |
| 其余 26 个（map_\*/obj_\*/skin/text/share/mus…） | 各异 | 24..3540 | — | 密钥提取并全量验证通过 |
| `res/lua.package` / `lua64` / `map_ini` / `text` | 96FC/2696/C694/F9FE | ? | — | 数据区重写导致新旧对比失效，暂未破解 |
| 6 个无 2023 旧版对照的包 | — | — | — | 需结构约束法，暂未破解 |

密钥提取与验证脚本见 `analysis/`（batch_crack2.py 等）；密钥表为仓库根目录
`jiuyin-keys.txt`。

## 实测记录（2026-08，1.0.2.584 客户端）

| 包 | 条目 | 结果 |
|---|---|---|
| `res/eff.package` | 79 | 全部成功，`.c` 为明文 HLSL 着色器 |
| `res/lua.package` | 2251 | 全部成功，2250 个 Lua 解密（chunkname `@G:\Version_wx_JinJi\...` 可读） |
| `res/ini.package` | 18459 | 全部成功（84MB，约 1.6s） |
| `updater_/updater_lua.package` | 11 | 全部成功，11 个 Lua 解密（size_t=8） |
| `updater_/updater_res.package` | 572 | 全部成功，PNG 完好 |
| `patch/jyzj-1.0.2.585-1.0.2.586.patch` | 6 | 全部成功，按目标包名分目录 |
| 批量 `--all-packages`（整个安装目录） | 58 包 | 全部解析并可解包（res + updater + updater_） |
| 批量 `--all-patches`（patch 目录） | 17 包 | 12 个成功，5 个为索引加密新格式被跳过 |

`-l bin64\fxgame.exe` 与默认 `fxupdate.exe` 提取的密钥解密结果逐字节一致；
游戏目录全程零写入（工具亦内置输出目录防护，拒绝向包所在目录树输出）。

## 构建

```bash
cargo build --release   # 产物 target/release/jiuyin-unpack.exe
cargo test              # 集成测试（tests/：PCK 解析 / Lua 往返解密 / 密钥提取 / 扫描与参数校验）
```

## 项目结构

```text
src/
  lib.rs    库入口（crate jiuyin_unpack）
  cli.rs    CLI 参数定义（clap）、模式校验、批量目录递归扫描
  pck.rs    PCK0 头/条目解析、索引解密（标志 4 循环 XOR）、GBK 文件名解码、安全输出路径
  key.rs    启动器密钥提取（签名锚点 + 最长可打印串兜底）、自动探测、索引密钥表
  lua.rs    Lua 5.1 undump 结构遍历与逐字段去 XOR（含结构校验）
  main.rs   可执行入口：编排、进度条、并行解包与汇总
tests/      集成测试（按模块分文件：pck / lua / key / cli）
jiuyin-keys.txt   索引加密格式的密钥表（25 个密钥，见"索引加密格式"一节）
analysis/         密钥提取/验证的 Python 脚本（已知明文对比 + 结构约束求解）
```

仅供学习研究游戏资源格式之用。
