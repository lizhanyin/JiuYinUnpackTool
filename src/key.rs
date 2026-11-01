//! 从启动器/客户端二进制中静态提取 Lua 字节码 XOR 密钥（无需运行程序）。
//!
//! 密钥为 523 字节可打印 ASCII 的 C 字符串（NUL 结尾），以明文存在于
//! `updater_\fxupdate.exe` 与 `bin64\fxgame.exe` 的 .rdata 区，两处逐字节
//! 一致。偏移随客户端版本漂移（实测 2026-08 版为 0x4EE40 / 0x64530，
//! 2026-11 版为 0x4EE70 / 0x64760），因此提取不依赖固定偏移：
//!   1. 主策略：搜索 16 字节签名锚点，向后延伸至首个非可打印字节（NUL）；
//!   2. 兜底：若签名未命中（游戏更新轮换密钥），取文件中最长的可打印 ASCII
//!      字符串（≥300 字节）作为启发式候选，最终由 Lua undump 校验把关。
//!
//! 注意：2023-04 旧客户端的 exe 中无此密钥（该版本密钥另存），签名与兜底
//! 均无法命中——此时 undump 校验失败，条目按原始数据写出（安全回退）。

use anyhow::{bail, Context, Result};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// 索引加密密钥表的默认文件名（`--keys` 未指定时按 exe 目录与当前目录探测）。
pub const KEY_TABLE_FILENAME: &str = "jiuyin-keys.txt";

/// 密钥开头的 16 字节签名锚点（完整密钥从启动器文件中读出）。
pub const KEY_SIGNATURE: &[u8] = b"abcd464fghfgfjhf";
/// 实测密钥长度（fxupdate.exe 与 fxgame.exe 中一致）。
pub const EXPECTED_KEY_LEN: usize = 523;
const MIN_KEY_LEN: usize = 128;
const FALLBACK_MIN_LEN: usize = 300;

/// 从 exe 文件提取密钥，返回 (密钥, 提取方式说明)。
pub fn extract_key(path: &Path) -> Result<(Vec<u8>, &'static str)> {
    let data = std::fs::read(path)
        .with_context(|| format!("读取启动器文件失败：{}", path.display()))?;

    if let Some(pos) = find_sub(&data, KEY_SIGNATURE) {
        let end = data[pos..]
            .iter()
            .position(|&b| !is_printable(b))
            .map(|i| pos + i)
            .unwrap_or(data.len());
        let key = &data[pos..end];
        if key.len() < MIN_KEY_LEN {
            bail!(
                "签名命中但密钥长度异常（{} 字节），文件：{}",
                key.len(),
                path.display()
            );
        }
        let note = if key.len() == EXPECTED_KEY_LEN {
            "签名锚点"
        } else {
            "签名锚点（长度与实测 523 不同，可能已轮换，将由 undump 校验）"
        };
        return Ok((key.to_vec(), note));
    }

    // 兜底：最长可打印 ASCII 串。
    let (start, len) = longest_printable_run(&data);
    if len >= FALLBACK_MIN_LEN {
        return Ok((
            data[start..start + len].to_vec(),
            "启发式（签名未命中，取最长可打印串）",
        ));
    }
    bail!(
        "在 {} 中未找到候选密钥（签名未命中，最长可打印串仅 {} 字节）",
        path.display(),
        len
    );
}

pub fn is_printable(b: u8) -> bool {
    (0x20..=0x7E).contains(&b)
}

pub fn find_sub(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

pub fn longest_printable_run(data: &[u8]) -> (usize, usize) {
    let mut best = (0usize, 0usize);
    let mut run_start = 0usize;
    let mut in_run = false;
    for (i, &b) in data.iter().enumerate() {
        if is_printable(b) {
            if !in_run {
                in_run = true;
                run_start = i;
            }
        } else if in_run {
            in_run = false;
            let len = i - run_start;
            if len > best.1 {
                best = (run_start, len);
            }
        }
    }
    if in_run && data.len() - run_start > best.1 {
        best = (run_start, data.len() - run_start);
    }
    best
}

/// 在 anchor 目录及其上级（最多 3 级）自动探测启动器/客户端 exe。
/// anchor 为游戏安装目录（批量模式）或包文件所在目录（单包模式）。
pub fn find_launcher(anchor: &Path) -> Option<PathBuf> {
    let mut base = anchor;
    for _ in 0..3 {
        for rel in [
            "updater_/fxupdate.exe",
            "updater/fxupdate.exe",
            "bin64/fxgame.exe",
            "fxupdate.exe",
            "fxgame.exe",
        ] {
            let cand = base.join(rel);
            if cand.is_file() {
                return Some(cand);
            }
        }
        base = base.parent()?;
    }
    None
}

// ---------- 索引加密密钥表 ----------

/// 解析密钥表文本：每行 `密钥ID=hex`（ID 为 1..4 位十六进制，# 开头为注释）。
///
/// 示例：
/// ```text
/// # 2026-11 客户端提取
/// 4A3C=23aa67753dd5...
/// A3C8=a6abf68c...
/// ```
/// 返回 密钥ID -> 循环 XOR 密钥字节串。
pub fn parse_key_table(text: &str) -> Result<HashMap<u16, Vec<u8>>> {
    let mut table = HashMap::new();
    for (lineno, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((id_s, hex_s)) = line.split_once('=') else {
            bail!("密钥表第 {} 行缺少 '='：{:?}", lineno + 1, line);
        };
        let id = u16::from_str_radix(id_s.trim(), 16)
            .with_context(|| format!("密钥表第 {} 行密钥 ID 非法：{:?}", lineno + 1, id_s))?;
        let hex_s = hex_s.trim();
        if hex_s.len() % 2 != 0 || !hex_s.chars().all(|c| c.is_ascii_hexdigit()) {
            bail!(
                "密钥表第 {} 行密钥 hex 非法（长度 {:?}）",
                lineno + 1,
                hex_s.len()
            );
        }
        let mut key = Vec::with_capacity(hex_s.len() / 2);
        let b = hex_s.as_bytes();
        for i in (0..b.len()).step_by(2) {
            let hi = (b[i] as char).to_digit(16).unwrap() as u8;
            let lo = (b[i + 1] as char).to_digit(16).unwrap() as u8;
            key.push(hi << 4 | lo);
        }
        if id_s.trim().len() > 4 || key.len() < 8 {
            bail!(
                "密钥表第 {} 行异常：ID 超范围或密钥过短（{} 字节）",
                lineno + 1,
                key.len()
            );
        }
        table.insert(id, key);
    }
    if table.is_empty() {
        bail!("密钥表为空（无有效条目）");
    }
    Ok(table)
}

/// 加载密钥表文件。
pub fn load_key_table(path: &Path) -> Result<HashMap<u16, Vec<u8>>> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("读取密钥表 {} 失败", path.display()))?;
    parse_key_table(&text).with_context(|| format!("解析密钥表 {} 失败", path.display()))
}

/// 定位密钥表：--keys 显式路径优先，其次 exe 所在目录、当前目录下的
/// `jiuyin-keys.txt`。返回 (路径, 是否显式指定)。
pub fn find_key_table(explicit: Option<&Path>) -> Option<(PathBuf, bool)> {
    if let Some(p) = explicit {
        return Some((p.to_path_buf(), true));
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let cand = dir.join(KEY_TABLE_FILENAME);
            if cand.is_file() {
                return Some((cand, false));
            }
        }
    }
    let cand = PathBuf::from(KEY_TABLE_FILENAME);
    if cand.is_file() {
        return Some((cand, false));
    }
    None
}
