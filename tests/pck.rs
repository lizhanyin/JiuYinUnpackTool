//! PCK0 容器解析集成测试。

use jiuyin_unpack::pck::{self, ENTRY_FIXED_SIZE, HEADER_SIZE, MAGIC, SUPPORTED_VERSION};
use std::path::Path;

fn build_pkg(entries: &[(u64, u32, u32, &str, Option<&str>)]) -> Vec<u8> {
    let mut index = Vec::new();
    for &(off, raw, comp, name, pkg) in entries {
        let name_b = name.as_bytes();
        let mut rec_len = (ENTRY_FIXED_SIZE + name_b.len() + 1) as u16;
        let extra = match pkg {
            Some(p) => {
                rec_len += (p.len() + 1) as u16;
                (name_b.len() + 1) as u16
            }
            None => 0,
        };
        index.extend_from_slice(&rec_len.to_le_bytes());
        index.extend_from_slice(&off.to_le_bytes());
        index.extend_from_slice(&raw.to_le_bytes());
        index.extend_from_slice(&comp.to_le_bytes());
        index.extend_from_slice(&[0xEA, 0x07, 6, 3, 10, 1, 21]); // 时间戳
        index.extend_from_slice(&extra.to_le_bytes());
        index.extend_from_slice(name_b);
        index.push(0);
        if let Some(p) = pkg {
            index.extend_from_slice(p.as_bytes());
            index.push(0);
        }
    }
    let index_end = (HEADER_SIZE + index.len()) as u32;
    let mut buf = Vec::new();
    buf.extend_from_slice(MAGIC);
    buf.extend_from_slice(&SUPPORTED_VERSION.to_le_bytes());
    buf.extend_from_slice(&[0u8; 4]); // 偏移 6..0x0A 保留区（两段保留字均为 0）
    buf.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    buf.extend_from_slice(&index_end.to_le_bytes());
    buf.push(0);
    debug_assert_eq!(buf.len(), HEADER_SIZE);
    buf.extend_from_slice(&index);
    buf.extend_from_slice(&[0x78, 0x9C]); // 假数据区
    // 补齐到覆盖最大条目的 offset+comp_size（真实文件数据区连续铺满到 EOF）。
    let max_end = entries
        .iter()
        .map(|&(off, _, comp, _, _)| off + comp as u64)
        .max()
        .unwrap_or(0) as usize;
    buf.resize(buf.len().max(max_end), 0);
    buf
}

#[test]
fn parse_plain_entries() {
    let buf = build_pkg(&[
        (0x1AB, 29, 37, "version.ini", None),
        (
            0x1D0,
            320757,
            36173,
            "res\\share\\rule\\card.ini",
            Some("res\\share.package"),
        ),
    ]);
    let pkg = pck::parse(&buf[..], buf.len() as u64).unwrap();
    assert_eq!(pkg.entries.len(), 2);
    assert_eq!(pkg.entries[0].name, "version.ini");
    assert!(pkg.entries[0].package_name.is_none());
    assert_eq!(pkg.entries[1].name, "res\\share\\rule\\card.ini");
    assert_eq!(
        pkg.entries[1].package_name.as_deref(),
        Some("res\\share.package")
    );
    assert_eq!(pkg.entries[1].raw_size, 320757);
    assert_eq!(pkg.entries[1].comp_size, 36173);
    assert_eq!(pkg.entries[1].timestamp_string(), "2026-06-03 10:01:21");
}

#[test]
fn reject_bad_magic() {
    let mut buf = build_pkg(&[(0, 1, 1, "a", None)]);
    buf[0] = b'X';
    assert!(pck::parse(&buf[..], buf.len() as u64).is_err());
}

#[test]
fn reject_encrypted_index_flag() {
    // 标志 4 且未提供密钥：应报错并给出密钥 ID（供 --keys 密钥表查用）。
    let buf = build_pkg(&[(0, 1, 1, "a", None)]);
    let buf = encrypt_pkg(buf, 0x4A3C, &[7u8; 60]);
    let err = pck::parse(&buf[..], buf.len() as u64).unwrap_err().to_string();
    assert!(err.contains("索引加密"), "实际错误：{err}");
    assert!(err.contains("0x4A3C"), "应包含密钥 ID：{err}");
}

/// 将明文包改造为索引加密格式（标志 4）：头部写标志与密钥 ID，索引区循环 XOR。
fn encrypt_pkg(mut buf: Vec<u8>, key_id: u16, key: &[u8]) -> Vec<u8> {
    let index_end = u32::from_le_bytes([buf[0x0E], buf[0x0F], buf[0x10], buf[0x11]]) as usize;
    buf[6..8].copy_from_slice(&pck::FLAG_INDEX_ENCRYPTED.to_le_bytes());
    buf[8..10].copy_from_slice(&key_id.to_le_bytes());
    for i in pck::HEADER_SIZE..index_end {
        buf[i] ^= key[(i - pck::HEADER_SIZE) % key.len()];
    }
    buf
}

#[test]
fn encrypted_index_roundtrip() {
    // 真实格式特征：60 字节循环 XOR 密钥（同 ini.package 实测），头部 ID 0x4A3C。
    let key: Vec<u8> = (0..60).map(|i| (i * 37 + 11) as u8).collect();
    let entries: Vec<(u64, u32, u32, &str, Option<&str>)> = vec![
        (0x1E5AEC, 63, 61, "res\\ini\\npc\\fbmac031006.ini", None),
        (0x425347, 66, 54, "res\\ini\\npc\\npcitem856.ini", None),
    ];
    let plain = build_pkg(&entries);
    let enc = encrypt_pkg(plain.clone(), 0x4A3C, &key);

    let pkg = pck::parse_with_key(&enc[..], enc.len() as u64, Some(&key)).unwrap();
    assert_eq!(pkg.header.flags, pck::FLAG_INDEX_ENCRYPTED);
    assert_eq!(pkg.header.key_id, 0x4A3C);
    assert_eq!(pkg.entries.len(), 2);
    assert_eq!(pkg.entries[0].name, "res\\ini\\npc\\fbmac031006.ini");
    assert_eq!(pkg.entries[0].raw_size, 63);
    assert_eq!(pkg.entries[1].data_offset, 0x425347);
    // 与明文包逐条目一致（密钥长度 60 不是索引长度的因子，覆盖跨周期场景）。
    let plain_pkg = pck::parse(&plain[..], plain.len() as u64).unwrap();
    for (a, b) in pkg.entries.iter().zip(plain_pkg.entries.iter()) {
        assert_eq!(a.name, b.name);
        assert_eq!(a.data_offset, b.data_offset);
        assert_eq!(a.raw_size, b.raw_size);
        assert_eq!(a.comp_size, b.comp_size);
    }
}

#[test]
fn encrypted_index_wrong_key_fails() {
    let key = [9u8; 200]; // eff/icon 实测 200 字节密钥长度
    let wrong = [8u8; 200];
    let enc =
        encrypt_pkg(build_pkg(&[(0x188BE, 3754, 1051, "res\\eff\\x.c", None)]), 0xA3C8, &key);
    let err = pck::parse_with_key(&enc[..], enc.len() as u64, Some(&wrong)).unwrap_err();
    // 错误密钥必然破坏 u16 记录长度或 NUL 结构，解析应当失败而非返回垃圾。
    let msg = format!("{err:#}");
    assert!(
        msg.contains("记录长度非法") || msg.contains("NUL") || msg.contains("条目数不符"),
        "实际错误：{msg}"
    );
}

#[test]
fn safe_path_blocks_traversal() {
    let base = Path::new("out");
    let p = pck::safe_output_path(base, "..\\..\\evil.txt");
    assert_eq!(p, Path::new("out").join("evil.txt"));
    let p = pck::safe_output_path(base, "C:\\abs\\x.png");
    assert_eq!(p, Path::new("out").join("abs").join("x.png"));
    let p = pck::safe_output_path(base, "res\\eff\\a.c");
    assert_eq!(p, Path::new("out").join("res").join("eff").join("a.c"));
}
