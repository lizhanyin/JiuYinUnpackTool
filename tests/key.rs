//! 启动器密钥提取集成测试。

use jiuyin_unpack::key::{
    extract_key, find_sub, is_printable, longest_printable_run, KEY_SIGNATURE,
};
use jiuyin_unpack::key;
use std::path::PathBuf;

fn temp_path(tag: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "jyu_{tag}_{}.tmp",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}

#[test]
fn signature_hit_extends_to_nul() {
    let mut exe = vec![0u8; 64];
    exe.extend_from_slice(b"\x00\x00abcd464fghfgfjhfREST_OF_KEY\x00NEXT_STR");
    let pos = find_sub(&exe, KEY_SIGNATURE).unwrap();
    assert_eq!(pos, 66);
    let end = exe[pos..]
        .iter()
        .position(|&b| !is_printable(b))
        .map(|i| pos + i)
        .unwrap();
    assert_eq!(&exe[pos..end], b"abcd464fghfgfjhfREST_OF_KEY");
}

#[test]
fn longest_run_fallback() {
    let data = b"short\x00aaaa\x00this_is_a_very_long_printable_run_for_fallback\x00zz";
    let (start, len) = longest_printable_run(data);
    assert_eq!(
        &data[start..start + len],
        b"this_is_a_very_long_printable_run_for_fallback"
    );
}

#[test]
fn extract_key_from_fake_exe() {
    // 构造含签名锚点的伪 exe（密钥体 ≥128 字节过长度校验），走公开 API 提取。
    let sig = std::str::from_utf8(KEY_SIGNATURE).unwrap();
    let body = format!("{sig}{}", "X".repeat(200));
    let mut exe = vec![0u8; 64];
    exe.extend_from_slice(body.as_bytes());
    exe.push(0);
    exe.extend_from_slice(b"other strings follow");
    let path = temp_path("key");
    std::fs::write(&path, &exe).unwrap();

    let (key, note) = extract_key(&path).unwrap();
    assert_eq!(key, body.as_bytes());
    assert!(note.contains("签名"));
    std::fs::remove_file(&path).ok();
}

// ---------- 索引加密密钥表 ----------

#[test]
fn key_table_parse() {
    let text = "# 注释\n\n4A3C=23aa67753dd57541\nA3C8=a6abf68c7249ed51\n";
    let t = key::parse_key_table(text).unwrap();
    assert_eq!(t.len(), 2);
    assert_eq!(t[&0x4A3C], vec![0x23, 0xaa, 0x67, 0x75, 0x3d, 0xd5, 0x75, 0x41]);
    assert_eq!(t[&0xA3C8].len(), 8);
    assert_eq!(t[&0xA3C8][0], 0xa6);
}

#[test]
fn key_table_rejects_garbage() {
    assert!(key::parse_key_table("no-equals-sign").is_err());
    assert!(key::parse_key_table("4A3C=zz").is_err());       // 非 hex
    assert!(key::parse_key_table("4A3C=23a").is_err());      // 奇数长度
    assert!(key::parse_key_table("12345=23aa").is_err());    // ID 超 u16
    assert!(key::parse_key_table("").is_err());              // 空表
}

#[test]
fn key_table_min_key_len() {
    // 过短密钥（<8 字节）视为行异常，拒绝。
    assert!(key::parse_key_table("4A3C=23aa67753dd57541").is_ok());
    assert!(key::parse_key_table("4A3C=23aa6775").is_err());
}
