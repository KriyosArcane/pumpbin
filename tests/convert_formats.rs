//! v1.4.0 `pumpbin::convert` round-trip tests.
//!
//! For each non-Raw format, verify that:
//! 1. The conversion is non-empty for non-empty input.
//! 2. The output contains the expected fixture markers (header,
//!    pattern, etc.) for the format.
//! 3. Hex specifically: the round-trip parse_hex(convert(x, Hex)) == x.

use pumpbin::convert::{convert, parse_hex, OutputFormat};

const FIXTURE: &[u8] = &[0xDE, 0xAD, 0xBE, 0xEF, 0x90, 0x90, 0x90, 0xC3];

#[test]
fn raw_format_returns_bytes_unchanged() {
    let out = convert(FIXTURE, OutputFormat::Raw);
    assert_eq!(out, FIXTURE);
}

#[test]
fn hex_format_produces_lowercase_hex() {
    let out = convert(FIXTURE, OutputFormat::Hex);
    let s = std::str::from_utf8(&out).unwrap();
    // 16 hex chars for 8 bytes; all-lowercase hex digits.
    assert_eq!(s.len(), FIXTURE.len() * 2);
    assert!(s
        .chars()
        .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()));
    assert!(s.starts_with("deadbeef"));
    assert!(s.ends_with("c3"));
}

#[test]
fn hex_roundtrips_through_parse_hex() {
    let encoded = convert(FIXTURE, OutputFormat::Hex);
    let parsed = parse_hex(std::str::from_utf8(&encoded).unwrap()).unwrap();
    assert_eq!(parsed, FIXTURE);
}

#[test]
fn parse_hex_accepts_separators_and_whitespace() {
    let parsed = parse_hex("de ad,be:ef 90:90 90 c3").unwrap();
    assert_eq!(parsed, FIXTURE);
}

#[test]
fn c_format_produces_valid_c_array() {
    let out = convert(FIXTURE, OutputFormat::C);
    let s = std::str::from_utf8(&out).unwrap();
    assert!(s.contains("unsigned char shellcode[]"));
    assert!(s.contains("0xde, 0xad, 0xbe, 0xef"));
    assert!(s.ends_with("};\n"));
}

#[test]
fn csharp_format_produces_valid_csharp_array() {
    let out = convert(FIXTURE, OutputFormat::Csharp);
    let s = std::str::from_utf8(&out).unwrap();
    assert!(s.contains("byte[] shellcode = new byte[]"));
    assert!(s.contains("0xde"));
    assert!(s.ends_with("};\n"));
}

#[test]
fn python_format_produces_valid_python_bytes() {
    let out = convert(FIXTURE, OutputFormat::Python);
    let s = std::str::from_utf8(&out).unwrap();
    assert!(s.starts_with("shellcode = b\""));
    assert!(s.contains(r"\xde\xad\xbe\xef"));
    assert!(s.ends_with("\"\n"));
}

#[test]
fn base64_roundtrips_with_engine() {
    use base64::Engine;
    let encoded = convert(FIXTURE, OutputFormat::Base64);
    let s = std::str::from_utf8(&encoded).unwrap();
    let decoded = base64::engine::general_purpose::STANDARD.decode(s).unwrap();
    assert_eq!(decoded, FIXTURE);
}

#[test]
fn format_aliases_are_case_insensitive() {
    assert_eq!(OutputFormat::from_str_ci("RAW"), Some(OutputFormat::Raw));
    assert_eq!(OutputFormat::from_str_ci("Hex"), Some(OutputFormat::Hex));
    assert_eq!(OutputFormat::from_str_ci("C-array"), Some(OutputFormat::C));
    assert_eq!(OutputFormat::from_str_ci("cs"), Some(OutputFormat::Csharp));
    assert_eq!(OutputFormat::from_str_ci("py"), Some(OutputFormat::Python));
    assert_eq!(OutputFormat::from_str_ci("b64"), Some(OutputFormat::Base64));
    assert_eq!(OutputFormat::from_str_ci("bogus"), None);
}
