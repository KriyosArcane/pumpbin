//! Regression tests for `utils::recompute_pe_checksum`.
//!
//! O-6: Pre-v1.5.0 PumpBin patched the loader template but never
//! recomputed `IMAGE_OPTIONAL_HEADER.CheckSum`. Every stamped EXE
//! kept the stale template checksum, which made:
//!   - `pumpbin-cli verify` fail on PumpBin's own output
//!   - stock Windows tooling treat the binary as tampered
//!
//! These tests pin the helper's behavior on hand-rolled minimal PE
//! payloads and on the realistic non-PE case (must not panic, must
//! return false, must not modify the buffer).

use pumpbin::utils::recompute_pe_checksum;

/// Minimum viable PE32+ skeleton: DOS header → PE\0\0 → FileHeader
/// (20 bytes) → OptionalHeader64 (240 bytes). Enough for the helper
/// to locate the CheckSum field; sections are absent but the helper
/// only needs the file size and the CheckSum field offset.
fn minimal_pe(payload_size: usize) -> Vec<u8> {
    let e_lfanew: usize = 0x80;
    let header_end = e_lfanew + 4 + 20 + 240;
    let mut bin = vec![0u8; header_end + payload_size];
    bin[0..2].copy_from_slice(b"MZ");
    bin[0x3C..0x40].copy_from_slice(&(e_lfanew as u32).to_le_bytes());
    bin[e_lfanew..e_lfanew + 4].copy_from_slice(b"PE\0\0");
    // Pre-seed a wrong CheckSum value to make sure the helper overwrites it.
    let checksum_off = e_lfanew + 24 + 64;
    bin[checksum_off..checksum_off + 4].copy_from_slice(&0xDEADBEEFu32.to_le_bytes());
    // Sprinkle some non-zero payload so the checksum isn't trivially zero.
    for (i, b) in bin[header_end..].iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(7).wrapping_add(0x33);
    }
    bin
}

fn checksum_field(bin: &[u8]) -> u32 {
    let e_lfanew = u32::from_le_bytes(bin[0x3C..0x40].try_into().unwrap()) as usize;
    let off = e_lfanew + 24 + 64;
    u32::from_le_bytes(bin[off..off + 4].try_into().unwrap())
}

/// Reference implementation (matches `CheckSumMappedFile`). Kept inline
/// so the test fails loudly if the production helper drifts from the
/// canonical algorithm.
fn reference_checksum(bin: &[u8]) -> u32 {
    let e_lfanew = u32::from_le_bytes(bin[0x3C..0x40].try_into().unwrap()) as usize;
    let off = e_lfanew + 24 + 64;
    let mut tmp = bin.to_vec();
    tmp[off..off + 4].fill(0);
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < tmp.len() {
        sum = sum.wrapping_add(u16::from_le_bytes([tmp[i], tmp[i + 1]]) as u32);
        sum = (sum & 0xFFFF) + (sum >> 16);
        i += 2;
    }
    if i < tmp.len() {
        sum = sum.wrapping_add(tmp[i] as u32);
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    sum = (sum & 0xFFFF) + (sum >> 16);
    sum.wrapping_add(tmp.len() as u32)
}

#[test]
fn recomputes_checksum_for_minimal_pe() {
    let mut bin = minimal_pe(0);
    let expected = reference_checksum(&bin);
    assert!(recompute_pe_checksum(&mut bin));
    assert_eq!(checksum_field(&bin), expected);
}

#[test]
fn recomputes_checksum_for_pe_with_payload() {
    let mut bin = minimal_pe(8192);
    let expected = reference_checksum(&bin);
    assert!(recompute_pe_checksum(&mut bin));
    assert_eq!(checksum_field(&bin), expected);
}

#[test]
fn recomputes_checksum_for_odd_size_pe() {
    // Exercise the "trailing single byte" branch.
    let mut bin = minimal_pe(127);
    assert_eq!(bin.len() % 2, 1);
    let expected = reference_checksum(&bin);
    assert!(recompute_pe_checksum(&mut bin));
    assert_eq!(checksum_field(&bin), expected);
}

#[test]
fn no_op_on_elf_input() {
    // ELF magic (0x7F E L F). Helper must report `false` and leave
    // the input untouched.
    let mut bin = vec![0x7F, b'E', b'L', b'F', b'\x02', b'\x01', b'\x01', b'\x00'];
    bin.extend(std::iter::repeat_n(0xAAu8, 1000));
    let before = bin.clone();
    assert!(!recompute_pe_checksum(&mut bin));
    assert_eq!(bin, before, "non-PE buffer must not be mutated");
}

#[test]
fn no_op_on_truncated_pe() {
    // Has MZ + e_lfanew but the e_lfanew points past the buffer end.
    let mut bin = vec![0u8; 64];
    bin[0..2].copy_from_slice(b"MZ");
    bin[0x3C..0x40].copy_from_slice(&999_999u32.to_le_bytes());
    let before = bin.clone();
    assert!(!recompute_pe_checksum(&mut bin));
    assert_eq!(bin, before);
}

#[test]
fn no_op_on_tiny_buffer() {
    let mut bin = vec![b'M', b'Z'];
    let before = bin.clone();
    assert!(!recompute_pe_checksum(&mut bin));
    assert_eq!(bin, before);
}

/// End-to-end: build with the starter Windows plugin against the
/// committed sentinel shellcode, then assert the stamped output's
/// stored CheckSum matches the reference recomputation.
///
/// `#[ignore]` because it shells out to pumpbin-cli — the unit
/// tests above already cover the algorithm itself.
#[test]
#[ignore = "shells out to pumpbin-cli; covered by qa-execute.sh"]
fn end_to_end_stamped_pe_self_verifies() {
    use std::process::Command;
    let repo = env!("CARGO_MANIFEST_DIR");
    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().join("implant.exe");
    let profile = tmp.path().join("p.toml");
    std::fs::write(
        &profile,
        format!(
            r#"
schema = "pumpbin.profile/v1"
[pack]
source = "{repo}/examples/starter-plugins/windows.b1n"
[target]
platform = "windows"
binary_type = "exe"
[shellcode]
source = "file"
path = "{repo}/tests/fixtures/qa/windows_sentinel.bin"
[output]
path = "{}"
"#,
            out.display()
        ),
    )
    .unwrap();
    let status = Command::new(format!("{repo}/target/debug/pumpbin-cli"))
        .args(["--no-log", "build", "-f"])
        .arg(&profile)
        .status()
        .unwrap();
    assert!(status.success(), "pumpbin-cli build failed");
    let bin = std::fs::read(&out).unwrap();
    let stored = checksum_field(&bin);
    let expected = reference_checksum(&bin);
    assert_eq!(
        stored, expected,
        "stamped PE CheckSum stale (stored=0x{stored:08X}, expected=0x{expected:08X})"
    );
}
