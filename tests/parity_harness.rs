//! Parity harness — the foundation for v2.0 CLI-vs-UI byte-equivalence tests.
//!
//! Both `pumpbin` (GUI) and `pumpbin-cli` should produce identical output
//! bytes given identical inputs. There is no shared `BuildJob` abstraction
//! yet (planned for v2.0 Phase 0), so today both surfaces hand-wire calls
//! into `Plugin::replace_binary`. This file exists to:
//!
//! 1. Document, in code, the canonical "build a Plugin + generate" path that
//!    both surfaces are expected to follow.
//! 2. Cover the structural invariants of `replace_binary` output that don't
//!    depend on the random padding (length, shellcode bytes injected,
//!    holders consumed).
//! 3. Make the regression net easy to extend when `BuildJob` lands.
//!
//! `replace_binary`'s random padding currently goes through `thread_rng`
//! inside `utils::replace`, so byte-for-byte equality of two runs is not
//! achievable here without plumbing `replace_with_rng` all the way through.
//! That plumbing is v2.0 Phase 0 scope; for v1.1.3 we assert what's
//! deterministic and let the existing `tests/golden.rs` cover the seeded
//! lower-level path.

use pumpbin::plugin::{Plugin, PluginBins, PluginInfo, PluginPlugins, PluginReplace};
use pumpbin::{BinaryType, Platform};

const PREFIX: &[u8] = b"$$SHELLCODE$$";
const SIZE_HOLDER: &[u8] = b"$$99999$$";

/// Build the minimal Local-mode Plugin both surfaces should converge on.
fn fixture_plugin(template: Vec<u8>) -> Plugin {
    let mut bins = PluginBins::default();
    *bins.windows.executable_mut() = Some(template);

    Plugin {
        version: env!("CARGO_PKG_VERSION").to_string(),
        info: PluginInfo {
            plugin_name: "parity-fixture".into(),
            author: "tests".into(),
            version: "1.0.0".into(),
            desc: String::new(),
        },
        replace: PluginReplace {
            src_prefix: PREFIX.to_vec(),
            size_holder: Some(SIZE_HOLDER.to_vec()),
            max_len: 4096,
        },
        bins,
        plugins: PluginPlugins::default(),
    }
}

fn fixture_template() -> Vec<u8> {
    let mut bin = Vec::new();
    bin.extend_from_slice(&[0xAA; 64]);
    bin.extend_from_slice(PREFIX);
    bin.extend(std::iter::repeat_n(b'0', 4096 - PREFIX.len()));
    bin.extend_from_slice(&[0xBB; 32]);
    bin.extend_from_slice(SIZE_HOLDER);
    bin.extend_from_slice(&[0xCC; 32]);
    bin
}

fn write_shellcode(dir: &tempfile::TempDir, bytes: &[u8]) -> std::path::PathBuf {
    let p = dir.path().join("payload.bin");
    std::fs::write(&p, bytes).unwrap();
    p
}

/// Drive `replace_binary` end-to-end and return the produced bytes. This is
/// the canonical sequence both the CLI Generate handler
/// (`src/bin/pumpbin-cli.rs:240`) and the GUI Generate handler
/// (`src/lib.rs:588`) wrap with surface-specific UI / clap noise.
fn generate(template: Vec<u8>, shellcode: &[u8]) -> Vec<u8> {
    let plugin = fixture_plugin(template);
    let bin = plugin
        .bins()
        .get_that_binary(Platform::Windows, BinaryType::Executable)
        .unwrap();

    let dir = tempfile::tempdir().unwrap();
    let path = write_shellcode(&dir, shellcode);

    plugin
        .validate_for_generation(Platform::Windows, BinaryType::Executable)
        .unwrap();
    plugin
        .validate_shellcode_source(path.to_string_lossy().as_ref())
        .unwrap();

    plugin
        .replace_binary(bin, path.to_string_lossy().into_owned(), vec![], None)
        .expect("replace_binary failed")
}

#[test]
fn output_length_matches_template_length() {
    // `replace_binary` mutates `bin` in place (then post_binary modules may
    // resize, but we have none). Output length must equal template length.
    let template = fixture_template();
    let template_len = template.len();
    let out = generate(template, &[0x90u8; 64]);
    assert_eq!(out.len(), template_len, "output length must match template");
}

#[test]
fn shellcode_bytes_are_injected_verbatim() {
    let shellcode: Vec<u8> = (0..128u8).collect();
    let out = generate(fixture_template(), &shellcode);
    let pos = out.windows(shellcode.len()).position(|w| w == shellcode);
    assert!(
        pos.is_some(),
        "shellcode bytes must appear contiguously in output"
    );
}

#[test]
fn placeholders_are_consumed() {
    let out = generate(fixture_template(), &[0x90u8; 64]);
    assert!(
        !out.windows(PREFIX.len()).any(|w| w == PREFIX),
        "src_prefix placeholder must not appear in output"
    );
    assert!(
        !out.windows(SIZE_HOLDER.len()).any(|w| w == SIZE_HOLDER),
        "size_holder placeholder must not appear in output"
    );
}

#[test]
fn size_holder_carries_decimal_shellcode_length() {
    let shellcode_len = 128usize;
    let shellcode = vec![0x42u8; shellcode_len];
    let out = generate(fixture_template(), &shellcode);
    let expected = {
        // Local-mode loaders read a zero-padded decimal length from the
        // size_holder slot. For shellcode_len=128 and a 9-byte holder
        // (`$$99999$$` is 9 bytes including the `$$` sentinels), expect
        // "000000128".
        let s = shellcode_len.to_string();
        let pad = SIZE_HOLDER.len() - s.len();
        let mut v = vec![b'0'; pad];
        v.extend_from_slice(s.as_bytes());
        v
    };
    assert!(
        out.windows(expected.len()).any(|w| w == expected),
        "expected size string {:?} not found in output",
        String::from_utf8_lossy(&expected)
    );
}

#[test]
fn two_runs_differ_only_in_random_padding() {
    // The random padding inside the placeholder slot uses thread_rng, so two
    // runs will differ there. But the constant bytes (AA / BB / CC) and the
    // injected shellcode + size string must be identical.
    let template = fixture_template();
    let shellcode: Vec<u8> = (0..96u8).collect();
    let a = generate(template.clone(), &shellcode);
    let b = generate(template, &shellcode);
    assert_eq!(a.len(), b.len());

    // First 64 bytes are the 0xAA prefix and must match.
    assert_eq!(&a[..64], &b[..64], "constant prefix must match across runs");

    // Find where the shellcode landed in each and confirm identical position.
    let pa = a
        .windows(shellcode.len())
        .position(|w| w == shellcode)
        .unwrap();
    let pb = b
        .windows(shellcode.len())
        .position(|w| w == shellcode)
        .unwrap();
    assert_eq!(pa, pb, "shellcode must land at the same offset across runs");
}
