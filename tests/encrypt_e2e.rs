//! End-to-end test: `replace_binary` with AES-GCM encryption wired.
//!
//! Constructs a synthetic Plugin whose template contains all the
//! placeholders that the AES-GCM encrypt module expects (shellcode
//! slot, size holder, key holder, nonce holder), sets
//! `encrypt_shellcode = Some("aes-gcm")`, and calls `replace_binary`.
//!
//! Assertions:
//!   1. Raw shellcode does NOT appear in the output (it was encrypted).
//!   2. KEY_HOLDER and NONCE_HOLDER markers are replaced (not present).
//!   3. Template junk bytes surrounding the placeholders survive.

use pumpbin::plugin::{Plugin, PluginBins, PluginInfo, PluginPlugins, PluginReplace};
use pumpbin::{BinaryType, Pass, Platform};

/// Shellcode placeholder — same as the scaffold default.
const SHELLCODE_HOLDER: &[u8] = b"$$SHELLCODE$$";
/// Size placeholder — same as the scaffold default.
const SIZE_HOLDER: &[u8] = b"$$99999$$";

/// AES-GCM key holder (32 bytes) — must match
/// `pumpbin::modules::encrypt::aes256_gcm::KEY_HOLDER`.
const KEY_HOLDER: &[u8] = b"$$KKKKKKKKKKKKKKKKKKKKKKKKKKKK$$";

/// AES-GCM nonce holder (12 bytes) — must match
/// `pumpbin::modules::encrypt::aes256_gcm::NONCE_HOLDER`.
const NONCE_HOLDER: &[u8] = b"$$NNNNNNNN$$";

/// Recognizable junk bytes embedded in the template so we can verify
/// the non-placeholder parts survive the stamping process.
const JUNK_HEAD: &[u8] = b"HEAD_JUNK_1234567890";
const JUNK_TAIL: &[u8] = b"TAIL_JUNK_ABCDEFGHIJ";

fn make_template() -> Vec<u8> {
    // Layout:
    //   JUNK_HEAD | KEY_HOLDER | padding | NONCE_HOLDER | padding
    //   | SHELLCODE_HOLDER + padding (256 bytes total) | padding
    //   | SIZE_HOLDER | JUNK_TAIL
    let mut bin = Vec::new();
    bin.extend_from_slice(JUNK_HEAD);
    bin.extend_from_slice(KEY_HOLDER);
    bin.extend_from_slice(&[0xAA; 16]);
    bin.extend_from_slice(NONCE_HOLDER);
    bin.extend_from_slice(&[0xBB; 16]);
    bin.extend_from_slice(SHELLCODE_HOLDER);
    // Pad shellcode slot to 256 bytes total.
    bin.extend(std::iter::repeat_n(b'0', 256 - SHELLCODE_HOLDER.len()));
    bin.extend_from_slice(&[0xCC; 16]);
    bin.extend_from_slice(SIZE_HOLDER);
    bin.extend_from_slice(JUNK_TAIL);
    bin
}

fn make_plugin(template: &[u8]) -> Plugin {
    let mut bins = PluginBins::default();
    *bins.windows.executable_mut() = Some(template.to_vec());

    Plugin {
        version: "1.0.0".into(),
        info: PluginInfo {
            plugin_name: "encrypt-e2e-fixture".into(),
            author: "tests".into(),
            version: "1.0.0".into(),
            desc: String::new(),
        },
        replace: PluginReplace {
            src_prefix: SHELLCODE_HOLDER.to_vec(),
            size_holder: Some(SIZE_HOLDER.to_vec()),
            max_len: 256,
        },
        bins,
        plugins: PluginPlugins {
            encrypt_shellcode: Some("aes-gcm".into()),
            ..Default::default()
        },
    }
}

#[test]
fn replace_binary_with_aes_gcm_encrypts_shellcode() {
    let template = make_template();
    let plugin = make_plugin(&template);
    let template_bin = plugin
        .bins()
        .get_that_binary(Platform::Windows, BinaryType::Executable)
        .map(|b| b.to_vec())
        .unwrap();

    // Write test shellcode to a temp file (Local mode reads from disk).
    let dir = tempfile::tempdir().unwrap();
    let shellcode_path = dir.path().join("payload.bin");
    let shellcode = b"RECOGNIZABLE_SHELLCODE_PAYLOAD_BYTES_HERE";
    std::fs::write(&shellcode_path, shellcode).unwrap();

    // No caller-supplied Pass entries — the encrypt module should
    // generate its own key/nonce Pass entries internally.
    let caller_pass: Vec<Pass> = Vec::new();

    let out = plugin
        .replace_binary(
            template_bin,
            shellcode_path.to_string_lossy().into_owned(),
            caller_pass,
            None,
        )
        .expect("replace_binary with aes-gcm should succeed");

    // 1. Raw shellcode must NOT appear (it should be encrypted).
    assert!(
        memchr_find(&out, shellcode).is_none(),
        "raw shellcode found in output — encryption did not run"
    );

    // 2. KEY_HOLDER and NONCE_HOLDER must be replaced.
    assert!(
        memchr_find(&out, KEY_HOLDER).is_none(),
        "KEY_HOLDER still present — key was not stamped"
    );
    assert!(
        memchr_find(&out, NONCE_HOLDER).is_none(),
        "NONCE_HOLDER still present — nonce was not stamped"
    );

    // 3. Non-placeholder template content must survive.
    assert!(
        memchr_find(&out, JUNK_HEAD).is_some(),
        "JUNK_HEAD missing from output — template was corrupted"
    );
    assert!(
        memchr_find(&out, JUNK_TAIL).is_some(),
        "JUNK_TAIL missing from output — template was corrupted"
    );
}

fn memchr_find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}
