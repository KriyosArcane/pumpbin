//! Regression test for the pre-1.1.2 pass-clobber bug in `Plugin::replace_binary`.
//!
//! The bug: `replace_binary` previously did
//!     pass = output.pass().to_vec();
//! inside the Local branch, unconditionally overwriting any caller-supplied
//! `Pass` entries with whatever `run_encrypt_shellcode` returned. When callers
//! handed precomputed Pass entries into `replace_binary`, those entries were
//! silently dropped and the implant ran with un-substituted holders in the binary.
//!
//! This test builds a synthetic Plugin with no encrypt module (so
//! `run_encrypt_shellcode` returns an empty Pass list and the plaintext
//! shellcode), supplies two caller-side Pass entries whose holders are
//! present in the template, and asserts both holders got replaced.

use pumpbin::plugin::{Plugin, PluginBins, PluginInfo, PluginPlugins, PluginReplace};
use pumpbin::{BinaryType, Pass, Platform};

const SHELLCODE_HOLDER: &[u8] = b"$$SHELLCODE$$";
const SIZE_HOLDER: &[u8] = b"$$99999$$";
const KEY_HOLDER: &[u8] = b"$$KKKKKKKKKKKKKKKKKKKKKKKKKKKKKK$$";
const NONCE_HOLDER: &[u8] = b"$$NNNNNNNNNNNN$$";

const KEY_REPLACE: &[u8] = b"unit-test-key-bytes-here-32xxxxx";
const NONCE_REPLACE: &[u8] = b"unit-nonce12";

fn make_template() -> Vec<u8> {
    // Layout: junk | KEY_HOLDER | junk | NONCE_HOLDER | junk | SHELLCODE_HOLDER + padding | junk | SIZE_HOLDER | junk
    // The shellcode slot must be at least 256 bytes (matching SHELLCODE_LEN below).
    let mut bin = Vec::new();
    bin.extend_from_slice(&[0xAA; 32]);
    bin.extend_from_slice(KEY_HOLDER);
    bin.extend_from_slice(&[0xBB; 16]);
    bin.extend_from_slice(NONCE_HOLDER);
    bin.extend_from_slice(&[0xCC; 16]);
    bin.extend_from_slice(SHELLCODE_HOLDER);
    bin.extend(std::iter::repeat_n(b'0', 256 - SHELLCODE_HOLDER.len()));
    bin.extend_from_slice(&[0xDD; 16]);
    bin.extend_from_slice(SIZE_HOLDER);
    bin.extend_from_slice(&[0xEE; 16]);
    bin
}

fn make_plugin(template: &[u8]) -> Plugin {
    let mut bins = PluginBins::default();
    *bins.windows.executable_mut() = Some(template.to_vec());

    Plugin {
        version: "1.0.0".into(),
        info: PluginInfo {
            plugin_name: "pass-merge-fixture".into(),
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
        plugins: PluginPlugins::default(),
    }
}

#[test]
fn caller_supplied_pass_entries_survive_replace_binary() {
    let template = make_template();
    let plugin = make_plugin(&template);
    let template_bin = plugin
        .bins()
        .get_that_binary(Platform::Windows, BinaryType::Executable)
        .map(|b| b.to_vec())
        .unwrap();

    // Write the shellcode to a tempfile because Plugin uses ShellcodeSaveType::Local
    // and reads the source path from disk.
    let dir = tempfile::tempdir().unwrap();
    let shellcode_path = dir.path().join("payload.bin");
    let shellcode = vec![0x90u8; 64]; // 64 NOPs
    std::fs::write(&shellcode_path, &shellcode).unwrap();

    let caller_pass = vec![
        Pass {
            holder: KEY_HOLDER.to_vec(),
            replace_by: KEY_REPLACE.to_vec(),
        },
        Pass {
            holder: NONCE_HOLDER.to_vec(),
            replace_by: NONCE_REPLACE.to_vec(),
        },
    ];

    let out = plugin
        .replace_binary(
            template_bin,
            shellcode_path.to_string_lossy().into_owned(),
            caller_pass,
            None,
        )
        .expect("replace_binary should succeed with no WASM modules loaded");

    // Holders must NOT appear in the output (they were replaced).
    assert!(
        memchr_find(&out, KEY_HOLDER).is_none(),
        "KEY_HOLDER was not replaced \u{2014} pass-clobber bug regressed"
    );
    assert!(
        memchr_find(&out, NONCE_HOLDER).is_none(),
        "NONCE_HOLDER was not replaced \u{2014} pass-clobber bug regressed"
    );

    // Replacement bytes must appear in the output.
    assert!(
        memchr_find(&out, KEY_REPLACE).is_some(),
        "KEY_REPLACE bytes missing from output"
    );
    assert!(
        memchr_find(&out, NONCE_REPLACE).is_some(),
        "NONCE_REPLACE bytes missing from output"
    );

    // And the shellcode itself should be in there too.
    assert!(
        memchr_find(&out, &shellcode).is_some(),
        "shellcode bytes missing from output"
    );
}

fn memchr_find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}
