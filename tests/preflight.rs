//! Tests for `PluginReplace::preflight_template`, the shared helper that both
//! the Maker GUI (src/maker.rs) and the CLI `create-b1n` subcommand
//! (src/bin/pumpbin-cli.rs) call before encoding a `.b1n`.
//!
//! Pre-1.1.3 the Maker enforced template preflight inline and the CLI
//! skipped it entirely, producing silently-broken `.b1n` files. The shared
//! helper closes that drift.

use pumpbin::plugin::PluginReplace;

const PREFIX: &[u8] = b"$$SHELLCODE$$";
const SIZE_HOLDER: &[u8] = b"$$99999$$";

fn local_replace() -> PluginReplace {
    PluginReplace {
        src_prefix: PREFIX.to_vec(),
        size_holder: Some(SIZE_HOLDER.to_vec()),
        max_len: 4096,
    }
}

fn remote_replace() -> PluginReplace {
    PluginReplace {
        src_prefix: PREFIX.to_vec(),
        size_holder: None,
        max_len: 4096,
    }
}

fn template_with(parts: &[&[u8]]) -> Vec<u8> {
    let mut bin = Vec::new();
    bin.extend_from_slice(&[0xAA; 32]);
    for p in parts {
        bin.extend_from_slice(p);
        bin.extend_from_slice(&[0xBB; 16]);
    }
    bin
}

#[test]
fn local_template_with_both_placeholders_passes() {
    let bin = template_with(&[PREFIX, SIZE_HOLDER]);
    local_replace().preflight_template(&bin).expect("ok");
}

#[test]
fn local_template_missing_size_holder_fails() {
    let bin = template_with(&[PREFIX]);
    let err = local_replace().preflight_template(&bin).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("size_holder"),
        "error should name size_holder, got: {msg}"
    );
}

#[test]
fn local_template_missing_prefix_fails() {
    let bin = template_with(&[SIZE_HOLDER]);
    let err = local_replace().preflight_template(&bin).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("src_prefix"),
        "error should name src_prefix, got: {msg}"
    );
}

#[test]
fn local_template_with_neither_fails_naming_prefix_first() {
    let bin = template_with(&[b"nothing relevant here"]);
    let err = local_replace().preflight_template(&bin).unwrap_err();
    // src_prefix is checked first; that's the message we surface.
    assert!(err.to_string().contains("src_prefix"));
}

#[test]
fn remote_template_does_not_need_size_holder() {
    // Remote mode: size_holder is None, so the helper must skip that check.
    let bin = template_with(&[PREFIX]);
    remote_replace().preflight_template(&bin).expect("ok");
}

#[test]
fn remote_template_still_needs_prefix() {
    let bin = template_with(&[b"no placeholder anywhere"]);
    let err = remote_replace().preflight_template(&bin).unwrap_err();
    assert!(err.to_string().contains("src_prefix"));
}
