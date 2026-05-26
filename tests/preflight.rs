//! Tests for `PluginReplace::preflight_template`, the shared helper that both
//! the Maker GUI (src/maker.rs) and the CLI `create-b1n` subcommand
//! (src/bin/pumpbin-cli.rs) call before encoding a `.b1n`.
//!
//! Pre-1.1.3 the Maker enforced template preflight inline and the CLI
//! skipped it entirely, producing silently-broken `.b1n` files. The shared
//! helper closes that drift.

use pumpbin::plugin::PluginReplace;
use pumpbin::PumpBinError;

const PREFIX: &[u8] = b"$$SHELLCODE$$";
const SIZE_HOLDER: &[u8] = b"$$99999$$";

/// Helper: downcast the anyhow::Error to PumpBinError and assert both
/// the error code and the holder bytes carried in the variant.
fn assert_placeholder_error(err: anyhow::Error, expected_holder: &[u8]) {
    let pb = err
        .downcast_ref::<PumpBinError>()
        .unwrap_or_else(|| panic!("error did not downcast to PumpBinError: {err}"));
    assert_eq!(
        pb.code(),
        "PB-E0001",
        "expected PB-E0001, got {}",
        pb.code()
    );
    match pb {
        PumpBinError::PlaceholderNotFound { holder } => {
            let expected = String::from_utf8_lossy(expected_holder);
            assert_eq!(holder, &expected.as_ref(), "wrong holder in error");
        }
        other => panic!("expected PlaceholderNotFound, got {other:?}"),
    }
    // Display output must include the stable code.
    let display = format!("{err}");
    assert!(
        display.contains("PB-E0001"),
        "Display lacks code: {display}"
    );
}

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
    // Updated for v1.1.5: errors now carry the concrete missing holder
    // bytes instead of the abstract category name. PB-E0001 covers both
    // missing-prefix and missing-size_holder; the variant payload
    // distinguishes them.
    assert_placeholder_error(err, SIZE_HOLDER);
}

#[test]
fn local_template_missing_prefix_fails() {
    let bin = template_with(&[SIZE_HOLDER]);
    let err = local_replace().preflight_template(&bin).unwrap_err();
    assert_placeholder_error(err, PREFIX);
}

#[test]
fn local_template_with_neither_fails_naming_prefix_first() {
    let bin = template_with(&[b"nothing relevant here"]);
    let err = local_replace().preflight_template(&bin).unwrap_err();
    // src_prefix is checked first; the error must name that holder.
    assert_placeholder_error(err, PREFIX);
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
    assert_placeholder_error(err, PREFIX);
}
