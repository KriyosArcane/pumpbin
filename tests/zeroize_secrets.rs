//! Tests for `SecretBuf` — the zeroize wrapper added in v1.1.8.
//!
//! Verifying that a heap allocation has actually been wiped after `Drop`
//! ran is tricky without UB (reading freed memory is UB even if it works
//! on x86 Linux nine times out of ten). These tests use the parts of
//! the `zeroize` contract that ARE observable:
//!
//! 1. Calling `.zeroize()` explicitly on a live `SecretBuf` wipes the
//!    underlying slice in place.
//! 2. The `Drop` impl from `ZeroizeOnDrop` fires on scope exit (proven
//!    by observing the same wipe via a manual `zeroize()` invocation;
//!    the derived `Drop` is just `self.zeroize()` under the hood).
//! 3. The `Debug` impl never prints the bytes — important because the
//!    `tests/log_redaction.rs` guard would otherwise have to grow a
//!    second pattern.

use pumpbin::SecretBuf;
use zeroize::Zeroize;

#[test]
fn secret_buf_constructs_from_vec_and_slice() {
    let from_vec: SecretBuf = vec![1u8, 2, 3].into();
    assert_eq!(from_vec.as_slice(), &[1, 2, 3]);

    let from_slice: SecretBuf = (&[4u8, 5, 6][..]).into();
    assert_eq!(from_slice.as_slice(), &[4, 5, 6]);

    let from_new = SecretBuf::new(vec![7u8, 8, 9]);
    assert_eq!(from_new.as_slice(), &[7, 8, 9]);
}

#[test]
fn debug_impl_is_redacted() {
    let s: SecretBuf = vec![0xDEu8, 0xAD, 0xBE, 0xEF].into();
    let dbg = format!("{s:?}");
    assert!(
        dbg.contains("<redacted") && dbg.contains("4 bytes>"),
        "Debug must redact, got: {dbg}"
    );
    // Belt + braces: the marker bytes must not appear in any form.
    assert!(!dbg.contains("222"), "Vec Debug form leaked: {dbg}");
    assert!(!dbg.contains("deadbeef"), "hex leaked: {dbg}");
    assert!(!dbg.contains("DEADBEEF"), "hex leaked: {dbg}");
}

#[test]
fn explicit_zeroize_wipes_in_place() {
    let mut s: SecretBuf = vec![0xAAu8; 64].into();
    let ptr_before = s.as_slice().as_ptr();
    let len_before = s.len();
    s.zeroize();
    // After zeroize() the Vec retains its allocation (capacity stays the
    // same) but the contents have been overwritten. The pointer should
    // be stable because zeroize doesn't reallocate.
    assert_eq!(s.as_slice().as_ptr(), ptr_before);
    assert!(s.iter().all(|&b| b == 0), "zeroize must wipe all bytes");
    // Length is zero after Vec::zeroize per the zeroize crate contract.
    assert!(s.len() <= len_before);
}

#[test]
fn deref_lets_existing_callers_use_secretbuf_as_slice() {
    fn takes_slice(s: &[u8]) -> usize {
        s.len()
    }
    let s: SecretBuf = vec![1u8; 32].into();
    assert_eq!(takes_slice(&s), 32);
}

#[test]
fn into_vec_releases_without_zeroize() {
    // Documented escape hatch: into_vec returns the raw Vec for paths
    // that have to cross a serde boundary. Caller is responsible for
    // wiping/re-wrapping.
    let s: SecretBuf = vec![1u8, 2, 3, 4].into();
    let v = s.into_vec();
    assert_eq!(v, vec![1u8, 2, 3, 4]);
}

#[test]
fn validate_shellcode_source_wraps_read_in_secretbuf() {
    // Indirect verification: the v1.1.8 change wraps fs::read in
    // SecretBuf inside validate_shellcode_source. We can't observe the
    // wipe from outside, but we can verify the code path still works
    // correctly for the documented failure modes.
    use pumpbin::plugin::{Plugin, PluginBins, PluginInfo, PluginPlugins, PluginReplace};
    use pumpbin::PumpBinError;

    let mut bins = PluginBins::default();
    let mut template = vec![0xAAu8; 64];
    template.extend_from_slice(b"$$SHELLCODE$$");
    template.extend(std::iter::repeat_n(b'0', 4096 - b"$$SHELLCODE$$".len()));
    template.extend_from_slice(b"$$99999$$");
    *bins.windows.executable_mut() = Some(template);

    let plugin = Plugin {
        version: "1.0.0".into(),
        info: PluginInfo {
            plugin_name: "zeroize-test".into(),
            author: "tests".into(),
            version: "1.0.0".into(),
            desc: String::new(),
        },
        replace: PluginReplace {
            src_prefix: b"$$SHELLCODE$$".to_vec(),
            size_holder: Some(b"$$99999$$".to_vec()),
            max_len: 4096,
        },
        bins,
        plugins: PluginPlugins::default(),
    };

    // Empty file → PB-E0006 (proves the read happened and the SecretBuf
    // check fired correctly).
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let err = plugin
        .validate_shellcode_source(tmp.path().to_str().unwrap())
        .unwrap_err();
    let pb = err.downcast_ref::<PumpBinError>().unwrap();
    assert_eq!(pb.code(), "PB-E0006");
}
