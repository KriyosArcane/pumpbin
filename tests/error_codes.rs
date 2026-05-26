//! Error-code regression tests for `PumpBinError`.
//!
//! These tests assert that:
//!
//! 1. Every `PumpBinError` variant has a unique stable `PB-Exxxx` code.
//! 2. The library functions return errors that downcast to the expected
//!    `PumpBinError` variant (so machine consumers can match on codes
//!    without parsing strings).
//! 3. The `Display` output includes the code, so human consumers see the
//!    same identifier.
//!
//! Note: as of v1.1.5 public library functions still return
//! `anyhow::Result<T>`. The `PumpBinError` is reachable via
//! `err.downcast_ref::<PumpBinError>()`. v2.0 Phase 0 will migrate
//! signatures to `PumpBinResult<T>` directly.

use pumpbin::plugin::{Plugin, PluginBins, PluginInfo, PluginPlugins, PluginReplace};
use pumpbin::{BinaryType, Platform, PumpBinError};

fn assert_pb_code<T: std::fmt::Debug>(
    result: anyhow::Result<T>,
    expected_code: &str,
    expected_variant_check: impl FnOnce(&PumpBinError) -> bool,
) {
    let err = result.expect_err("expected an error, got Ok");
    let pb: &PumpBinError = err
        .downcast_ref::<PumpBinError>()
        .unwrap_or_else(|| panic!("error did not downcast to PumpBinError: {err}"));
    assert_eq!(
        pb.code(),
        expected_code,
        "expected code {} got {} for: {err}",
        expected_code,
        pb.code()
    );
    assert!(
        expected_variant_check(pb),
        "variant check failed for: {err}"
    );
    // Display must contain the code so humans see the same identifier.
    let display = format!("{err}");
    assert!(
        display.contains(expected_code),
        "Display output {display:?} must contain {expected_code:?}"
    );
}

fn make_plugin_local() -> Plugin {
    let mut bins = PluginBins::default();
    *bins.windows.executable_mut() = {
        let mut template = vec![0xAAu8; 64];
        template.extend_from_slice(b"$$SHELLCODE$$");
        template.extend(std::iter::repeat_n(b'0', 4096 - b"$$SHELLCODE$$".len()));
        template.extend_from_slice(&[0xCCu8; 32]);
        template.extend_from_slice(b"$$99999$$");
        Some(template)
    };
    Plugin {
        version: "1.0.0".into(),
        info: PluginInfo {
            plugin_name: "error-test".into(),
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
    }
}

// ── PB-E0001 PlaceholderNotFound (via preflight_template) ─────────────────

#[test]
fn pb_e0001_preflight_missing_prefix() {
    let replace = PluginReplace {
        src_prefix: b"$$SHELLCODE$$".to_vec(),
        size_holder: Some(b"$$99999$$".to_vec()),
        max_len: 4096,
    };
    let bad_template = b"this template has no placeholders".to_vec();
    assert_pb_code(replace.preflight_template(&bad_template), "PB-E0001", |e| {
        matches!(e, PumpBinError::PlaceholderNotFound { .. })
    });
}

#[test]
fn pb_e0001_preflight_missing_size_holder() {
    let replace = PluginReplace {
        src_prefix: b"$$SHELLCODE$$".to_vec(),
        size_holder: Some(b"$$99999$$".to_vec()),
        max_len: 4096,
    };
    // Template has prefix but not size_holder.
    let mut template = vec![0xAAu8; 16];
    template.extend_from_slice(b"$$SHELLCODE$$");
    template.extend_from_slice(&[0xBBu8; 16]);
    assert_pb_code(
        replace.preflight_template(&template),
        "PB-E0001",
        |e| matches!(e, PumpBinError::PlaceholderNotFound { holder } if holder == "$$99999$$"),
    );
}

// ── PB-E0003 ShellcodeSourceEmpty ────────────────────────────────────────

#[test]
fn pb_e0003_shellcode_source_empty() {
    let plugin = make_plugin_local();
    assert_pb_code(plugin.validate_shellcode_source("   "), "PB-E0003", |e| {
        matches!(e, PumpBinError::ShellcodeSourceEmpty)
    });
}

// ── PB-E0004 ShellcodeFileNotFound ───────────────────────────────────────

#[test]
fn pb_e0004_shellcode_file_not_found() {
    let plugin = make_plugin_local();
    assert_pb_code(
        plugin.validate_shellcode_source("/no/such/file"),
        "PB-E0004",
        |e| matches!(e, PumpBinError::ShellcodeFileNotFound { .. }),
    );
}

// ── PB-E0006 ShellcodeFileEmpty ──────────────────────────────────────────

#[test]
fn pb_e0006_shellcode_file_empty() {
    let plugin = make_plugin_local();
    let tmp = tempfile::NamedTempFile::new().unwrap();
    // tempfile is created empty.
    assert_pb_code(
        plugin.validate_shellcode_source(tmp.path().to_str().unwrap()),
        "PB-E0006",
        |e| matches!(e, PumpBinError::ShellcodeFileEmpty { .. }),
    );
}

// ── PB-E0007 ShellcodeContainsPlaceholder ────────────────────────────────

#[test]
fn pb_e0007_shellcode_contains_placeholder() {
    let plugin = make_plugin_local();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("looks-like-template.bin");
    std::fs::write(
        &path,
        b"this is not a payload, contains $$SHELLCODE$$ bytes",
    )
    .unwrap();
    assert_pb_code(
        plugin.validate_shellcode_source(path.to_str().unwrap()),
        "PB-E0007",
        |e| matches!(e, PumpBinError::ShellcodeContainsPlaceholder { .. }),
    );
}

// ── PB-E0008 RemoteUrlInvalidScheme ──────────────────────────────────────

#[test]
fn pb_e0008_remote_url_invalid_scheme() {
    // Build a Remote-mode plugin (size_holder=None).
    let mut plugin = make_plugin_local();
    plugin.replace.size_holder = None;
    assert_pb_code(
        plugin.validate_shellcode_source("ftp://example.com/sc.bin"),
        "PB-E0008",
        |e| matches!(e, PumpBinError::RemoteUrlInvalidScheme { .. }),
    );
}

// ── PB-E0009 BinaryNotInPlugin ───────────────────────────────────────────

#[test]
fn pb_e0009_binary_not_in_plugin() {
    let plugin = make_plugin_local(); // only Windows EXE present
    assert_pb_code(
        plugin.validate_for_generation(Platform::Linux, BinaryType::Executable),
        "PB-E0009",
        |e| matches!(e, PumpBinError::BinaryNotInPlugin { .. }),
    );
}

// ── PB-E0010 LocalRequiresSizeHolder ─────────────────────────────────────

#[test]
fn pb_e0010_local_requires_size_holder() {
    // Plugin with Local-mode validator state but no size_holder is
    // structurally impossible to construct via the high-level types
    // (save_type() infers from size_holder). However, validate_for_generation
    // checks the invariant explicitly — exercise it by editing the replace
    // after construction. In practice this catches a corrupted .b1n that was
    // hand-modified.
    // Note: this PB-E0010 path is unreachable via the public Plugin API
    // because `save_type()` infers Local-vs-Remote from `size_holder.is_some()`,
    // so a Local-mode plugin always has a size_holder by construction. The
    // validate_for_generation branch exists as a defense against a
    // hand-corrupted .b1n that was edited to break that invariant. We can't
    // synthesize that via the safe types, so this test asserts the code()
    // string only.
    let err = PumpBinError::LocalRequiresSizeHolder;
    assert_eq!(err.code(), "PB-E0010");
    assert!(format!("{err}").contains("PB-E0010"));
}

// ── PB-E0011 MaxLenZero ──────────────────────────────────────────────────

#[test]
fn pb_e0011_max_len_zero() {
    let mut plugin = make_plugin_local();
    plugin.replace.max_len = 0;
    assert_pb_code(
        plugin.validate_for_generation(Platform::Windows, BinaryType::Executable),
        "PB-E0011",
        |e| matches!(e, PumpBinError::MaxLenZero),
    );
}

// ── PB-E0015 PluginNotFound ──────────────────────────────────────────────

#[test]
fn pb_e0015_plugin_not_found() {
    use pumpbin::plugin::Plugins;
    let plugins = Plugins::default();
    assert_pb_code(plugins.get("does-not-exist"), "PB-E0015", |e| {
        matches!(e, PumpBinError::PluginNotFound { .. })
    });
}

// ── Unique codes across all variants ─────────────────────────────────────

#[test]
fn all_codes_are_unique_and_well_formed() {
    // Construct one of each variant we can build cheaply.
    let variants: Vec<PumpBinError> = vec![
        PumpBinError::PlaceholderNotFound { holder: "x".into() },
        PumpBinError::ReplacementTooLong { got: 1, max: 0 },
        PumpBinError::ShellcodeSourceEmpty,
        PumpBinError::ShellcodeFileNotFound { path: "x".into() },
        PumpBinError::ShellcodeReadFailed {
            path: "x".into(),
            source: std::io::Error::other("x"),
        },
        PumpBinError::ShellcodeFileEmpty { path: "x".into() },
        PumpBinError::ShellcodeContainsPlaceholder { path: "x".into() },
        PumpBinError::RemoteUrlInvalidScheme { url: "x".into() },
        PumpBinError::BinaryNotInPlugin {
            platform: "x".into(),
            bin_type: "x".into(),
        },
        PumpBinError::LocalRequiresSizeHolder,
        PumpBinError::MaxLenZero,
        PumpBinError::ShellcodeTooLong {
            kind: "x",
            got: 0,
            max: 0,
        },
        PumpBinError::SizeStringTooLong {
            got: 0,
            holder_len: 0,
        },
        PumpBinError::ConfigPathUnavailable { what: "x" },
        PumpBinError::PluginNotFound { name: "x".into() },
        PumpBinError::WasmCallFailed {
            hook: "x".into(),
            detail: "x".into(),
        },
        PumpBinError::MakerFieldEmpty { field: "x" },
        PumpBinError::MakerSourcePrefixCollision,
        PumpBinError::MakerPreflightFailed { report: "x".into() },
        PumpBinError::MakerMaxLenInvalid { reason: "x" },
        // v1.1.7 WASM policy variants
        PumpBinError::WasmHostDenied {
            module: "x".into(),
            host: "x".into(),
        },
        PumpBinError::WasmSdkVersionMismatch {
            module: "x".into(),
            declared: 99,
            host_version: 1,
        },
        PumpBinError::WasmTimeoutInvalid {
            module: "x".into(),
            timeout_ms: 0,
        },
    ];

    use std::collections::HashSet;
    let codes: Vec<&str> = variants.iter().map(|v| v.code()).collect();
    let unique: HashSet<&&str> = codes.iter().collect();
    assert_eq!(
        codes.len(),
        unique.len(),
        "duplicate error codes detected: {codes:?}"
    );
    for c in &codes {
        // Format: "PB-E" + 4 decimal digits = 8 chars total.
        assert!(
            c.starts_with("PB-E") && c.len() == 8,
            "malformed code {c:?} (len={})",
            c.len()
        );
        let n: u16 = c[4..].parse().expect("numeric suffix");
        assert!(n > 0, "code numbers must be > 0");
    }
}
