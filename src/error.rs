//! Structured error type for PumpBin core.
//!
//! Every distinct failure condition in `plugin.rs`, `utils.rs`,
//! `plugin_system.rs`, and `maker.rs` is represented as a `PumpBinError`
//! variant with a stable `PB-Exxxx` code accessible via [`PumpBinError::code`].
//!
//! Most public APIs return `anyhow::Error`; callers that want
//! machine-readable error matching can downcast:
//!
//! ```ignore
//! match plugin.replace_binary(bin, src, pass, None) {
//!     Ok(out) => use(out),
//!     Err(e) => match e.downcast_ref::<PumpBinError>() {
//!         Some(PumpBinError::PlaceholderNotFound { holder, .. }) => ...,
//!         Some(other) => log::warn!("pb error {}: {}", other.code(), other),
//!         None => log::error!("unstructured anyhow: {e}"),
//!     }
//! }
//! ```
//!
//! The library boundaries return `anyhow::Error`; `PB-Exxxx` codes are the
//! stable contract for machine-readable matching.
//!
//! # Code allocation
//!
//! The `PB-Exxxx` numbering is a flat namespace, allocated chronologically.
//! Never reuse a number: retiring a variant means leaving a doc-only stub.
//! New variants get the next free number.

use thiserror::Error;

/// Result alias for APIs that return `PumpBinError` directly.
pub type PumpBinResult<T> = std::result::Result<T, PumpBinError>;

#[derive(Debug, Error)]
pub enum PumpBinError {
    // ── Replacement / template surface (utils.rs + plugin.rs preflight) ──
    /// PB-E0001: a required placeholder was not found inside a binary.
    /// Surfaces from both `utils::replace` (during generate) and
    /// `PluginReplace::preflight_template` (during create-b1n / maker save).
    #[error("[PB-E0001] Placeholder {holder:?} not found in binary")]
    PlaceholderNotFound { holder: String },

    /// PB-E0002: caller-supplied replacement bytes don't fit the placeholder
    /// slot. Carries the actual length and the slot's max so the user can
    /// shrink the input or grow the template.
    #[error("[PB-E0002] Replacement is {got} bytes but the slot accepts at most {max} bytes")]
    ReplacementTooLong { got: usize, max: usize },

    // ── Shellcode source validation (plugin.rs validate_shellcode_source) ──
    /// PB-E0003: shellcode source string (path or URL) is empty.
    #[error("[PB-E0003] Shellcode source cannot be empty")]
    ShellcodeSourceEmpty,

    /// PB-E0004: Local-mode shellcode path doesn't exist on disk.
    #[error("[PB-E0004] Shellcode file not found: {path}")]
    ShellcodeFileNotFound { path: String },

    /// PB-E0005: Local-mode shellcode path exists but couldn't be read
    /// (permissions, broken symlink, EIO, etc.).
    #[error("[PB-E0005] Failed to read shellcode file {path}: {source}")]
    ShellcodeReadFailed {
        path: String,
        source: std::io::Error,
    },

    /// PB-E0006: Local-mode shellcode file is zero bytes.
    #[error("[PB-E0006] Shellcode file is empty: {path}")]
    ShellcodeFileEmpty { path: String },

    /// PB-E0007: Shellcode file literally contains the bytes
    /// `$$SHELLCODE$$`: the user almost certainly passed the template
    /// binary by mistake instead of an actual payload.
    #[error("[PB-E0007] Shellcode file appears to be an unprocessed template (contains placeholder): {path}")]
    ShellcodeContainsPlaceholder { path: String },

    /// PB-E0008: Remote-mode shellcode source is not a recognized URL.
    #[error("[PB-E0008] Remote shellcode source must start with http:// or https://, got {url:?}")]
    RemoteUrlInvalidScheme { url: String },

    // ── Plugin / generate validation (plugin.rs validate_for_generation) ──
    /// PB-E0009: the loaded plugin doesn't ship a binary for the requested
    /// (platform, binary_type) tuple.
    #[error("[PB-E0009] Binary for {platform} ({bin_type}) is not included in this plugin")]
    BinaryNotInPlugin { platform: String, bin_type: String },

    /// PB-E0010: Local-mode plugins require a size_holder; this one has none.
    #[error("[PB-E0010] Local save type requires a size_holder, but none is defined")]
    LocalRequiresSizeHolder,

    /// PB-E0011: replace.max_len is zero, meaning there is nowhere to inject
    /// shellcode.
    #[error("[PB-E0011] Maximum shellcode length cannot be zero")]
    MaxLenZero,

    // ── Generate-time payload size checks (plugin.rs replace_binary) ──
    /// PB-E0012: encrypted shellcode (or URL bytes, for Remote mode)
    /// exceed the placeholder slot's max_len.
    #[error("[PB-E0012] {kind} is {got} bytes; placeholder slot accepts at most {max}")]
    ShellcodeTooLong {
        kind: &'static str, // "Shellcode" or "Shellcode URL"
        got: usize,
        max: usize,
    },

    /// PB-E0013: decimal shellcode-length string doesn't fit the
    /// size_holder slot (rare: needs > 99999999... bytes of shellcode).
    #[error("[PB-E0013] Shellcode size string is {got} bytes but the size_holder is {holder_len}")]
    SizeStringTooLong { got: usize, holder_len: usize },

    // ── Maker validation (maker.rs check_generate) ──
    /// PB-E0017: a required Maker form field is empty.
    #[error("[PB-E0017] Maker field {field:?} is empty")]
    MakerFieldEmpty { field: &'static str },

    /// PB-E0018: Maker prefix and size_holder are set to the same value.
    #[error("[PB-E0018] Maker size_holder cannot equal src_prefix")]
    MakerSourcePrefixCollision,

    /// PB-E0019: Maker preflight scan found one or more templates that
    /// don't contain the configured placeholders. Carries a multi-line
    /// human report listing each failing template.
    #[error("[PB-E0019] Maker preflight failed:\n{report}")]
    MakerPreflightFailed { report: String },

    /// PB-E0020: Maker max_len is invalid (empty, non-numeric, or zero).
    #[error("[PB-E0020] Maker max_len is invalid: {reason}")]
    MakerMaxLenInvalid { reason: &'static str },

    // ── Profile validation (profile.rs) ──
    /// PB-E0024: profile `schema` field doesn't match the host's expected
    /// schema version. The user needs to update the profile or upgrade
    /// PumpBin.
    #[error("[PB-E0024] Profile schema {schema:?} is not supported; host expects {expected:?}")]
    ProfileSchemaUnsupported { schema: String, expected: String },

    /// PB-E0025: a profile field (platform, binary_type, save type, etc.)
    /// contains a value that can't be parsed into its target enum.
    #[error("[PB-E0025] Invalid profile field {field}: {value:?} (expected one of: {expected})")]
    ProfileFieldInvalid {
        field: &'static str,
        value: String,
        expected: &'static str,
    },

    // ── Pack / B1nBuilder assembly (pack.rs) ──
    /// PB-E0026: explicit max_len exceeds measured padding capacity.
    #[error(
        "[PB-E0026] max_len {max_len} exceeds the {capacity} bytes of padding measured \
         after `{prefix}` in the template"
    )]
    MaxLenExceedsCapacity {
        max_len: u64,
        capacity: usize,
        prefix: String,
    },

    /// PB-E0027: auto-detection found zero padding after the prefix.
    #[error(
        "[PB-E0027] could not auto-detect placeholder capacity (no padding \
         after `{prefix}` in template). Set max_len explicitly."
    )]
    CapacityAutoDetectFailed { prefix: String },

    // ── General I/O ──
    /// PB-E0028: an I/O operation failed on a known path.
    #[error("[PB-E0028] I/O error on {path}: {source}")]
    IoFailed {
        path: String,
        source: std::io::Error,
    },
}

impl PumpBinError {
    /// Stable error identifier safe to match on from external tooling.
    /// Format: `"PB-Exxxx"`. Never reuse a code: retiring a variant means
    /// leaving the number doc-only.
    pub fn code(&self) -> &'static str {
        match self {
            Self::PlaceholderNotFound { .. } => "PB-E0001",
            Self::ReplacementTooLong { .. } => "PB-E0002",
            Self::ShellcodeSourceEmpty => "PB-E0003",
            Self::ShellcodeFileNotFound { .. } => "PB-E0004",
            Self::ShellcodeReadFailed { .. } => "PB-E0005",
            Self::ShellcodeFileEmpty { .. } => "PB-E0006",
            Self::ShellcodeContainsPlaceholder { .. } => "PB-E0007",
            Self::RemoteUrlInvalidScheme { .. } => "PB-E0008",
            Self::BinaryNotInPlugin { .. } => "PB-E0009",
            Self::LocalRequiresSizeHolder => "PB-E0010",
            Self::MaxLenZero => "PB-E0011",
            Self::ShellcodeTooLong { .. } => "PB-E0012",
            Self::SizeStringTooLong { .. } => "PB-E0013",
            Self::MakerFieldEmpty { .. } => "PB-E0017",
            Self::MakerSourcePrefixCollision => "PB-E0018",
            Self::MakerPreflightFailed { .. } => "PB-E0019",
            Self::MakerMaxLenInvalid { .. } => "PB-E0020",
            Self::ProfileSchemaUnsupported { .. } => "PB-E0024",
            Self::ProfileFieldInvalid { .. } => "PB-E0025",
            Self::MaxLenExceedsCapacity { .. } => "PB-E0026",
            Self::CapacityAutoDetectFailed { .. } => "PB-E0027",
            Self::IoFailed { .. } => "PB-E0028",
        }
    }
}

/// Bridge from the existing `utils::ReplaceError` so old callers keep
/// working while new code can match on `PumpBinError` codes via downcast.
impl From<crate::utils::ReplaceError> for PumpBinError {
    fn from(e: crate::utils::ReplaceError) -> Self {
        match e {
            crate::utils::ReplaceError::HolderNotFound(holder) => {
                Self::PlaceholderNotFound { holder }
            }
            crate::utils::ReplaceError::ReplacementTooLong(got, max) => {
                Self::ReplacementTooLong { got, max }
            }
        }
    }
}
