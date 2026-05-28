//! PumpBin Plugin SDK
//!
//! Add this crate as a dependency, then implement any of the hook functions
//! below. PumpBin calls whichever hooks your WASM exports; unexported hooks
//! are silently skipped.
//!
//! # Minimal example
//!
//! ```rust,ignore
//! use pumpbin_plugin_sdk::*;
//!
//! #[plugin_fn]
//! pub fn encrypt_shellcode(Json(input): Json<EncryptShellcodeInput>)
//!     -> FnResult<Json<EncryptShellcodeOutput>>
//! {
//!     // your encryption logic here
//!     Ok(Json(EncryptShellcodeOutput {
//!         encrypted: input.shellcode,
//!         pass: vec![],
//!     }))
//! }
//! ```

pub use extism_pdk::{self, config, host_fn, plugin_fn, FnResult, Json};
use serde::{Deserialize, Serialize};

pub mod host;

// ── Config access helper ──────────────────────────────────────────────────────

/// Read a runtime config value by key.
/// Returns `None` if the key is not set.
///
/// # Example
/// ```rust,ignore
/// let key = pumpbin_config!("my_key").unwrap_or_default();
/// ```
#[macro_export]
macro_rules! pumpbin_config {
    ($key:expr) => {
        $crate::config::get($key)
            .unwrap_or_default()
            .filter(|s| !s.is_empty())
    };
}

// ── Shared types ──────────────────────────────────────────────────────────────

/// A binary placeholder-replacement pair returned by `encrypt_shellcode`.
///
/// The `holder` bytes must exist in the compiled binary template as a
/// fixed-size placeholder. PumpBin replaces every occurrence with `replace_by`,
/// padding to the holder's length with trailing nulls if needed.
///
/// # Example
/// ```rust,ignore
/// Pass {
///     holder: b"$$KEY_32_BYTES_PLACEHOLDER______$$".to_vec(),
///     replace_by: my_aes_key.to_vec(),
/// }
/// ```
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Pass {
    pub holder: Vec<u8>,
    pub replace_by: Vec<u8>,
}

// ── Hook: encrypt_shellcode ───────────────────────────────────────────────────

/// Input for the `encrypt_shellcode` hook.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct EncryptShellcodeInput {
    /// Raw shellcode bytes read from disk.
    pub shellcode: Vec<u8>,
}

/// Output for the `encrypt_shellcode` hook.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct EncryptShellcodeOutput {
    /// The (possibly encrypted) shellcode to embed in the binary.
    pub encrypted: Vec<u8>,
    /// Placeholder replacements for keys, nonces, or other per-payload values.
    pub pass: Vec<Pass>,
}

// ── Hook: format_encrypted_shellcode ─────────────────────────────────────────

/// Input for the `format_encrypted_shellcode` hook.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct FormatEncryptedShellcodeInput {
    /// The shellcode (potentially already encrypted) from the previous stage.
    pub shellcode: Vec<u8>,
}

/// Output for the `format_encrypted_shellcode` hook.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct FormatEncryptedShellcodeOutput {
    /// Final bytes to embed in the binary placeholder region.
    pub formatted_shellcode: Vec<u8>,
}

// ── Hook: format_url_remote ───────────────────────────────────────────────────

/// Input for the `format_url_remote` hook (remote mode only).
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct FormatUrlRemoteInput {
    /// The raw shellcode URL entered by the operator.
    pub url: String,
}

/// Output for the `format_url_remote` hook.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct FormatUrlRemoteOutput {
    /// The URL (possibly modified) to embed in the binary.
    pub formatted_url: String,
}

// ── Hook: upload_final_shellcode_remote ───────────────────────────────────────

/// Input for the `upload_final_shellcode_remote` hook.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct UploadFinalShellcodeRemoteInput {
    /// Encrypted + formatted shellcode bytes to upload.
    pub final_shellcode: Vec<u8>,
}

/// Output for the `upload_final_shellcode_remote` hook.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct UploadFinalShellcodeRemoteOutput {
    /// URL where the shellcode was uploaded. Embedded in the binary.
    pub url: String,
}

// ── Hook: post_binary ────────────────────────────────────────────────────────

/// Input for the `post_binary` hook, called after all placeholder replacements.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct PostBinaryInput {
    /// The fully-generated binary with shellcode injected.
    pub final_binary: Vec<u8>,
    /// Reserved — always empty in current PumpBin versions.
    #[serde(default)]
    pub binary: Vec<u8>,
}

/// Output for the `post_binary` hook.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct PostBinaryOutput {
    /// The modified binary. Only used when `changed` is `true`.
    #[serde(default, alias = "binary")]
    pub final_binary: Vec<u8>,
    /// Set to `true` if you modified `final_binary`; `false` to leave it unchanged.
    #[serde(default)]
    pub changed: bool,
}

// ── Schema types ──────────────────────────────────────────────────────────────

/// A single configurable field shown in the PumpBin UI.
///
/// Return a list of these from `plugin_schema` to declare what runtime
/// config your plugin reads via `pumpbin_config!`.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct PluginConfigField {
    /// Config key name (matches what you pass to `pumpbin_config!`).
    pub key: String,
    /// UI widget type: `"text"`, `"password"`, `"file"`, `"file_base64"`,
    /// `"file_path"`, `"choice"`, `"boolean"`, `"number"`.
    #[serde(default, rename = "type")]
    pub field_type: String,
    /// Human-readable description shown in the UI.
    #[serde(default)]
    pub description: String,
    /// Whether PumpBin blocks generation if this field is empty.
    #[serde(default)]
    pub required: bool,
    /// Default value pre-filled in the UI.
    #[serde(default)]
    pub default: Option<String>,
    /// For `field_type = "choice"`: the allowed values.
    #[serde(default)]
    pub options: Vec<String>,
}

impl PluginConfigField {
    /// Convenience constructor.
    pub fn new(key: impl Into<String>, field_type: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            field_type: field_type.into(),
            ..Default::default()
        }
    }

    pub fn description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }

    pub fn required(mut self) -> Self {
        self.required = true;
        self
    }

    pub fn default(mut self, val: impl Into<String>) -> Self {
        self.default = Some(val.into());
        self
    }

    pub fn options(mut self, opts: Vec<impl Into<String>>) -> Self {
        self.options = opts.into_iter().map(Into::into).collect();
        self
    }
}

/// Current PumpBin SDK version. Bump on breaking schema changes only.
/// Plugins declare the SDK version they target via `RuntimeConfig::sdk_version`;
/// the host refuses to load a plugin whose declared version doesn't match.
/// `None` (the default when `runtime` is absent) is treated as "compatible
/// with any host" for backward compatibility with pre-1.1.7 plugins.
///
/// History:
/// - v1 (PumpBin 1.1.7): per-module runtime policy (timeout, allowed_hosts).
/// - v2 (PumpBin 1.5.0): host helper ABI (`host::pe`, `host::log`) via
///   Extism `with_function`. Additive — pre-v2 plugins still load.
pub const PUMPBIN_SDK_VERSION: u32 = 2;

/// Per-module runtime policy declared by the plugin author.
///
/// Returned as part of [`PluginConfigSchema`]. Every field has a safe default,
/// so older plugins that don't ship a `runtime` block run under the host's
/// strict defaults (3-second timeout, no network).
///
/// # Example
/// ```rust,ignore
/// PluginConfigSchema {
///     version: 1,
///     fields: vec![...],
///     runtime: Some(RuntimeConfig {
///         timeout_ms: 10_000,                    // signing can be slow
///         allowed_hosts: vec!["api.signer.example".into()],
///         on_error: OnError::Abort,
///         sdk_version: Some(PUMPBIN_SDK_VERSION),
///     }),
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeConfig {
    /// Maximum wall-clock time the module may run for one hook invocation.
    /// Default: 3000 ms. Bounds: 1..=600_000 ms (10 minutes).
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    /// Explicit allowlist of hosts the module may contact via Extism's
    /// HTTP host functions. Default: empty list = no network. Use `["*"]`
    /// only if your plugin genuinely needs unrestricted access (and only
    /// works when the host profile sets
    /// `security.allow_unrestricted_network = true`).
    #[serde(default)]
    pub allowed_hosts: Vec<String>,
    /// What the chain dispatcher does if this module returns an error.
    /// Default: `Abort` — stop the chain and bubble the error up.
    /// `Skip` — log and continue to the next module.
    #[serde(default)]
    pub on_error: OnError,
    /// The PumpBin SDK version this plugin was compiled against. Host
    /// compares against [`PUMPBIN_SDK_VERSION`]; mismatch on major version
    /// refuses to load. `None` is "any" for backward compatibility.
    #[serde(default)]
    pub sdk_version: Option<u32>,
}

fn default_timeout_ms() -> u64 {
    3000
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            timeout_ms: 3000,
            allowed_hosts: Vec::new(),
            on_error: OnError::Abort,
            sdk_version: Some(PUMPBIN_SDK_VERSION),
        }
    }
}

/// What the chain dispatcher does when a module errors.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OnError {
    /// Stop the chain and propagate the error.
    #[default]
    Abort,
    /// Log a warning and continue to the next module.
    Skip,
}

/// The schema returned by `plugin_schema`. Declares all config fields and
/// (optionally) the runtime policy this module needs.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct PluginConfigSchema {
    /// Schema version — set to `1`.
    #[serde(default)]
    pub version: u32,
    /// Ordered list of config fields.
    #[serde(default)]
    pub fields: Vec<PluginConfigField>,
    /// Per-module runtime policy. `None` means the host applies safe
    /// defaults (3s timeout, no network, abort-on-error).
    #[serde(default)]
    pub runtime: Option<RuntimeConfig>,
}

impl PluginConfigSchema {
    pub fn new(fields: Vec<PluginConfigField>) -> Self {
        Self {
            version: 1,
            fields,
            runtime: None,
        }
    }

    /// Attach a runtime policy. Chainable on top of `new`.
    pub fn with_runtime(mut self, runtime: RuntimeConfig) -> Self {
        self.runtime = Some(runtime);
        self
    }
}
