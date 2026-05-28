//! Data types shared across pumpbin (CLI, lib, modules, tests).
//!
//! Pre-v2.0.0 this module also hosted the Extism wasm dispatch
//! surface (ResolvedPolicy, manifest_from_wasm_with_policy,
//! build_plugin, resolve_policy, run_module, run_plugin,
//! get_plugin_config_schema, EventManager). All of that was deleted
//! when wasm plugins were replaced with native Rust modules
//! (`crate::modules::*`). Dispatch now lives in
//! `crate::modules::dispatch`.

use serde::{Deserialize, Serialize};

// ── Schema types ─────────────────────────────────────────────────────────────
//
// Native modules don't currently declare schemas; these types are
// retained because the GUI maker and CLI still render config forms
// from `Vec<PluginConfigField>` and we don't want to churn that
// surface in this PR. `get_plugin_config_schema` is a stub that
// returns `Ok(None)` for every module id — Step 7+ will wire up
// per-module schemas.

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct PluginConfigField {
    pub key: String,
    #[serde(default, rename = "type")]
    pub field_type: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub required: bool,
    #[serde(default)]
    pub default: Option<String>,
    #[serde(default)]
    pub options: Vec<String>,
}

/// Retained for binary-format provenance. Pre-v2.0.0 this was bumped
/// on every host-helper ABI change; in v2.0 there is no host-helper
/// ABI. Old .b1n files that pin a higher value get a clear decode
/// error elsewhere.
pub const PUMPBIN_SDK_VERSION: u32 = 2;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeConfig {
    #[serde(default)]
    pub timeout_ms: u64,
    #[serde(default)]
    pub allowed_hosts: Vec<String>,
    #[serde(default)]
    pub on_error: OnError,
    #[serde(default)]
    pub sdk_version: Option<u32>,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            timeout_ms: 3000,
            allowed_hosts: Vec::new(),
            on_error: OnError::default(),
            sdk_version: Some(PUMPBIN_SDK_VERSION),
        }
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OnError {
    #[default]
    Abort,
    Skip,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct PluginConfigSchema {
    #[serde(default)]
    pub version: u32,
    #[serde(default)]
    pub fields: Vec<PluginConfigField>,
    #[serde(default)]
    pub runtime: Option<RuntimeConfig>,
}

/// v1.x compatibility stub. Pre-v2.0.0 this loaded a wasm module via
/// Extism and called its `plugin_schema` export; that path is gone.
/// Native modules don't yet expose a runtime-discoverable schema, so
/// callers get `Ok(None)` and fall back to their own defaults.
pub fn get_plugin_config_schema(_module_id: &str) -> anyhow::Result<Option<PluginConfigSchema>> {
    Ok(None)
}

// ── I/O types (shared between host, native modules, and tests) ─────────────

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct EncryptShellcodeInput {
    pub shellcode: Vec<u8>,
}

/// A placeholder-replacement pair returned by `encrypt_shellcode`.
///
/// `holder` must be present as a fixed-length byte sequence in the binary
/// template. PumpBin finds it with memmem and overwrites it with `replace_by`,
/// padded to the holder's length.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Pass {
    pub holder: Vec<u8>,
    pub replace_by: Vec<u8>,
}

impl Pass {
    pub fn holder(&self) -> &[u8] {
        &self.holder
    }
    pub fn replace_by(&self) -> &[u8] {
        &self.replace_by
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct EncryptShellcodeOutput {
    pub encrypted: Vec<u8>,
    pub pass: Vec<Pass>,
}

impl EncryptShellcodeOutput {
    pub fn encrypted(&self) -> &[u8] {
        &self.encrypted
    }
    pub fn pass(&self) -> &[Pass] {
        &self.pass
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct FormatEncryptedShellcodeInput {
    pub shellcode: Vec<u8>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct FormatEncryptedShellcodeOutput {
    pub formatted_shellcode: Vec<u8>,
}

impl FormatEncryptedShellcodeOutput {
    pub fn formatted_shellcode(&self) -> &[u8] {
        &self.formatted_shellcode
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct FormatUrlRemoteInput {
    pub url: String,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct FormatUrlRemoteOutput {
    pub formatted_url: String,
}

impl FormatUrlRemoteOutput {
    pub fn formatted_url(&self) -> &str {
        &self.formatted_url
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct UploadFinalShellcodeRemoteInput {
    pub final_shellcode: Vec<u8>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct UploadFinalShellcodeRemoteOutput {
    pub final_shellcode_url: String,
}

impl UploadFinalShellcodeRemoteOutput {
    pub fn final_shellcode_url(&self) -> &str {
        &self.final_shellcode_url
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct PostBinaryInput {
    pub binary: Vec<u8>,
    pub final_binary: Vec<u8>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct PostBinaryOutput {
    pub final_binary: Vec<u8>,
    pub changed: bool,
}
