use anyhow::Context;
use std::{collections::BTreeMap, time::Duration};

use extism::{Manifest, Wasm};
use serde::{Deserialize, Serialize};

fn manifest_from_wasm(wasm: &[u8], timeout_secs: u64) -> anyhow::Result<Manifest> {
    let manifest = if wasm.starts_with(b"\0asm") {
        Manifest::new([Wasm::data(wasm.to_vec())])
    } else {
        serde_json::from_slice::<Manifest>(wasm).with_context(|| {
            "module bytes are neither raw wasm (\\0asm) nor valid Extism Manifest JSON"
        })?
    };

    Ok(manifest
        .with_timeout(Duration::from_secs(timeout_secs))
        .with_allowed_host("*"))
}

fn is_missing_export(message: &str) -> bool {
    let msg = message.to_ascii_lowercase();
    (msg.contains("not found") || msg.contains("missing"))
        && (msg.contains("function") || msg.contains("export"))
}

// ── Schema types (mirrored in plugin-sdk for WASM authors) ────────────────────

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

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct PluginConfigSchema {
    #[serde(default)]
    pub version: u32,
    #[serde(default)]
    pub fields: Vec<PluginConfigField>,
}

// ── Module invocation ─────────────────────────────────────────────────────────

/// Call a single WASM module's exported function with JSON input.
/// Returns `None` if the function is not exported (optional hook).
pub fn run_module<T: Serialize>(
    wasm: &[u8],
    func: &str,
    input: &T,
    config: Option<&BTreeMap<String, String>>,
) -> anyhow::Result<Option<Vec<u8>>> {
    let mut manifest = manifest_from_wasm(wasm, 5)?;

    if let Some(cfg) = config {
        manifest = manifest.with_config(cfg.clone().into_iter());
    }

    let mut plugin = extism::Plugin::new(manifest, [], true)?;

    match plugin.call::<Vec<u8>, Vec<u8>>(func, serde_json::to_vec(input)?) {
        Ok(output) => Ok(Some(output)),
        Err(e) => {
            // Modules don't have to export every hook — treat missing exports as no-op.
            if is_missing_export(&e.to_string()) {
                Ok(None)
            } else {
                Err(anyhow::anyhow!("module call '{}' failed: {}", func, e))
            }
        }
    }
}

/// Kept for backwards-compatibility callers inside plugin.rs.
#[inline]
pub fn run_plugin<T: Serialize>(
    wasm: &[u8],
    func: &str,
    input: &T,
    config: Option<&BTreeMap<String, String>>,
) -> anyhow::Result<Option<Vec<u8>>> {
    run_module(wasm, func, input, config)
}

/// Load and call `plugin_schema` from a WASM module.
/// Returns `None` if the module does not export the function.
pub fn get_plugin_config_schema(wasm: &[u8]) -> anyhow::Result<Option<PluginConfigSchema>> {
    let manifest = manifest_from_wasm(wasm, 3)?;

    let mut plugin = extism::Plugin::new(manifest, [], true)?;

    match plugin.call::<Vec<u8>, Vec<u8>>("plugin_schema", Vec::new()) {
        Ok(output) => Ok(Some(serde_json::from_slice(output.as_slice())?)),
        Err(e) => {
            if is_missing_export(&e.to_string()) {
                Ok(None)
            } else {
                Err(e)
            }
        }
    }
}

// ── Event dispatch ────────────────────────────────────────────────────────────

pub struct EventManager;

impl EventManager {
    /// Call the first module that exports `hook_name` and return its output.
    /// Modules that don't export the hook are skipped transparently.
    /// Use this for all hooks except `post_binary`.
    pub fn fire<T: Serialize, R: serde::de::DeserializeOwned>(
        modules: &[Vec<u8>],
        hook_name: &str,
        input: &T,
        config: Option<&BTreeMap<String, String>>,
    ) -> anyhow::Result<Option<R>> {
        for wasm in modules {
            if let Some(res) = run_module(wasm, hook_name, input, config)? {
                return Ok(Some(serde_json::from_slice(&res)?));
            }
        }
        Ok(None)
    }

    /// Run `post_binary` through ALL modules in order, passing the output of
    /// each into the next. This allows chaining: e.g. strip → sign → obfuscate.
    /// A module that doesn't export `post_binary` is skipped.
    pub fn fire_post_binary(
        modules: &[Vec<u8>],
        initial: Vec<u8>,
        config: Option<&BTreeMap<String, String>>,
    ) -> anyhow::Result<Vec<u8>> {
        let mut binary = initial;

        for wasm in modules {
            let input = PostBinaryInput {
                final_binary: binary.clone(),
                binary: vec![],
            };

            if let Some(raw) = run_module(wasm, "post_binary", &input, config)? {
                let output: PostBinaryOutput = serde_json::from_slice(&raw)?;
                if output.changed && !output.final_binary.is_empty() {
                    binary = output.final_binary;
                }
            }
        }

        Ok(binary)
    }
}

// ── I/O types (host side) ─────────────────────────────────────────────────────

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
    pub url: String,
}

impl UploadFinalShellcodeRemoteOutput {
    pub fn url(&self) -> &str {
        &self.url
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct PostBinaryInput {
    pub final_binary: Vec<u8>,
    #[serde(default)]
    pub binary: Vec<u8>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct PostBinaryOutput {
    #[serde(default, alias = "binary")]
    pub final_binary: Vec<u8>,
    #[serde(default)]
    pub changed: bool,
}
