//! Data types shared across pumpbin (CLI, lib, modules, tests).

use serde::{Deserialize, Serialize};

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

pub fn get_plugin_config_schema(module_id: &str) -> anyhow::Result<Option<PluginConfigSchema>> {
    Ok(crate::modules::descriptors()
        .into_iter()
        .find(|descriptor| descriptor.id == module_id)
        .map(|descriptor| PluginConfigSchema {
            fields: descriptor
                .args
                .into_iter()
                .map(|arg| PluginConfigField {
                    key: arg.key,
                    field_type: arg.arg_type,
                    description: arg.description,
                    required: arg.required,
                    default: arg.default,
                    options: Vec::new(),
                })
                .collect(),
            ..Default::default()
        }))
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
