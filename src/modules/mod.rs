//! Native Rust module traits.
//!
//! Replaces the Extism WASM plugin slots with statically-linked Rust
//! implementations. Each kind has its own trait (compile-time typed
//! input/output) and its own registry of `&'static dyn`-erased
//! implementations.
//!
//! Step 2 of the WASM-removal track: defines the surface only. Concrete
//! modules land in Step 3+.

pub mod dispatch;
pub mod encrypt;
pub mod external;
pub mod format_url;
pub mod post_build;

use anyhow::Result;

use crate::plugin_system::{EncryptShellcodeOutput, Pass};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModuleKind {
    Encrypt,
    FormatEncrypted,
    FormatUrl,
    UploadRemote,
    PostBuild,
}

/// Per-argument schema entry, surfaced by `pumpbin-cli list-modules
/// --options`. Built-in modules return a `Vec<ArgSpec>` from
/// `args()`; external modules carry their schema in the manifest
/// (see `external::wire::ManifestArg`) — both render uniformly in
/// the CLI.
#[derive(Debug, Clone)]
pub struct ArgSpec {
    pub key: &'static str,
    pub arg_type: &'static str,
    pub description: &'static str,
    pub required: bool,
    pub default: Option<&'static str>,
}

impl ArgSpec {
    pub const fn new(key: &'static str, arg_type: &'static str) -> Self {
        Self {
            key,
            arg_type,
            description: "",
            required: false,
            default: None,
        }
    }
    pub const fn required(mut self) -> Self {
        self.required = true;
        self
    }
    pub const fn described(mut self, d: &'static str) -> Self {
        self.description = d;
        self
    }
    pub const fn default_val(mut self, d: &'static str) -> Self {
        self.default = Some(d);
        self
    }
}

pub trait EncryptModule: Send + Sync {
    fn id(&self) -> &'static str;
    fn description(&self) -> &'static str;
    fn args(&self) -> Vec<ArgSpec> {
        Vec::new()
    }
    fn encrypt(&self, shellcode: &[u8]) -> Result<EncryptShellcodeOutput>;
}

pub trait FormatEncryptedModule: Send + Sync {
    fn id(&self) -> &'static str;
    fn description(&self) -> &'static str;
    fn args(&self) -> Vec<ArgSpec> {
        Vec::new()
    }
    fn format(&self, encrypted: &[u8]) -> Result<FormatEncryptedOutput>;
}

pub trait FormatUrlModule: Send + Sync {
    fn id(&self) -> &'static str;
    fn description(&self) -> &'static str;
    fn args(&self) -> Vec<ArgSpec> {
        Vec::new()
    }
    fn format(&self, url: &str) -> Result<String>;
}

pub trait UploadRemoteModule: Send + Sync {
    fn id(&self) -> &'static str;
    fn description(&self) -> &'static str;
    fn args(&self) -> Vec<ArgSpec> {
        Vec::new()
    }
    fn upload(&self, shellcode: &[u8]) -> Result<String>;
}

pub trait PostBuildModule: Send + Sync {
    fn id(&self) -> &'static str;
    fn description(&self) -> &'static str;
    fn args(&self) -> Vec<ArgSpec> {
        Vec::new()
    }
    fn apply(&self, args: &[String], implant: &mut Vec<u8>) -> Result<()>;
}

/// `format_encrypted_shellcode` reshapes the encrypted blob and may
/// emit additional placeholder-replacement pairs (e.g. a new key or
/// nonce that the format step introduced).
#[derive(Debug, Default, Clone)]
pub struct FormatEncryptedOutput {
    pub formatted: Vec<u8>,
    pub pass: Vec<Pass>,
}

pub fn encrypt_modules() -> &'static [&'static dyn EncryptModule] {
    &[&encrypt::aes256_gcm::AesGcm, &encrypt::xor::Xor]
}

pub fn format_encrypted_modules() -> &'static [&'static dyn FormatEncryptedModule] {
    &[]
}

pub fn format_url_modules() -> &'static [&'static dyn FormatUrlModule] {
    &[&format_url::prefix_suffix::PassThrough]
}

pub fn upload_remote_modules() -> &'static [&'static dyn UploadRemoteModule] {
    &[]
}

pub fn post_build_modules() -> &'static [&'static dyn PostBuildModule] {
    &[
        &post_build::pe_version_info::PeVersionInfo,
        &post_build::cert_blob_steal::CertBlobSteal,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aes_gcm_is_registered_in_encrypt_modules() {
        let ids: Vec<_> = encrypt_modules().iter().map(|m| m.id()).collect();
        assert!(ids.contains(&"aes-gcm"), "got {:?}", ids);
    }

    #[test]
    fn registries_reflect_step_4_ports() {
        let encrypt: Vec<_> = encrypt_modules().iter().map(|m| m.id()).collect();
        assert!(encrypt.contains(&"aes-gcm"));
        assert!(encrypt.contains(&"xor"));

        let urls: Vec<_> = format_url_modules().iter().map(|m| m.id()).collect();
        assert!(urls.contains(&"url-passthrough"));

        let post: Vec<_> = post_build_modules().iter().map(|m| m.id()).collect();
        assert!(post.contains(&"pe-version-info"));
        assert!(post.contains(&"cert-blob-steal"));

        assert!(format_encrypted_modules().is_empty());
        assert!(upload_remote_modules().is_empty());
    }

    #[test]
    fn module_kind_is_copy() {
        let k = ModuleKind::Encrypt;
        let _k2 = k;
        let _k3 = k;
    }
}
