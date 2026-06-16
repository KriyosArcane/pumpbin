pub mod dispatch;
pub mod encrypt;
pub mod external;
pub mod post_build;

use anyhow::Result;
use serde::Serialize;

use crate::plugin_system::{EncryptShellcodeOutput, Pass};

#[derive(Debug, Clone, Default, Serialize)]
pub struct ModuleConstraints {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub host_platforms: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requires_platform: Option<crate::Platform>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requires_binary_type: Option<crate::BinaryType>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub incompatible_with: Vec<String>,
}

impl ModuleConstraints {
    pub fn display_strings(&self) -> Vec<String> {
        let mut out = Vec::new();
        if !self.host_platforms.is_empty() {
            out.push(format!(
                "host platforms: {}",
                self.host_platforms.join(", ")
            ));
        }
        if let Some(platform) = self.requires_platform {
            out.push(format!("target platform: {platform}"));
        }
        if let Some(binary_type) = self.requires_binary_type {
            out.push(format!("target type: {binary_type}"));
        }
        if !self.incompatible_with.is_empty() {
            out.push(format!(
                "incompatible with: {}",
                self.incompatible_with.join(", ")
            ));
        }
        out
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModuleKind {
    Encrypt,
    FormatEncrypted,
    FormatUrl,
    UploadRemote,
    PostBuild,
}

impl ModuleKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Encrypt => "encrypt",
            Self::FormatEncrypted => "format-encrypted",
            Self::FormatUrl => "format-url",
            Self::UploadRemote => "upload-remote",
            Self::PostBuild => "post-build",
        }
    }
}

/// Per-argument schema entry, surfaced by `pumpbin-cli module list
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

#[derive(Debug, Clone, Serialize)]
pub struct ModuleArg {
    pub key: String,
    pub arg_type: String,
    pub required: bool,
    pub default: Option<String>,
    pub description: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ModuleDescriptor {
    pub id: String,
    pub kind: String,
    pub source: String,
    pub description: String,
    pub args: Vec<ModuleArg>,
    pub constraints: ModuleConstraints,
}

impl ModuleDescriptor {
    pub fn allows_arbitrary_args_without_schema(&self) -> bool {
        self.source.starts_with("external:") && self.args.is_empty()
    }
}

pub trait EncryptModule: Send + Sync {
    fn id(&self) -> &'static str;
    fn description(&self) -> &'static str;
    fn args(&self) -> Vec<ArgSpec> {
        Vec::new()
    }
    fn constraints(&self) -> ModuleConstraints {
        ModuleConstraints::default()
    }
    fn encrypt(&self, shellcode: &[u8]) -> Result<EncryptShellcodeOutput>;
}

pub trait PostBuildModule: Send + Sync {
    fn id(&self) -> &'static str;
    fn description(&self) -> &'static str;
    fn args(&self) -> Vec<ArgSpec> {
        Vec::new()
    }
    fn constraints(&self) -> ModuleConstraints {
        ModuleConstraints::default()
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

pub fn post_build_modules() -> &'static [&'static dyn PostBuildModule] {
    &[
        &post_build::pe_version_info::PeVersionInfo,
        &post_build::byte_patch::BytePatch,
        &post_build::cert_graft::CertGraft,
    ]
}

pub fn descriptors() -> Vec<ModuleDescriptor> {
    let mut out = Vec::new();

    out.extend(encrypt_modules().iter().map(|m| {
        builtin_descriptor(
            m.id(),
            ModuleKind::Encrypt,
            m.description(),
            m.args(),
            m.constraints(),
        )
    }));
    out.extend(post_build_modules().iter().map(|m| {
        builtin_descriptor(
            m.id(),
            ModuleKind::PostBuild,
            m.description(),
            m.args(),
            m.constraints(),
        )
    }));

    for module in external::registry().all() {
        let kind = module.kind().to_string();
        let host_platforms = if module
            .manifest
            .platforms
            .iter()
            .any(|platform| platform == "any")
        {
            Vec::new()
        } else {
            module.manifest.platforms.clone()
        };
        out.push(ModuleDescriptor {
            id: module.id().to_string(),
            kind,
            source: format!("external: {}", module.manifest_path.display()),
            description: module.description().to_string(),
            args: module
                .manifest
                .args
                .iter()
                .map(|arg| ModuleArg {
                    key: arg.key.clone(),
                    arg_type: if arg.arg_type.is_empty() {
                        "string".to_string()
                    } else {
                        arg.arg_type.clone()
                    },
                    required: arg.required,
                    default: arg.default.clone(),
                    description: arg.description.clone(),
                })
                .collect(),
            constraints: ModuleConstraints {
                host_platforms,
                ..Default::default()
            },
        });
    }

    out
}

pub fn descriptor_for(kind: ModuleKind, id: &str) -> Option<ModuleDescriptor> {
    descriptors()
        .into_iter()
        .find(|descriptor| descriptor.kind == kind.as_str() && descriptor.id == id)
}

fn builtin_descriptor(
    id: &str,
    kind: ModuleKind,
    description: &str,
    args: Vec<ArgSpec>,
    constraints: ModuleConstraints,
) -> ModuleDescriptor {
    ModuleDescriptor {
        id: id.to_string(),
        kind: kind.as_str().to_string(),
        source: "built-in".to_string(),
        description: description.to_string(),
        args: args.into_iter().map(arg_from_spec).collect(),
        constraints,
    }
}

fn arg_from_spec(arg: ArgSpec) -> ModuleArg {
    ModuleArg {
        key: arg.key.to_string(),
        arg_type: arg.arg_type.to_string(),
        required: arg.required,
        default: arg.default.map(str::to_string),
        description: arg.description.to_string(),
    }
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

        let post: Vec<_> = post_build_modules().iter().map(|m| m.id()).collect();
        assert!(post.contains(&"pe-version-info"));
        assert!(
            !post.contains(&"cert-blob-steal"),
            "cert-blob-steal removed; use trustmebro external module"
        );
    }

    #[test]
    fn module_kind_is_copy() {
        let k = ModuleKind::Encrypt;
        let _k2 = k;
        let _k3 = k;
    }

    #[test]
    fn no_duplicate_module_ids() {
        let mut seen = std::collections::HashSet::new();
        for m in encrypt_modules() {
            assert!(seen.insert(m.id()), "duplicate: {}", m.id());
        }
        for m in post_build_modules() {
            assert!(seen.insert(m.id()), "duplicate: {}", m.id());
        }
    }

    #[test]
    fn all_modules_have_nonempty_id_and_description() {
        for m in encrypt_modules() {
            assert!(!m.id().is_empty());
            assert!(!m.description().is_empty());
        }
        for m in post_build_modules() {
            assert!(!m.id().is_empty());
            assert!(!m.description().is_empty());
        }
    }

    #[test]
    fn descriptors_include_built_in_args_and_constraints() {
        let descriptors = descriptors();
        let byte_patch = descriptors
            .iter()
            .find(|descriptor| descriptor.id == "byte-patch")
            .expect("byte-patch descriptor");
        assert_eq!(byte_patch.kind, "post-build");
        assert!(byte_patch
            .args
            .iter()
            .any(|arg| arg.key == "patches" && arg.required));

        let cert_graft = descriptors
            .iter()
            .find(|descriptor| descriptor.id == "cert-graft")
            .expect("cert-graft descriptor");
        assert_eq!(
            cert_graft.constraints.requires_platform,
            Some(crate::Platform::Windows)
        );
        assert!(cert_graft
            .constraints
            .display_strings()
            .iter()
            .any(|constraint| constraint == "target platform: Windows"));
    }

    #[test]
    fn descriptor_for_finds_kind_specific_module() {
        let descriptor =
            descriptor_for(ModuleKind::PostBuild, "byte-patch").expect("byte-patch descriptor");
        assert_eq!(descriptor.kind, ModuleKind::PostBuild.as_str());

        assert!(descriptor_for(ModuleKind::Encrypt, "byte-patch").is_none());
    }
}
