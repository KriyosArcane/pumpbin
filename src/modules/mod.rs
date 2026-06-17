pub mod dispatch;
pub mod encrypt;
pub mod external;
pub mod post_build;

use anyhow::Result;
use serde::Serialize;

use crate::plugin_system::EncryptShellcodeOutput;

#[derive(Debug, Clone, Default, Serialize)]
pub struct ModuleConstraints {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub host_platforms: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requires_platform: Option<crate::Platform>,
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
        out
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModuleKind {
    Encrypt,
    PostBuild,
}

impl ModuleKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Encrypt => "encrypt",
            Self::PostBuild => "post-build",
        }
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

impl ModuleArg {
    pub fn new(key: impl Into<String>, arg_type: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            arg_type: arg_type.into(),
            description: String::new(),
            required: false,
            default: None,
        }
    }
    pub fn required(mut self) -> Self {
        self.required = true;
        self
    }
    pub fn described(mut self, description: impl Into<String>) -> Self {
        self.description = description.into();
        self
    }
    pub fn default_val(mut self, default: impl Into<String>) -> Self {
        self.default = Some(default.into());
        self
    }
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
    fn args(&self) -> Vec<ModuleArg> {
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
    fn args(&self) -> Vec<ModuleArg> {
        Vec::new()
    }
    fn constraints(&self) -> ModuleConstraints {
        ModuleConstraints::default()
    }
    fn apply(&self, args: &[String], implant: &mut Vec<u8>) -> Result<()>;
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
        out.push(external_descriptor(module));
    }

    out
}

pub fn descriptor_for(kind: ModuleKind, id: &str) -> Option<ModuleDescriptor> {
    match kind {
        ModuleKind::Encrypt => encrypt_modules()
            .iter()
            .find(|module| module.id() == id)
            .map(|module| {
                builtin_descriptor(
                    module.id(),
                    kind,
                    module.description(),
                    module.args(),
                    module.constraints(),
                )
            }),
        ModuleKind::PostBuild => post_build_modules()
            .iter()
            .find(|module| module.id() == id)
            .map(|module| {
                builtin_descriptor(
                    module.id(),
                    kind,
                    module.description(),
                    module.args(),
                    module.constraints(),
                )
            }),
    }
    .or_else(|| {
        external::registry()
            .get(id)
            .filter(|module| module.kind().to_string() == kind.as_str())
            .map(external_descriptor)
    })
}

pub fn wire_kind_for(id: &str) -> Option<external::wire::WireKind> {
    if encrypt_modules().iter().any(|module| module.id() == id) {
        return Some(external::wire::WireKind::Encrypt);
    }
    if post_build_modules().iter().any(|module| module.id() == id) {
        return Some(external::wire::WireKind::PostBuild);
    }
    external::registry().get(id).map(|module| module.kind())
}

fn builtin_descriptor(
    id: &str,
    kind: ModuleKind,
    description: &str,
    args: Vec<ModuleArg>,
    constraints: ModuleConstraints,
) -> ModuleDescriptor {
    ModuleDescriptor {
        id: id.to_string(),
        kind: kind.as_str().to_string(),
        source: "built-in".to_string(),
        description: description.to_string(),
        args,
        constraints,
    }
}

fn external_descriptor(module: &external::ExternalModule) -> ModuleDescriptor {
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
    ModuleDescriptor {
        id: module.id().to_string(),
        kind: module.kind().to_string(),
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
    }
}
