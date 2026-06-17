//! `.b1n` assembly. Shared between `pumpbin-cli create-b1n` (low-level
//! flag-driven) and `pumpbin-cli pack` (reads `[package.metadata.pumpbin]`
//! from a scaffolded Cargo crate, runs `cargo build --release`, packs).
//!
//! The `B1nBuilder` owns the plugin-assembly logic that both CLI paths
//! call into. Adding new fields here is the single edit point for both.

use anyhow::{anyhow, Context, Result};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::plugin::{Plugin, PluginInfo, PluginReplace};
use crate::{BinaryType, Platform, ShellcodeSaveType};

/// Inputs to assemble a `.b1n` loader pack. Field meanings mirror the
/// `pumpbin-cli create-b1n` CLI flags one-for-one — see that subcommand
/// for the operator-facing names.
pub struct B1nBuilder {
    pub template_bytes: Vec<u8>,
    pub name: String,
    pub author: String,
    pub plugin_version: String,
    pub desc: String,
    pub platform: Platform,
    pub binary_type: BinaryType,
    pub save_type: ShellcodeSaveType,
    pub src_prefix: String,
    pub size_holder: String,
    /// `None` = auto-measure the contiguous padding run after `src_prefix`
    /// in the template and use that. `Some(n)` = explicit override; fails
    /// if `n` exceeds the measured capacity.
    pub max_len_override: Option<u64>,
    pub primary_module: Option<String>,
    pub post_modules: Vec<String>,
    /// Pre-parsed module config, keyed by module id (for example `post:byte-patch`).
    pub module_config: BTreeMap<String, String>,
}

impl B1nBuilder {
    /// Build the binary-encoded `.b1n` bytes. Caller decides how to
    /// persist them (atomic file write, stdout, in-memory test, etc).
    pub fn assemble(self) -> Result<Vec<u8>> {
        let Self {
            template_bytes,
            name,
            author,
            plugin_version,
            desc,
            platform,
            binary_type,
            save_type,
            src_prefix,
            size_holder,
            max_len_override,
            primary_module,
            post_modules,
            module_config,
        } = self;

        let mut plugin = Plugin {
            version: env!("CARGO_PKG_VERSION").to_string(),
            info: PluginInfo {
                plugin_name: name,
                author,
                version: plugin_version,
                desc,
            },
            replace: PluginReplace {
                src_prefix: src_prefix.as_bytes().to_vec(),
                size_holder: match save_type {
                    ShellcodeSaveType::Local => Some(size_holder.as_bytes().to_vec()),
                    ShellcodeSaveType::Remote => None,
                },
                max_len: 0,
            },
            ..Default::default()
        };

        // Preflight: marker bytes must actually exist in the template.
        // Without this, pumpbin-cli silently produced .b1n files that
        // failed at generate-time with "Holder '...' not found in binary".
        plugin
            .replace
            .preflight_template(&template_bytes)
            .context("template preflight")?;

        // Auto-detect placeholder capacity (the contiguous padding run
        // after src_prefix). Used as the default when max_len_override is
        // None; if it's Some and exceeds the detected capacity, refuse.
        let detected_capacity = plugin
            .replace
            .measure_placeholder_capacity(&template_bytes)
            .unwrap_or(0);
        plugin.replace.max_len = match max_len_override {
            Some(explicit) => {
                if explicit > detected_capacity as u64 && detected_capacity > 0 {
                    return Err(crate::error::PumpBinError::MaxLenExceedsCapacity {
                        max_len: explicit,
                        capacity: detected_capacity,
                        prefix: src_prefix,
                    }
                    .into());
                }
                explicit
            }
            None => {
                if detected_capacity == 0 {
                    return Err(crate::error::PumpBinError::CapacityAutoDetectFailed {
                        prefix: src_prefix,
                    }
                    .into());
                }
                detected_capacity as u64
            }
        };

        match (platform, binary_type) {
            (Platform::Windows, BinaryType::Executable) => {
                plugin.bins.windows.executable = Some(template_bytes);
            }
            (Platform::Windows, BinaryType::DynamicLibrary) => {
                plugin.bins.windows.dynamic_library = Some(template_bytes);
            }
            (Platform::Linux, BinaryType::Executable) => {
                plugin.bins.linux.executable = Some(template_bytes);
            }
            (Platform::Linux, BinaryType::DynamicLibrary) => {
                plugin.bins.linux.dynamic_library = Some(template_bytes);
            }
            (Platform::Darwin, BinaryType::Executable) => {
                plugin.bins.darwin.executable = Some(template_bytes);
            }
            (Platform::Darwin, BinaryType::DynamicLibrary) => {
                plugin.bins.darwin.dynamic_library = Some(template_bytes);
            }
        }

        if let Some(module_id) = primary_module {
            plugin.plugins.encrypt_shellcode = Some(module_id);
        }
        for id in post_modules {
            plugin.plugins.modules.push(id);
        }
        plugin.plugins.plugin_config = module_config.into_iter().collect();

        plugin.encode_to_vec()
    }
}

// ── pack: read [package.metadata.pumpbin] from a Cargo crate ───────────────

/// `[package.metadata.pumpbin]` schema. Required: `name`, `platform`.
/// Everything else has a sensible default that matches what `new-loader`
/// scaffolds.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoaderMetadata {
    pub name: String,
    pub platform: String,
    #[serde(default = "default_binary_type")]
    pub binary_type: String,
    #[serde(default = "default_src_prefix")]
    pub src_prefix: String,
    #[serde(default = "default_size_holder")]
    pub size_holder: String,
    #[serde(default = "default_save_type")]
    pub save_type: String,
    #[serde(default = "default_author")]
    pub author: String,
    #[serde(default = "default_desc")]
    pub description: String,
    #[serde(default = "default_plugin_version")]
    pub plugin_version: String,
    /// Auto-measure from the template if omitted (the recommended path).
    #[serde(default)]
    pub max_len: Option<u64>,
    /// Optional default post-build module chain baked into the .b1n.
    /// Operators can append further `--post` modules at generate time.
    #[serde(default)]
    pub post: Vec<PostEntry>,
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PostEntry {
    pub id: String,
    #[serde(default)]
    pub config: BTreeMap<String, String>,
}

fn default_binary_type() -> String {
    "exe".to_string()
}
fn default_src_prefix() -> String {
    crate::scaffold::DEFAULT_PREFIX.to_string()
}
fn default_size_holder() -> String {
    crate::scaffold::DEFAULT_SIZE_HOLDER.to_string()
}
fn default_save_type() -> String {
    "local".to_string()
}
fn default_author() -> String {
    "pumpbin-cli pack".to_string()
}
fn default_desc() -> String {
    "Built with pumpbin-cli pack".to_string()
}
fn default_plugin_version() -> String {
    "0.1.0".to_string()
}

/// Minimal Cargo.toml shape we care about: `[package]` for the binary
/// name, `[package.metadata.pumpbin]` for the loader config.
#[derive(Debug, serde::Deserialize)]
struct CargoToml {
    package: CargoPackage,
}

#[derive(Debug, serde::Deserialize)]
struct CargoPackage {
    name: String,
    #[serde(default)]
    metadata: Option<CargoPackageMetadata>,
}

#[derive(Debug, serde::Deserialize)]
struct CargoPackageMetadata {
    pumpbin: Option<LoaderMetadata>,
}

/// Read `<crate_dir>/Cargo.toml` and return both the cargo package name
/// (which determines the built binary's filename) and the loader metadata
/// block.
pub fn read_loader_metadata(crate_dir: &Path) -> Result<(String, LoaderMetadata)> {
    let cargo_toml_path = crate_dir.join("Cargo.toml");
    let raw = std::fs::read_to_string(&cargo_toml_path).with_context(|| {
        format!(
            "no Cargo.toml at {} — is this a scaffolded loader crate?",
            cargo_toml_path.display()
        )
    })?;
    let parsed: CargoToml = toml::from_str(&raw)
        .with_context(|| format!("failed to parse {} as TOML", cargo_toml_path.display()))?;
    let metadata = parsed
        .package
        .metadata
        .and_then(|m| m.pumpbin)
        .ok_or_else(|| {
            anyhow!(
                "no `[package.metadata.pumpbin]` block in {}. \
                 Add one (see `pumpbin-cli new-loader` output for the schema), \
                 or use `pumpbin-cli create-b1n` for ad-hoc packing.",
                cargo_toml_path.display()
            )
        })?;
    Ok((parsed.package.name, metadata))
}

/// Map the cargo binary name + the loader metadata's platform/binary_type
/// to where `cargo build --release` will drop the file on disk.
pub fn expected_artifact_path(
    crate_dir: &Path,
    cargo_pkg_name: &str,
    platform: Platform,
    binary_type: BinaryType,
    profile: &str,
) -> PathBuf {
    let dir = crate_dir.join("target").join(profile);
    let filename = match (platform, binary_type) {
        (Platform::Windows, BinaryType::Executable) => format!("{cargo_pkg_name}.exe"),
        (Platform::Windows, BinaryType::DynamicLibrary) => format!("{cargo_pkg_name}.dll"),
        (Platform::Linux, BinaryType::Executable) => cargo_pkg_name.to_string(),
        (Platform::Linux, BinaryType::DynamicLibrary) => format!("lib{cargo_pkg_name}.so"),
        (Platform::Darwin, BinaryType::Executable) => cargo_pkg_name.to_string(),
        (Platform::Darwin, BinaryType::DynamicLibrary) => format!("lib{cargo_pkg_name}.dylib"),
    };
    dir.join(filename)
}
