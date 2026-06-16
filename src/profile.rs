//! `pumpbin.toml` profile schema and execution.
//!
//! A *profile* is a single TOML file that captures everything needed to
//! reproduce an implant build: which plugin, which shellcode, which
//! platform / binary type, what to override in the module config, and
//! where to write the output. The CLI's `pumpbin-cli build -f
//! pumpbin.toml` reads a profile and runs the same code path the
//! ad-hoc-flags `generate` subcommand uses.
//!
//! This is the v1.3.0 chip of v2.0 Phase 1. It ships the profile +
//! execute API; the planned `--json` versioned output, `inspect`
//! subcommand, and SBOM (`<output>.pbom.json`) land in follow-up
//! v1.3.x or v2.0 chips.
//!
//! # Schema example
//!
//! ```toml
//! schema = "pumpbin.profile/v1"
//!
//! [pack]
//! source = "/path/to/plugin.b1n"
//!
//! [target]
//! platform = "windows"      # windows | linux | darwin
//! binary_type = "exe"       # exe | lib
//!
//! [shellcode]
//! source = "file"           # file | url | base64 | hex
//! path = "shellcode.bin"
//! # url = "https://..."     # for source = "url"
//! # data = "..."            # for source = "base64" or "hex"
//!
//! [module_config]
//! xor_key = 42
//! multi_byte = true
//!
//! [output]
//! path = "./out/implant.exe"   # explicit output path
//! ```
//!
//! Fields not listed are intentionally omitted from v1.3.0: `preset` and
//! the `output.name_template` + `output.sbom` keys ship in Phase 2 +
//! later Phase 1 chips.

use crate::error::PumpBinError;
use crate::plugin::Plugin;
use crate::{BinaryType, Platform, ShellcodeSaveType};
use anyhow::Context;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Profile schema version. Bump on breaking changes to the TOML shape.
pub const PROFILE_SCHEMA: &str = "pumpbin.profile/v1";

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Profile {
    /// Schema identifier. Must equal `PROFILE_SCHEMA` (currently
    /// `"pumpbin.profile/v1"`). Mismatch refuses load.
    pub schema: String,
    pub pack: PluginRef,
    pub target: TargetSpec,
    pub shellcode: ShellcodeSource,
    /// Module config overrides. Keys + values flow through to
    /// `Plugin::replace_binary` as the `runtime_config` argument.
    #[serde(default)]
    pub module_config: BTreeMap<String, String>,
    pub output: OutputSpec,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PluginRef {
    /// Filesystem path to a `.b1n` loader pack.
    pub source: PathBuf,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TargetSpec {
    pub platform: String,
    pub binary_type: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "source", rename_all = "snake_case")]
pub enum ShellcodeSource {
    File { path: PathBuf },
    Url { url: String },
    Base64 { data: String },
    Hex { data: String },
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct OutputSpec {
    pub path: PathBuf,
    /// When true, `Profile::execute` writes a `<output>.pbom.json`
    /// SBOM alongside the implant. Default: false.
    #[serde(default)]
    pub sbom: bool,
}

/// Outcome of a successful build.
#[derive(Debug, Clone, Serialize)]
pub struct BuildArtifact {
    pub output_path: PathBuf,
    pub bytes_written: usize,
    /// Path to the emitted `.pbom.json` SBOM, if `output.sbom = true`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sbom_path: Option<PathBuf>,
}

impl Profile {
    /// Read + parse a profile from disk. Validates `schema` matches the
    /// host's `PROFILE_SCHEMA` constant.
    pub fn from_toml(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let path = path.as_ref();
        let raw = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("Failed to read profile {}: {}", path.display(), e))?;
        let profile: Profile = toml::from_str(&raw)
            .map_err(|e| anyhow::anyhow!("Profile {} is not valid TOML: {}", path.display(), e))?;
        if profile.schema != PROFILE_SCHEMA {
            return Err(PumpBinError::ProfileSchemaUnsupported {
                schema: profile.schema,
                expected: PROFILE_SCHEMA.to_string(),
            }
            .into());
        }
        Ok(profile)
    }

    /// Execute the profile end-to-end: load the plugin, resolve the
    /// shellcode source, run validate + replace_binary + post_binary,
    /// write the output via `utils::atomic_write`.
    ///
    /// The shellcode source resolution mirrors `pumpbin-cli generate`:
    /// File reads the path and passes to `Plugin::replace_binary` as a
    /// Local-mode shellcode_src. Url passes the URL as a Remote-mode
    /// shellcode_src. Base64 / Hex decode to a tempfile and pass the
    /// tempfile path (Local mode).
    pub fn execute(&self) -> anyhow::Result<BuildArtifact> {
        let platform = parse_platform(&self.target.platform)?;
        let binary_type = parse_binary_type(&self.target.binary_type)?;

        let plugin_bytes = std::fs::read(&self.pack.source).map_err(|e| {
            anyhow::anyhow!(
                "Failed to read plugin {}: {}\n\
                 hint: run `pumpbin-cli create-b1n --help` to build a \
                 loader pack from a loader template, or copy one of the \
                 fixture .b1n files under pumpbin/tests/fixtures/qa/.",
                self.pack.source.display(),
                e
            )
        })?;
        let plugin = Plugin::decode_from_slice(&plugin_bytes)?;

        plugin.validate_for_generation(platform, binary_type)?;
        let bin = plugin
            .bins()
            .get_that_binary(platform, binary_type)
            .map(|b| b.to_vec())
            .ok_or_else(|| PumpBinError::BinaryNotInPlugin {
                platform: platform.to_string(),
                bin_type: binary_type.to_string(),
            })?;

        // Resolve shellcode source. For File and Base64/Hex we end up
        // with a path on disk that the existing Local-mode flow reads;
        // for Url we hand the URL string through as Remote-mode.
        let _tmp_holder: Option<tempfile::NamedTempFile>;
        let shellcode_src = match &self.shellcode {
            ShellcodeSource::File { path } => {
                _tmp_holder = None;
                path.to_string_lossy().into_owned()
            }
            ShellcodeSource::Url { url } => {
                // Sanity-check that the plugin is in Remote mode.
                if plugin.save_type() != ShellcodeSaveType::Remote {
                    anyhow::bail!(
                        "Profile has shellcode source=url but plugin is Local-mode \
                         (no size_holder). Mismatched profile + plugin combination."
                    );
                }
                _tmp_holder = None;
                url.clone()
            }
            ShellcodeSource::Base64 { data } => {
                use base64::Engine;
                let decoded = base64::engine::general_purpose::STANDARD
                    .decode(data.trim())
                    .map_err(|e| anyhow::anyhow!("shellcode.data base64 decode: {e}"))?;
                let tmp = tempfile::NamedTempFile::new()?;
                std::fs::write(tmp.path(), &decoded)?;
                let path = tmp.path().to_string_lossy().into_owned();
                _tmp_holder = Some(tmp);
                path
            }
            ShellcodeSource::Hex { data } => {
                let cleaned: String = data
                    .chars()
                    .filter(|c| !c.is_whitespace() && *c != ',' && *c != ':')
                    .collect();
                let decoded = hex_decode(&cleaned)?;
                let tmp = tempfile::NamedTempFile::new()?;
                std::fs::write(tmp.path(), &decoded)?;
                let path = tmp.path().to_string_lossy().into_owned();
                _tmp_holder = Some(tmp);
                path
            }
        };

        plugin.validate_shellcode_source(&shellcode_src)?;

        let runtime_config = if self.module_config.is_empty() {
            None
        } else {
            Some(&self.module_config)
        };

        let build_start = std::time::Instant::now();

        // Capture shellcode bytes for the SBOM hash before replace_binary
        // takes ownership. Local mode reads from disk; Remote mode hashes
        // the URL bytes (it's what gets embedded in the implant anyway).
        let shellcode_for_sbom: Vec<u8> = match &self.shellcode {
            ShellcodeSource::Url { url } => url.as_bytes().to_vec(),
            _ => std::fs::read(&shellcode_src).context("re-reading shellcode for SBOM hash")?,
        };

        let shellcode_src_for_sbom = shellcode_src.clone();
        let bin = plugin.replace_binary(bin, shellcode_src, vec![], runtime_config)?;
        let bytes_written = bin.len();

        crate::utils::atomic_write(&self.output.path, &bin)?;

        // SBOM emission (opt-in via output.sbom = true).
        let sbom_path = if self.output.sbom {
            let sbom_path = sbom_companion_path(&self.output.path);
            let build_id = build_id_for_run();
            let duration_ms = build_start.elapsed().as_millis();
            let sbom = crate::sbom::build_sbom(&crate::sbom::SbomInputs {
                build_id: &build_id,
                plugin_path: &self.pack.source,
                plugin_bytes: &plugin_bytes,
                shellcode_src: &shellcode_src_for_sbom,
                shellcode_bytes: &shellcode_for_sbom,
                output_path: &self.output.path,
                platform: &self.target.platform,
                binary_type: &self.target.binary_type,
                plugin_name: plugin.info().plugin_name(),
                plugin_version: plugin.info().version(),
                config: &self.module_config,
                modules: plugin.plugins().modules(),
                output_bytes: bytes_written,
                duration_ms,
            });
            crate::sbom::write_sbom(&sbom, &sbom_path)?;
            Some(sbom_path)
        } else {
            None
        };

        Ok(BuildArtifact {
            output_path: self.output.path.clone(),
            bytes_written,
            sbom_path,
        })
    }
}

fn sbom_companion_path(output: &std::path::Path) -> PathBuf {
    let file_name = output
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "implant".to_string());
    let parent = output.parent().unwrap_or(std::path::Path::new("."));
    parent.join(format!("{file_name}.pbom.json"))
}

/// Build-time identifier shared between the JSON log filename and the
/// SBOM build_id. Matches the format used in `logging::build_id`.
fn build_id_for_run() -> String {
    let ts = chrono::Local::now().format("%Y%m%d-%H%M%S");
    let pid = std::process::id();
    format!("{ts}-{pid}")
}

fn parse_platform(s: &str) -> anyhow::Result<Platform> {
    match s.to_ascii_lowercase().as_str() {
        "windows" => Ok(Platform::Windows),
        "linux" => Ok(Platform::Linux),
        "darwin" | "macos" => Ok(Platform::Darwin),
        other => Err(PumpBinError::ProfileFieldInvalid {
            field: "target.platform",
            value: other.to_string(),
            expected: "windows, linux, darwin",
        }
        .into()),
    }
}

fn parse_binary_type(s: &str) -> anyhow::Result<BinaryType> {
    match s.to_ascii_lowercase().as_str() {
        "exe" | "executable" => Ok(BinaryType::Executable),
        "lib" | "dll" | "so" | "dylib" => Ok(BinaryType::DynamicLibrary),
        other => Err(PumpBinError::ProfileFieldInvalid {
            field: "target.binary_type",
            value: other.to_string(),
            expected: "exe, lib",
        }
        .into()),
    }
}

/// Minimal hex decoder. Even-length hex string → bytes. Rejects
/// odd-length input and non-hex chars (after the caller has stripped
/// whitespace and the common `:`/`,` separators).
fn hex_decode(s: &str) -> anyhow::Result<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        anyhow::bail!(
            "shellcode.data hex length is odd ({}); needs full bytes",
            s.len()
        );
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for i in (0..s.len()).step_by(2) {
        let byte = u8::from_str_radix(&s[i..i + 2], 16)
            .map_err(|e| anyhow::anyhow!("hex parse at offset {i}: {e}"))?;
        out.push(byte);
    }
    Ok(out)
}
