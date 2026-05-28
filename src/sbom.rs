//! Software Bill of Materials (SBOM) emission for `Profile::execute`.
//!
//! When `output.sbom = true` in a profile, `Profile::execute` writes a
//! companion `<output>.pbom.json` file documenting every input that
//! produced the build: plugin sha256, module sha256s, shellcode sha256,
//! runtime config (passwords redacted), build duration, builder identity.
//! Critical for legal red-team engagements where chain-of-custody matters.

use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::Path;

pub const SBOM_SCHEMA: &str = "pumpbin.sbom/v1";

#[derive(Debug, Clone, Serialize)]
pub struct Sbom {
    pub schema: &'static str,
    pub build_id: String,
    pub build_time: String,
    pub builder: Builder,
    pub plugin: PluginRecord,
    pub modules: Vec<ModuleRecord>,
    pub shellcode_sha256: String,
    pub shellcode_bytes: usize,
    pub runtime_config: BTreeMap<String, String>,
    pub output_path: String,
    pub output_bytes: usize,
    pub duration_ms: u128,
}

#[derive(Debug, Clone, Serialize)]
pub struct Builder {
    pub hostname: String,
    pub user: String,
    pub pumpbin_version: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct PluginRecord {
    pub source: String,
    pub name: String,
    pub version: String,
    pub sha256: String,
    pub size: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct ModuleRecord {
    pub index: usize,
    /// Module id (post-v2.0). Pre-v2.0 this was sha256 of the wasm bytes.
    pub id: String,
}

/// Build an `Sbom` from the inputs `Profile::execute` already has at the
/// end of a successful build. Reads each module's schema to harvest its
/// declared `sdk_version` for traceability.
#[allow(clippy::too_many_arguments)]
pub fn build_sbom(
    build_id: String,
    plugin_path: &Path,
    plugin_bytes: &[u8],
    plugin_name: &str,
    plugin_version: &str,
    modules: &[String],
    shellcode_bytes: &[u8],
    runtime_config: &BTreeMap<String, String>,
    output_path: &Path,
    output_bytes: usize,
    duration_ms: u128,
) -> Sbom {
    let module_records: Vec<_> = modules
        .iter()
        .enumerate()
        .map(|(idx, id)| ModuleRecord {
            index: idx,
            id: id.clone(),
        })
        .collect();

    Sbom {
        schema: SBOM_SCHEMA,
        build_id,
        build_time: chrono::Local::now().to_rfc3339(),
        builder: Builder {
            hostname: hostname().unwrap_or_else(|| "<unknown>".to_string()),
            user: std::env::var("USER")
                .or_else(|_| std::env::var("USERNAME"))
                .unwrap_or_else(|_| "<unknown>".to_string()),
            pumpbin_version: env!("CARGO_PKG_VERSION"),
        },
        plugin: PluginRecord {
            source: plugin_path.display().to_string(),
            name: plugin_name.to_string(),
            version: plugin_version.to_string(),
            sha256: sha256_hex(plugin_bytes),
            size: plugin_bytes.len(),
        },
        modules: module_records,
        shellcode_sha256: sha256_hex(shellcode_bytes),
        shellcode_bytes: shellcode_bytes.len(),
        runtime_config: redact_config(runtime_config),
        output_path: output_path.display().to_string(),
        output_bytes,
        duration_ms,
    }
}

/// Replace any config value whose key contains "password", "secret",
/// "token", "key", or "pfx" with `<redacted N chars>`. Keys are
/// case-insensitive matched.
fn redact_config(cfg: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for (k, v) in cfg {
        let kl = k.to_ascii_lowercase();
        let is_secret = ["password", "secret", "token", "_key", "pfx", "donor_pe_b64"]
            .iter()
            .any(|needle| kl.contains(needle));
        if is_secret {
            out.insert(k.clone(), format!("<redacted {} chars>", v.len()));
        } else {
            out.insert(k.clone(), v.clone());
        }
    }
    out
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    format!("{:x}", h.finalize())
}

fn hostname() -> Option<String> {
    std::env::var("HOSTNAME").ok().or_else(|| {
        std::process::Command::new("hostname")
            .output()
            .ok()
            .and_then(|o| {
                if o.status.success() {
                    Some(String::from_utf8_lossy(&o.stdout).trim().to_string())
                } else {
                    None
                }
            })
    })
}

/// Serialize an Sbom to pretty JSON and write to `path` via atomic_write.
pub fn write_sbom(sbom: &Sbom, path: &Path) -> anyhow::Result<()> {
    let json = serde_json::to_vec_pretty(sbom)?;
    crate::utils::atomic_write(path, &json)?;
    Ok(())
}
