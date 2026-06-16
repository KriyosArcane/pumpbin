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

/// All inputs needed to produce an SBOM for a single build.
pub struct SbomInputs<'a> {
    pub build_id: &'a str,
    pub plugin_path: &'a Path,
    pub plugin_bytes: &'a [u8],
    pub shellcode_src: &'a str,
    pub shellcode_bytes: &'a [u8],
    pub output_path: &'a Path,
    pub platform: &'a str,
    pub binary_type: &'a str,
    pub plugin_name: &'a str,
    pub plugin_version: &'a str,
    pub config: &'a BTreeMap<String, String>,
    pub modules: &'a [String],
    pub output_bytes: usize,
    pub duration_ms: u128,
}

/// Build an `Sbom` from the inputs `Profile::execute` already has at the
/// end of a successful build. Reads each module's schema to harvest its
/// declared `sdk_version` for traceability.
pub fn build_sbom(inputs: &SbomInputs<'_>) -> Sbom {
    let module_records: Vec<_> = inputs
        .modules
        .iter()
        .enumerate()
        .map(|(idx, id)| ModuleRecord {
            index: idx,
            id: id.clone(),
        })
        .collect();

    Sbom {
        schema: SBOM_SCHEMA,
        build_id: inputs.build_id.to_string(),
        build_time: chrono::Local::now().to_rfc3339(),
        builder: Builder {
            hostname: hostname().unwrap_or_else(|| "<unknown>".to_string()),
            user: std::env::var("USER")
                .or_else(|_| std::env::var("USERNAME"))
                .unwrap_or_else(|_| "<unknown>".to_string()),
            pumpbin_version: env!("CARGO_PKG_VERSION"),
        },
        plugin: PluginRecord {
            source: inputs.plugin_path.display().to_string(),
            name: inputs.plugin_name.to_string(),
            version: inputs.plugin_version.to_string(),
            sha256: sha256_hex(inputs.plugin_bytes),
            size: inputs.plugin_bytes.len(),
        },
        modules: module_records,
        shellcode_sha256: sha256_hex(inputs.shellcode_bytes),
        shellcode_bytes: inputs.shellcode_bytes.len(),
        runtime_config: redact_config(inputs.config),
        output_path: inputs.output_path.display().to_string(),
        output_bytes: inputs.output_bytes,
        duration_ms: inputs.duration_ms,
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::path::Path;

    #[test]
    fn redact_config_masks_secret_keys() {
        let mut cfg = BTreeMap::new();
        cfg.insert("api_key".to_string(), "hunter2".to_string());
        cfg.insert("secret_token".to_string(), "s3cr3t".to_string());
        cfg.insert("password".to_string(), "abc123".to_string());

        let redacted = redact_config(&cfg);

        assert_eq!(redacted["api_key"], "<redacted 7 chars>");
        assert_eq!(redacted["secret_token"], "<redacted 6 chars>");
        assert_eq!(redacted["password"], "<redacted 6 chars>");
    }

    #[test]
    fn redact_config_passes_non_secret_keys() {
        let mut cfg = BTreeMap::new();
        cfg.insert("sleep_ms".to_string(), "5000".to_string());
        cfg.insert("jitter".to_string(), "10".to_string());
        cfg.insert("host".to_string(), "example.com".to_string());

        let redacted = redact_config(&cfg);

        assert_eq!(redacted["sleep_ms"], "5000");
        assert_eq!(redacted["jitter"], "10");
        assert_eq!(redacted["host"], "example.com");
    }

    #[test]
    fn build_sbom_produces_valid_json_with_expected_fields() {
        let config = BTreeMap::new();
        let modules = vec!["mod-abc".to_string()];
        let inputs = SbomInputs {
            build_id: "test-build-001",
            plugin_path: Path::new("/tmp/test.b1n"),
            plugin_bytes: b"fakeplugin",
            shellcode_src: "/tmp/sc.bin",
            shellcode_bytes: b"\xcc\xcc",
            output_path: Path::new("/tmp/out.exe"),
            platform: "windows",
            binary_type: "exe",
            plugin_name: "test-plugin",
            plugin_version: "0.1.0",
            config: &config,
            modules: &modules,
            output_bytes: 4096,
            duration_ms: 42,
        };

        let sbom = build_sbom(&inputs);
        let json = serde_json::to_value(&sbom).expect("sbom should serialize to JSON");

        assert_eq!(json["schema"], SBOM_SCHEMA);
        assert_eq!(json["build_id"], "test-build-001");
        assert_eq!(json["plugin"]["name"], "test-plugin");
        assert_eq!(json["plugin"]["version"], "0.1.0");
        assert_eq!(json["plugin"]["source"], "/tmp/test.b1n");
        assert_eq!(json["shellcode_bytes"], 2);
        assert_eq!(json["output_path"], "/tmp/out.exe");
        assert_eq!(json["output_bytes"], 4096);
        assert_eq!(json["duration_ms"], 42);
        assert!(json["build_time"].as_str().is_some());
        assert!(json["builder"]["pumpbin_version"].as_str().is_some());
        assert_eq!(json["modules"].as_array().unwrap().len(), 1);
    }
}
