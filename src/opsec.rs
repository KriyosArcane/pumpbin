//! OPSEC profile at `~/.config/pumpbin/opsec.toml`.
//!
//! Operator-wide policy that overrides per-profile values. Loaded
//! eagerly at the start of `Profile::execute`; mismatches between
//! the profile and the OPSEC policy produce a clear error before any
//! WASM module runs. Honors `$XDG_CONFIG_HOME` for sandboxed runs.
//!
//! v1.4.0 ships three knobs: `domain_allowlist` (eventually checked
//! against WASM module `allowed_hosts`), `refuse_unrestricted_network`
//! (refuse any plugin that declared `allowed_hosts = ["*"]`), and
//! `require_sbom` (refuse profile execution unless `output.sbom = true`).
//! The first two need cross-module coordination that lands in a follow-
//! up Phase 2 chip; v1.4.0 wires the file parse + the `require_sbom`
//! gate (the simplest enforcement and the one that immediately
//! benefits operators).

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub const OPSEC_SCHEMA: &str = "pumpbin.opsec/v1";

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct OpsecProfile {
    /// Must be `"pumpbin.opsec/v1"`. Missing → treat as defaults.
    #[serde(default)]
    pub schema: String,
    #[serde(default)]
    pub network: NetworkPolicy,
    #[serde(default)]
    pub builds: BuildsPolicy,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct NetworkPolicy {
    /// Allowed hosts (glob-style, e.g. `*.attacker.com`). Empty list
    /// means no restriction *from the OPSEC policy* — the per-module
    /// `allowed_hosts` still applies.
    #[serde(default)]
    pub domain_allowlist: Vec<String>,
    /// If true, refuse to load any plugin whose `allowed_hosts`
    /// contains `"*"`. v1.4.0 documents the field; enforcement lands
    /// when WASM module load checks the policy.
    #[serde(default)]
    pub refuse_unrestricted: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct BuildsPolicy {
    /// If true, refuse to execute a profile unless `output.sbom = true`.
    /// Wired in v1.4.0.
    #[serde(default)]
    pub require_sbom: bool,
    /// Reserved for v1.5.x: refuse builds that don't reference a named
    /// preset.
    #[serde(default)]
    pub require_preset: bool,
}

/// Resolve the OPSEC profile path. Honors `$XDG_CONFIG_HOME` first,
/// then falls back to `~/.config/pumpbin/opsec.toml`.
pub fn opsec_path() -> Option<PathBuf> {
    if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME") {
        return Some(PathBuf::from(xdg).join("pumpbin").join("opsec.toml"));
    }
    let home = dirs::home_dir()?;
    Some(home.join(".config").join("pumpbin").join("opsec.toml"))
}

/// Load the OPSEC profile if it exists. Returns `Ok(None)` (treated
/// as defaults — no OPSEC policy) when the file is absent; bubbles up
/// parse errors otherwise.
pub fn load_opsec() -> anyhow::Result<Option<OpsecProfile>> {
    let Some(path) = opsec_path() else {
        return Ok(None);
    };
    if !path.exists() {
        return Ok(None);
    }
    let raw = std::fs::read_to_string(&path)
        .map_err(|e| anyhow::anyhow!("Failed to read OPSEC profile {}: {e}", path.display()))?;
    let profile: OpsecProfile = toml::from_str(&raw)
        .map_err(|e| anyhow::anyhow!("OPSEC profile {} is not valid TOML: {e}", path.display()))?;
    if !profile.schema.is_empty() && profile.schema != OPSEC_SCHEMA {
        anyhow::bail!(
            "OPSEC profile {} has schema {:?}, expected {:?}",
            path.display(),
            profile.schema,
            OPSEC_SCHEMA
        );
    }
    Ok(Some(profile))
}
