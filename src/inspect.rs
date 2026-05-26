//! `.b1n` plugin pack introspection.
//!
//! Pumpbin plugin packs are opaque-by-default (capnp + zlib blob). v1.3.1
//! exposes a structured `inspect` API: load a `.b1n`, dump everything an
//! operator needs to know before adding it to their registry — plugin
//! info, replace config, supported platforms, embedded WASM modules
//! (with sha256 + declared runtime policy), and the config schema each
//! module exports.
//!
//! Plain-text output for now; `--json` versioned shape lands in a
//! follow-up chip alongside the generic `--json` CLI flag.

use crate::plugin::Plugin;
use crate::plugin_system::{
    get_plugin_config_schema, PluginConfigField, ResolvedPolicy, RuntimeConfig,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

/// One inspected `.b1n` file's worth of metadata.
#[derive(Debug, Clone, Serialize)]
pub struct InspectReport {
    pub path: PathBuf,
    pub plugin_name: String,
    pub author: String,
    pub plugin_version: String,
    pub description: String,
    /// Hex-encoded for JSON safety (raw Vec<u8> serializes as a byte array
    /// otherwise, which downstream JSON consumers find awkward).
    #[serde(serialize_with = "ser_bytes_as_lossy_string")]
    pub src_prefix: Vec<u8>,
    #[serde(serialize_with = "ser_opt_bytes_as_lossy_string")]
    pub size_holder: Option<Vec<u8>>,
    pub max_len: usize,
    pub save_type: String,
    pub platforms: Vec<PlatformReport>,
    pub modules: Vec<ModuleReport>,
    pub legacy_module_count: usize,
}

fn ser_bytes_as_lossy_string<S: serde::Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&String::from_utf8_lossy(bytes))
}

fn ser_opt_bytes_as_lossy_string<S: serde::Serializer>(
    bytes: &Option<Vec<u8>>,
    s: S,
) -> Result<S::Ok, S::Error> {
    match bytes {
        Some(b) => s.serialize_str(&String::from_utf8_lossy(b)),
        None => s.serialize_none(),
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct PlatformReport {
    pub name: String,
    pub binary_types: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ModuleReport {
    pub index: usize,
    pub size: usize,
    pub sha256: String,
    /// Parsed runtime policy (if the module exports `plugin_schema`).
    pub runtime: Option<RuntimeConfig>,
    /// Resolved policy after host validation (None if defaults applied).
    /// Not serialized — duplicate of `runtime` semantically; included
    /// in struct for downstream consumers using the rust API.
    #[serde(skip)]
    pub resolved_policy: Option<ResolvedPolicy>,
    /// Config schema fields the module declares.
    pub config_fields: Vec<PluginConfigField>,
}

/// Load + inspect a `.b1n` file.
pub fn inspect(path: impl AsRef<Path>) -> anyhow::Result<InspectReport> {
    let path = path.as_ref();
    let bytes = std::fs::read(path)?;
    let plugin = Plugin::decode_from_slice(&bytes)?;

    let modules = inspect_modules(&plugin);
    let platforms = inspect_platforms(&plugin);

    // Pre-v1.1.7 single-WASM fallback fields. Surface their presence so
    // operators know a plugin pre-dates the unified `modules: Vec<...>`
    // shape (informational; the legacy fields still work).
    let legacy_module_count = [
        plugin.plugins().encrypt_shellcode().is_some(),
        plugin.plugins().format_encrypted_shellcode().is_some(),
        plugin.plugins().format_url_remote().is_some(),
        plugin.plugins().upload_final_shellcode_remote().is_some(),
    ]
    .iter()
    .filter(|x| **x)
    .count();

    Ok(InspectReport {
        path: path.to_path_buf(),
        plugin_name: plugin.info().plugin_name().to_string(),
        author: plugin.info().author().to_string(),
        plugin_version: plugin.info().version().to_string(),
        description: plugin.info().desc().to_string(),
        src_prefix: plugin.replace().src_prefix().to_vec(),
        size_holder: plugin.replace().size_holder().cloned(),
        max_len: plugin.replace().max_len(),
        save_type: format!("{:?}", plugin.save_type()),
        platforms,
        modules,
        legacy_module_count,
    })
}

fn inspect_platforms(plugin: &Plugin) -> Vec<PlatformReport> {
    let mut out = Vec::new();
    for (name, bins) in [
        ("Windows", plugin.bins().windows()),
        ("Linux", plugin.bins().linux()),
        ("Darwin", plugin.bins().darwin()),
    ] {
        let mut binary_types = Vec::new();
        if bins.executable().is_some() {
            binary_types.push("exe".to_string());
        }
        if bins.dynamic_library().is_some() {
            binary_types.push("lib".to_string());
        }
        if !binary_types.is_empty() {
            out.push(PlatformReport {
                name: name.to_string(),
                binary_types,
            });
        }
    }
    out
}

fn inspect_modules(plugin: &Plugin) -> Vec<ModuleReport> {
    let mut out = Vec::new();
    for (idx, wasm) in plugin.plugins().modules().iter().enumerate() {
        let mut hasher = Sha256::new();
        hasher.update(wasm);
        let sha256 = format!("{:x}", hasher.finalize());

        // Try to read the module's schema. Modules without one get None
        // (host applies safe defaults at runtime).
        let (runtime, resolved_policy, config_fields) = match get_plugin_config_schema(wasm) {
            Ok(Some(schema)) => {
                let resolved = schema.runtime.as_ref().and_then(|rt| {
                    crate::plugin_system::ResolvedPolicy::from_runtime(format!("module#{idx}"), rt)
                        .ok()
                });
                (schema.runtime, resolved, schema.fields)
            }
            _ => (None, None, Vec::new()),
        };

        out.push(ModuleReport {
            index: idx,
            size: wasm.len(),
            sha256,
            runtime,
            resolved_policy,
            config_fields,
        });
    }
    out
}

/// Render an `InspectReport` to a human-readable plain-text string.
pub fn render_text(report: &InspectReport) -> String {
    use std::fmt::Write;
    let mut s = String::new();

    let _ = writeln!(s, "Path:        {}", report.path.display());
    let _ = writeln!(s, "Plugin:      {}", report.plugin_name);
    let _ = writeln!(s, "Author:      {}", report.author);
    let _ = writeln!(s, "Version:     {}", report.plugin_version);
    let _ = writeln!(s, "Save type:   {}", report.save_type);
    let _ = writeln!(
        s,
        "src_prefix:  {:?}",
        String::from_utf8_lossy(&report.src_prefix)
    );
    if let Some(holder) = &report.size_holder {
        let _ = writeln!(s, "size_holder: {:?}", String::from_utf8_lossy(holder));
    } else {
        let _ = writeln!(s, "size_holder: <none, Remote mode>");
    }
    let _ = writeln!(s, "max_len:     {} bytes", report.max_len);
    if !report.description.is_empty() {
        let _ = writeln!(s, "Description: {}", report.description);
    }

    let _ = writeln!(s, "\nPlatforms ({}):", report.platforms.len());
    for p in &report.platforms {
        let _ = writeln!(s, "  {} -> {}", p.name, p.binary_types.join(", "));
    }
    if report.platforms.is_empty() {
        let _ = writeln!(s, "  <none>");
    }

    let _ = writeln!(s, "\nModules ({}):", report.modules.len());
    for m in &report.modules {
        let _ = writeln!(s, "  [{}] {} bytes  sha256={}", m.index, m.size, m.sha256);
        if let Some(rt) = &m.runtime {
            let _ = writeln!(
                s,
                "      runtime: timeout_ms={} allowed_hosts={:?} on_error={:?} sdk_version={:?}",
                rt.timeout_ms, rt.allowed_hosts, rt.on_error, rt.sdk_version
            );
        } else {
            let _ = writeln!(s, "      runtime: <unset, defaults applied at runtime>");
        }
        if !m.config_fields.is_empty() {
            let _ = writeln!(s, "      config fields:");
            for f in &m.config_fields {
                let req = if f.required { " (required)" } else { "" };
                let _ = writeln!(s, "        - {:?} : {}{}", f.key, f.field_type, req);
            }
        }
    }
    if report.modules.is_empty() {
        let _ = writeln!(s, "  <none>");
    }

    if report.legacy_module_count > 0 {
        let _ = writeln!(
            s,
            "\nLegacy single-WASM fields populated: {}",
            report.legacy_module_count
        );
        let _ = writeln!(
            s,
            "  (Pre-v1.1.7 plugin shape; still works, but consider rebuilding under modules[])"
        );
    }
    s
}

/// Diff two `InspectReport`s: returns a human-readable summary of what
/// changed. Used by `pumpbin-cli inspect --diff <other.b1n>`.
pub fn render_diff(left: &InspectReport, right: &InspectReport) -> String {
    use std::fmt::Write;
    let mut s = String::new();
    let _ = writeln!(s, "--- {}", left.path.display());
    let _ = writeln!(s, "+++ {}", right.path.display());

    if left.plugin_name != right.plugin_name {
        let _ = writeln!(s, "name: {:?} -> {:?}", left.plugin_name, right.plugin_name);
    }
    if left.plugin_version != right.plugin_version {
        let _ = writeln!(
            s,
            "version: {:?} -> {:?}",
            left.plugin_version, right.plugin_version
        );
    }
    if left.src_prefix != right.src_prefix {
        let _ = writeln!(
            s,
            "src_prefix: {:?} -> {:?}",
            String::from_utf8_lossy(&left.src_prefix),
            String::from_utf8_lossy(&right.src_prefix)
        );
    }
    if left.size_holder != right.size_holder {
        let l = left
            .size_holder
            .as_ref()
            .map(|b| String::from_utf8_lossy(b).to_string());
        let r = right
            .size_holder
            .as_ref()
            .map(|b| String::from_utf8_lossy(b).to_string());
        let _ = writeln!(s, "size_holder: {l:?} -> {r:?}");
    }
    if left.max_len != right.max_len {
        let _ = writeln!(s, "max_len: {} -> {}", left.max_len, right.max_len);
    }
    if left.save_type != right.save_type {
        let _ = writeln!(s, "save_type: {} -> {}", left.save_type, right.save_type);
    }

    // Module diff by sha256.
    let l_shas: std::collections::HashSet<&str> =
        left.modules.iter().map(|m| m.sha256.as_str()).collect();
    let r_shas: std::collections::HashSet<&str> =
        right.modules.iter().map(|m| m.sha256.as_str()).collect();
    let added: Vec<&&str> = r_shas.difference(&l_shas).collect();
    let removed: Vec<&&str> = l_shas.difference(&r_shas).collect();
    if !added.is_empty() || !removed.is_empty() {
        let _ = writeln!(s, "modules:");
        for sha in &removed {
            let _ = writeln!(s, "  - {sha}");
        }
        for sha in &added {
            let _ = writeln!(s, "  + {sha}");
        }
    }

    if s.lines().count() == 2 {
        // Only the --- and +++ header lines: no differences.
        let _ = writeln!(s, "no differences");
    }
    s
}
