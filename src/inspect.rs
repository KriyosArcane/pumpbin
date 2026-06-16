//! `.b1n` loader pack introspection.
//!
//! PumpBin loader packs are opaque-by-default (capnp + zlib blob). v1.3.1
//! exposes a structured `inspect` API: load a `.b1n`, dump everything an
//! operator needs to know before adding it to their registry — plugin
//! info, replace config, supported platforms, and module ids.
//!
//! Plain-text output for now; `--json` versioned shape lands in a
//! follow-up chip alongside the generic `--json` CLI flag.

use crate::plugin::Plugin;
use crate::plugin_system::PluginConfigField;
use serde::Serialize;
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
    /// Pipeline hooks: encrypt, format-encrypted, format-url, upload-remote.
    /// Each is Some(module_id) when wired, None when not set.
    pub encrypt_module: Option<String>,
    pub format_encrypted_module: Option<String>,
    pub format_url_module: Option<String>,
    pub upload_remote_module: Option<String>,
    /// Post-build modules (run after shellcode injection, in order).
    pub modules: Vec<ModuleReport>,
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
    /// Module id.
    pub id: String,
    pub config_fields: Vec<PluginConfigField>,
}

/// Load + inspect a `.b1n` file.
pub fn inspect(path: impl AsRef<Path>) -> anyhow::Result<InspectReport> {
    let path = path.as_ref();
    let bytes = std::fs::read(path)?;
    let plugin = Plugin::decode_from_slice(&bytes)?;

    let modules = inspect_modules(&plugin);
    let platforms = inspect_platforms(&plugin);

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
        encrypt_module: plugin.plugins().encrypt_shellcode().map(|s| s.to_string()),
        format_encrypted_module: plugin
            .plugins()
            .format_encrypted_shellcode()
            .map(|s| s.to_string()),
        format_url_module: plugin.plugins().format_url_remote().map(|s| s.to_string()),
        upload_remote_module: plugin
            .plugins()
            .upload_final_shellcode_remote()
            .map(|s| s.to_string()),
        modules,
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
    plugin
        .plugins()
        .modules()
        .iter()
        .enumerate()
        .map(|(idx, id)| ModuleReport {
            index: idx,
            id: id.clone(),
            config_fields: Vec::new(),
        })
        .collect()
}

/// Render an `InspectReport` to a human-readable plain-text string.
pub fn render_text(report: &InspectReport) -> String {
    use std::fmt::Write;
    let mut s = String::new();

    let _ = writeln!(s, "Path:        {}", report.path.display());
    let _ = writeln!(s, "Pack:        {}", report.plugin_name);
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

    // Pipeline hooks — show all four slots, mark unset ones explicitly.
    let _ = writeln!(s, "\nPipeline hooks:");
    let _ = writeln!(
        s,
        "  encrypt:        {}",
        report.encrypt_module.as_deref().unwrap_or("<none>")
    );
    let _ = writeln!(
        s,
        "  format-encrypt: {}",
        report
            .format_encrypted_module
            .as_deref()
            .unwrap_or("<none>")
    );
    let _ = writeln!(
        s,
        "  format-url:     {}",
        report.format_url_module.as_deref().unwrap_or("<none>")
    );
    let _ = writeln!(
        s,
        "  upload-remote:  {}",
        report.upload_remote_module.as_deref().unwrap_or("<none>")
    );

    let _ = writeln!(s, "\nPlatforms ({}):", report.platforms.len());
    for p in &report.platforms {
        let _ = writeln!(s, "  {} -> {}", p.name, p.binary_types.join(", "));
    }
    if report.platforms.is_empty() {
        let _ = writeln!(s, "  <none>");
    }

    let _ = writeln!(s, "\nModules ({}):", report.modules.len());
    for m in &report.modules {
        let _ = writeln!(s, "  [{}] id={}", m.index, m.id);
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

    // Module diff by id.
    let l_ids: std::collections::HashSet<&str> =
        left.modules.iter().map(|m| m.id.as_str()).collect();
    let r_ids: std::collections::HashSet<&str> =
        right.modules.iter().map(|m| m.id.as_str()).collect();
    let added: Vec<&&str> = r_ids.difference(&l_ids).collect();
    let removed: Vec<&&str> = l_ids.difference(&r_ids).collect();
    if !added.is_empty() || !removed.is_empty() {
        let _ = writeln!(s, "modules:");
        for id in &removed {
            let _ = writeln!(s, "  - {id}");
        }
        for id in &added {
            let _ = writeln!(s, "  + {id}");
        }
    }

    if s.lines().count() == 2 {
        // Only the --- and +++ header lines: no differences.
        let _ = writeln!(s, "no differences");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugin::{Plugin, PluginBins, PluginInfo, PluginPlugins, PluginReplace};

    /// Build a minimal fixture plugin, encode it to a temp .b1n, return
    /// the path. Mirrors the pattern from tests/inspect_b1n.rs.
    fn write_fixture(name: &str, dir: &tempfile::TempDir) -> std::path::PathBuf {
        let mut bins = PluginBins::default();
        let mut template = vec![0xAAu8; 64];
        template.extend_from_slice(b"$$SHELLCODE$$");
        template.extend(std::iter::repeat_n(b'0', 4096 - b"$$SHELLCODE$$".len()));
        template.extend_from_slice(b"$$99999$$");
        *bins.windows.executable_mut() = Some(template);

        let plugin = Plugin {
            version: "1.0.0".into(),
            info: PluginInfo {
                plugin_name: name.into(),
                author: "unit-tests".into(),
                version: "0.1.0".into(),
                desc: "inline unit test fixture".into(),
            },
            replace: PluginReplace {
                src_prefix: b"$$SHELLCODE$$".to_vec(),
                size_holder: Some(b"$$99999$$".to_vec()),
                max_len: 4096,
            },
            bins,
            plugins: PluginPlugins::default(),
        };

        let bytes = plugin.encode_to_vec().unwrap();
        let path = dir.path().join(format!("{name}.b1n"));
        std::fs::write(&path, &bytes).unwrap();
        path
    }

    #[test]
    fn inspect_roundtrip_from_b1n() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_fixture("inspect-unit", &dir);

        let report = inspect(&path).expect("inspect must succeed on valid .b1n");

        assert_eq!(report.plugin_name, "inspect-unit");
        assert_eq!(report.author, "unit-tests");
        assert_eq!(report.plugin_version, "0.1.0");
        assert_eq!(report.description, "inline unit test fixture");
        assert_eq!(report.src_prefix, b"$$SHELLCODE$$".to_vec());
        assert_eq!(report.size_holder, Some(b"$$99999$$".to_vec()));
        assert_eq!(report.max_len, 4096);
        assert_eq!(report.platforms.len(), 1);
        assert_eq!(report.platforms[0].name, "Windows");
    }

    #[test]
    fn render_text_has_expected_sections() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_fixture("render-unit", &dir);
        let report = inspect(&path).unwrap();
        let text = render_text(&report);

        // Key section headers and field labels
        for needle in [
            "Pack:",
            "Author:",
            "Version:",
            "Save type:",
            "src_prefix:",
            "max_len:",
            "Pipeline hooks:",
            "Platforms (",
            "Modules (",
        ] {
            assert!(
                text.contains(needle),
                "render_text must contain section {needle:?}; got:\n{text}"
            );
        }

        // Fixture-specific values
        assert!(text.contains("render-unit"));
        assert!(text.contains("unit-tests"));
        assert!(text.contains("Windows"));
    }
}
