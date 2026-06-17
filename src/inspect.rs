//! `.b1n` loader pack introspection.
//!
//! PumpBin loader packs are opaque-by-default (capnp + zlib blob). v1.3.1
//! exposes a structured `inspect` API: load a `.b1n`, dump everything an
//! operator needs to know before adding it to their registry — plugin
//! info, replace config, supported platforms, and module ids.
//!
//! Plain-text output only.

use crate::plugin::Plugin;
use std::path::{Path, PathBuf};

/// One inspected `.b1n` file's worth of metadata.
#[derive(Debug, Clone)]
pub struct InspectReport {
    pub path: PathBuf,
    pub plugin_name: String,
    pub author: String,
    pub plugin_version: String,
    pub description: String,
    pub src_prefix: Vec<u8>,
    pub size_holder: Option<Vec<u8>>,
    pub max_len: usize,
    pub save_type: String,
    pub platforms: Vec<PlatformReport>,
    /// Encrypt hook module id, when wired.
    pub encrypt_module: Option<String>,
    /// Post-build modules (run after shellcode injection, in order).
    pub modules: Vec<ModuleReport>,
}

#[derive(Debug, Clone)]
pub struct PlatformReport {
    pub name: String,
    pub binary_types: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ModuleReport {
    pub index: usize,
    /// Module id.
    pub id: String,
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
        plugin_name: plugin.info.plugin_name.to_string(),
        author: plugin.info.author.to_string(),
        plugin_version: plugin.info.version.to_string(),
        description: plugin.info.desc.to_string(),
        src_prefix: plugin.replace.src_prefix.as_slice().to_vec(),
        size_holder: plugin.replace.size_holder.as_ref().cloned(),
        max_len: plugin.replace.max_len as usize,
        save_type: format!("{:?}", plugin.save_type()),
        platforms,
        encrypt_module: plugin
            .plugins
            .encrypt_shellcode
            .as_deref()
            .map(|s| s.to_string()),
        modules,
    })
}

fn inspect_platforms(plugin: &Plugin) -> Vec<PlatformReport> {
    let mut out = Vec::new();
    for (name, bins) in [
        ("Windows", &plugin.bins.windows),
        ("Linux", &plugin.bins.linux),
        ("Darwin", &plugin.bins.darwin),
    ] {
        let mut binary_types = Vec::new();
        if bins.executable.as_ref().is_some() {
            binary_types.push("exe".to_string());
        }
        if bins.dynamic_library.as_ref().is_some() {
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
        .modules
        .as_slice()
        .iter()
        .enumerate()
        .map(|(idx, id)| ModuleReport {
            index: idx,
            id: id.clone(),
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

    let _ = writeln!(s, "\nPipeline hooks:");
    let _ = writeln!(
        s,
        "  encrypt:        {}",
        report.encrypt_module.as_deref().unwrap_or("<none>")
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
    }
    if report.modules.is_empty() {
        let _ = writeln!(s, "  <none>");
    }
    s
}
