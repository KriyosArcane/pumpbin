//! External subprocess modules.
//!
//! Discovery model:
//!   1. `<install>/modules/`           ← shipped built-ins (none today)
//!   2. `$XDG_CONFIG_HOME/pumpbin/modules/`  (or platform equivalent)
//!   3. `$PUMPBIN_MODULES_PATH` (colon/`;`-separated, env override)
//!
//! Each directory is scanned for child directories containing a
//! `pumpbin-module.toml`. The TOML is parsed; the executable is **not**
//! invoked during discovery. A bad manifest logs a warning and the
//! module is skipped; the rest keep working.
//!
//! Dispatch: pumpbin spawns the executable, pipes a JSON header +
//! payload on stdin, reads the response on stdout. Stderr is captured
//! and surfaced to the operator on failure.

pub mod wire;

use anyhow::{anyhow, Context, Result};
use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;

use wire::{
    read_frame, write_frame, Manifest, RequestHeader, ResponseHeader, WireKind, PROTOCOL_VERSION,
};

/// One discovered external module. The manifest + the resolved
/// absolute path to the executable. Held in the registry.
#[derive(Debug, Clone)]
pub struct ExternalModule {
    pub manifest: Manifest,
    pub manifest_path: PathBuf,
    pub executable: PathBuf,
}

impl ExternalModule {
    pub fn id(&self) -> &str {
        &self.manifest.name
    }
    pub fn kind(&self) -> WireKind {
        self.manifest.kind
    }
    pub fn description(&self) -> &str {
        &self.manifest.description
    }
}

/// Registry of all discovered external modules. Populated once,
/// lazily, on first access. Subsequent lookups are O(1) via the map.
static REGISTRY: OnceLock<Registry> = OnceLock::new();

#[derive(Debug, Default)]
pub struct Registry {
    by_id: BTreeMap<String, ExternalModule>,
    /// Discovery warnings, surfaced by `list_modules` so operators
    /// know why a folder didn't register.
    warnings: Vec<String>,
}

pub fn registry() -> &'static Registry {
    REGISTRY.get_or_init(discover)
}

impl Registry {
    pub fn all(&self) -> impl Iterator<Item = &ExternalModule> {
        self.by_id.values()
    }
    pub fn get(&self, id: &str) -> Option<&ExternalModule> {
        self.by_id.get(id)
    }
    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }
}

/// Scan all discovery roots, parse manifests, build the registry.
/// Quiet on success; logs warnings for malformed entries.
fn discover() -> Registry {
    let mut reg = Registry::default();
    for root in discovery_roots() {
        if !root.is_dir() {
            continue;
        }
        let entries = match std::fs::read_dir(&root) {
            Ok(e) => e,
            Err(e) => {
                reg.warnings
                    .push(format!("read_dir({}) failed: {e}", root.display()));
                continue;
            }
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            let manifest_path = path.join("pumpbin-module.toml");
            if !manifest_path.is_file() {
                continue;
            }
            match load_one(&manifest_path) {
                Ok(m) => {
                    if let Some(prev) = reg.by_id.get(&m.manifest.name) {
                        reg.warnings.push(format!(
                            "duplicate module id '{}': kept {}, shadowed {}",
                            m.manifest.name,
                            prev.manifest_path.display(),
                            manifest_path.display(),
                        ));
                    } else {
                        reg.by_id.insert(m.manifest.name.clone(), m);
                    }
                }
                Err(e) => {
                    reg.warnings
                        .push(format!("skipped {}: {e:#}", manifest_path.display()));
                }
            }
        }
    }
    reg
}

/// Ordered list of directories to scan.
/// First-wins on duplicate ids: shipped modules cannot be hijacked
/// by a silently-dropped user override. Operators who want to
/// replace a built-in should rename it.
fn discovery_roots() -> Vec<PathBuf> {
    let mut out = Vec::new();

    // Built-in dir next to the pumpbin executable.
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            out.push(parent.join("modules"));
        }
    }

    // User config dir.
    if let Some(cfg) = user_config_modules_dir() {
        out.push(cfg);
    }

    // Env override (colon-separated on unix, ';' on windows).
    if let Ok(paths) = std::env::var("PUMPBIN_MODULES_PATH") {
        let sep = if cfg!(windows) { ';' } else { ':' };
        for p in paths.split(sep) {
            if !p.is_empty() {
                out.push(PathBuf::from(p));
            }
        }
    }

    out
}

fn user_config_modules_dir() -> Option<PathBuf> {
    // Use `dirs::config_dir` (already a dep): XDG on linux,
    // Application Support on macOS, AppData on windows.
    dirs::config_dir().map(|d| d.join("pumpbin").join("modules"))
}

fn load_one(manifest_path: &Path) -> Result<ExternalModule> {
    let raw = std::fs::read_to_string(manifest_path)
        .with_context(|| format!("read {}", manifest_path.display()))?;
    let manifest: Manifest =
        toml::from_str(&raw).with_context(|| format!("parse {}", manifest_path.display()))?;

    if manifest.protocol > PROTOCOL_VERSION {
        anyhow::bail!(
            "module declares protocol {} but host speaks {} (upgrade pumpbin or downgrade module)",
            manifest.protocol,
            PROTOCOL_VERSION
        );
    }

    if !platform_supported(&manifest.platforms) {
        anyhow::bail!(
            "module platforms {:?} do not include this host ({})",
            manifest.platforms,
            current_platform_tag()
        );
    }

    let parent = manifest_path.parent().unwrap_or_else(|| Path::new("."));
    let executable = parent.join(&manifest.executable);
    if !executable.is_file() {
        anyhow::bail!(
            "manifest references executable '{}' which does not exist at {}",
            manifest.executable,
            executable.display()
        );
    }

    Ok(ExternalModule {
        manifest,
        manifest_path: manifest_path.to_path_buf(),
        executable,
    })
}

fn platform_supported(declared: &[String]) -> bool {
    let host = current_platform_tag();
    declared.iter().any(|p| p == "any" || p == host)
}

fn current_platform_tag() -> &'static str {
    if cfg!(target_os = "linux") {
        "linux"
    } else if cfg!(target_os = "windows") {
        "windows"
    } else if cfg!(target_os = "macos") {
        "darwin"
    } else {
        "unknown"
    }
}

/// Run an external module to completion. Encodes the JSON header,
/// pipes both frames in, reads both frames out, parses the response,
/// surfaces any errors clearly.
///
/// `payload` is the raw input bytes (shellcode / implant / URL).
pub fn invoke(
    module: &ExternalModule,
    kind: WireKind,
    args: &[String],
    payload: &[u8],
) -> Result<(ResponseHeader, Vec<u8>)> {
    if module.manifest.kind != kind {
        anyhow::bail!(
            "module '{}' is kind={} but caller asked for kind={}",
            module.id(),
            module.manifest.kind,
            kind
        );
    }

    let header = RequestHeader {
        protocol: PROTOCOL_VERSION,
        kind,
        id: module.id().to_string(),
        args: args.to_vec(),
    };
    let header_json = serde_json::to_vec(&header)
        .with_context(|| format!("encode request header for '{}'", module.id()))?;

    let debug = std::env::var("PUMPBIN_MODULE_DEBUG").is_ok_and(|v| !v.is_empty() && v != "0");
    if debug {
        eprintln!(
            "[pumpbin-debug] → {} request header ({} B): {}",
            module.id(),
            header_json.len(),
            String::from_utf8_lossy(&header_json)
        );
        eprintln!(
            "[pumpbin-debug] → {} request payload: {} B",
            module.id(),
            payload.len()
        );
    }

    let mut child = Command::new(&module.executable)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("spawn '{}'", module.executable.display()))?;

    {
        let stdin = child
            .stdin
            .as_mut()
            .ok_or_else(|| anyhow!("module '{}' stdin not captured", module.id()))?;
        write_frame(stdin, &header_json)
            .with_context(|| format!("write header to '{}'", module.id()))?;
        write_frame(stdin, payload)
            .with_context(|| format!("write payload to '{}'", module.id()))?;
        stdin.flush().ok();
    }
    // Drop stdin so the child sees EOF.
    drop(child.stdin.take());

    let out = child
        .wait_with_output()
        .with_context(|| format!("wait '{}'", module.id()))?;

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        anyhow::bail!(
            "module '{}' exited with {}: {}",
            module.id(),
            out.status,
            stderr.trim()
        );
    }

    // Parse response frames out of captured stdout.
    let mut cursor = std::io::Cursor::new(out.stdout);
    let resp_header_bytes = read_frame(&mut cursor)
        .with_context(|| format!("read response header from '{}'", module.id()))?
        .ok_or_else(|| anyhow!("module '{}' produced no stdout", module.id()))?;
    let resp_header: ResponseHeader = serde_json::from_slice(&resp_header_bytes)
        .with_context(|| format!("parse response header from '{}'", module.id()))?;

    let resp_body = read_frame(&mut cursor)
        .with_context(|| format!("read response body from '{}'", module.id()))?
        .unwrap_or_default();

    if debug {
        eprintln!(
            "[pumpbin-debug] ← {} response header ({} B): {}",
            module.id(),
            resp_header_bytes.len(),
            String::from_utf8_lossy(&resp_header_bytes)
        );
        eprintln!(
            "[pumpbin-debug] ← {} response payload: {} B",
            module.id(),
            resp_body.len()
        );
        let stderr = String::from_utf8_lossy(&out.stderr);
        if !stderr.trim().is_empty() {
            eprintln!(
                "[pumpbin-debug] ← {} stderr: {}",
                module.id(),
                stderr.trim()
            );
        }
    }

    if let Some(err) = &resp_header.error {
        let stderr = String::from_utf8_lossy(&out.stderr);
        if stderr.trim().is_empty() {
            anyhow::bail!("module '{}' reported error: {err}", module.id());
        }
        anyhow::bail!(
            "module '{}' reported error: {err}\nstderr: {}",
            module.id(),
            stderr.trim()
        );
    }

    Ok((resp_header, resp_body))
}
