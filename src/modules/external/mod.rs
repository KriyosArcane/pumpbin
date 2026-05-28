//! External (subprocess) modules — NetExec-style folder autodetect.
//!
//! Discovery model:
//!   1. `<install>/modules/`           ← shipped built-ins (none today)
//!   2. `$XDG_CONFIG_HOME/pumpbin/modules/`  (or platform equivalent)
//!   3. `$PUMPBIN_MODULES_PATH` (colon/`;`-separated, env override)
//!
//! Each directory is scanned for child directories containing a
//! `pumpbin-module.toml`. The TOML is parsed; the executable is **not**
//! invoked during discovery. A bad manifest logs a warning and the
//! module is skipped; the rest keep working — same shape as NetExec's
//! `module_is_sane`.
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

/// Ordered list of directories to scan, lowest-priority first.
/// Later entries take precedence on duplicate ids (rationale: user
/// drop-in should be able to shadow shipped built-ins).
///
/// Actually we keep first-wins ("kept" in warnings) so shipped
/// modules can't be hijacked by a silently-dropped user override.
/// Operators who want to replace a built-in should rename it.
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
    let manifest: Manifest = toml::from_str(&raw)
        .with_context(|| format!("parse {}", manifest_path.display()))?;

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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn write_manifest(dir: &Path, toml: &str, exe_name: &str) {
        std::fs::write(dir.join("pumpbin-module.toml"), toml).unwrap();
        let exe_path = dir.join(exe_name);
        // Make a minimum-viable executable: a shell script that
        // exits 0. We need executable bit on unix.
        std::fs::write(&exe_path, "#!/bin/sh\nexit 0\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perm = std::fs::metadata(&exe_path).unwrap().permissions();
            perm.set_mode(0o755);
            std::fs::set_permissions(&exe_path, perm).unwrap();
        }
    }

    #[test]
    fn load_one_happy_path() {
        let dir = tempdir().unwrap();
        let mdir = dir.path().join("good");
        std::fs::create_dir_all(&mdir).unwrap();
        write_manifest(
            &mdir,
            r#"
                name = "good-mod"
                description = "demo"
                kind = "post-build"
                executable = "good-mod"
            "#,
            "good-mod",
        );
        let m = load_one(&mdir.join("pumpbin-module.toml")).unwrap();
        assert_eq!(m.id(), "good-mod");
        assert_eq!(m.kind(), WireKind::PostBuild);
        assert!(m.executable.is_file());
    }

    #[test]
    fn load_one_rejects_higher_protocol() {
        let dir = tempdir().unwrap();
        let mdir = dir.path().join("future-mod");
        std::fs::create_dir_all(&mdir).unwrap();
        write_manifest(
            &mdir,
            r#"
                name = "future-mod"
                description = "uses protocol 99"
                kind = "post-build"
                executable = "future-mod"
                protocol = 99
            "#,
            "future-mod",
        );
        let err = load_one(&mdir.join("pumpbin-module.toml")).unwrap_err();
        assert!(err.to_string().contains("protocol"));
    }

    #[test]
    fn load_one_rejects_missing_executable() {
        let dir = tempdir().unwrap();
        let mdir = dir.path().join("ghost");
        std::fs::create_dir_all(&mdir).unwrap();
        std::fs::write(
            mdir.join("pumpbin-module.toml"),
            r#"
                name = "ghost"
                description = "no exe"
                kind = "post-build"
                executable = "nope"
            "#,
        )
        .unwrap();
        let err = load_one(&mdir.join("pumpbin-module.toml")).unwrap_err();
        assert!(err.to_string().contains("does not exist"));
    }

    #[test]
    fn current_platform_tag_is_one_of_known() {
        let t = current_platform_tag();
        assert!(["linux", "windows", "darwin", "unknown"].contains(&t));
    }

    #[cfg(unix)]
    #[test]
    fn invoke_echo_passthrough() {
        // Module that emits a 4-byte zero-length response header
        // ({"protocol":1}) and echoes its payload back verbatim.
        let dir = tempdir().unwrap();
        let mdir = dir.path().join("echo");
        std::fs::create_dir_all(&mdir).unwrap();
        let script = r##"#!/usr/bin/env python3
import json, struct, sys
def read_frame():
    raw = sys.stdin.buffer.read(4)
    n = struct.unpack('<I', raw)[0]
    return sys.stdin.buffer.read(n)
def write_frame(payload):
    sys.stdout.buffer.write(struct.pack('<I', len(payload)))
    sys.stdout.buffer.write(payload)
header = json.loads(read_frame())
body = read_frame()
resp = json.dumps({"protocol": header["protocol"]}).encode()
write_frame(resp)
write_frame(body)
sys.stdout.buffer.flush()
"##;
        let exe_path = mdir.join("echo.py");
        std::fs::write(&exe_path, script).unwrap();
        use std::os::unix::fs::PermissionsExt;
        let mut perm = std::fs::metadata(&exe_path).unwrap().permissions();
        perm.set_mode(0o755);
        std::fs::set_permissions(&exe_path, perm).unwrap();

        std::fs::write(
            mdir.join("pumpbin-module.toml"),
            r#"
                name = "echo"
                description = "echo"
                kind = "post-build"
                executable = "echo.py"
            "#,
        )
        .unwrap();

        let m = load_one(&mdir.join("pumpbin-module.toml")).unwrap();
        let (resp, body) = invoke(&m, WireKind::PostBuild, &[], b"hello world").unwrap();
        assert_eq!(resp.protocol, PROTOCOL_VERSION);
        assert!(resp.error.is_none());
        assert_eq!(body, b"hello world");
    }
}
