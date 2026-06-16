//! Wire protocol for external (subprocess) modules.
//!
//! Goals: language-agnostic, implementable in ≤ 20 lines of Python.
//! Therefore: JSON header for control, raw bytes for payloads.
//!
//! ## Manifest (`pumpbin-module.toml`)
//!
//! Read at module-discovery time. The executable is **never** run during
//! discovery — only the TOML is parsed. A bad manifest logs a warning
//! and skips that module; the rest keep working.
//!
//! ## Invocation
//!
//! When the operator references a module, pumpbin spawns the executable
//! and speaks:
//!
//! ```text
//!  stdin frame 0  ── JSON header (length-prefixed, u32 little-endian)
//!  stdin frame 1  ── raw payload bytes (length-prefixed, u32 LE)
//!  stdout frame 0 ── JSON response header (length-prefixed, u32 LE)
//!  stdout frame 1 ── raw response bytes (length-prefixed, u32 LE)
//!  stderr         ── free-form human messages (surfaced to operator on err)
//!  exit code      ── 0 ok; non-zero = module failed
//! ```
//!
//! Both header and body use **u32 little-endian length prefixes** because
//! that's the lowest-effort framing in any language (4-byte read + payload).
//!
//! ## Protocol version
//!
//! Every JSON header carries `"protocol": 1`. Bump on breaking changes
//! only. Modules MAY reject unknown protocol versions; pumpbin MAY refuse
//! to dispatch to a module declaring a higher protocol than it speaks.

use serde::{Deserialize, Serialize};

/// Current wire protocol. Bump only when a header field's *meaning*
/// changes. Adding optional fields is forward-compatible.
pub const PROTOCOL_VERSION: u32 = 1;

/// Module kinds an external module can implement.
///
/// Mirrors `crate::modules::ModuleKind` but with kebab-case wire names
/// so manifests read naturally in TOML.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WireKind {
    Encrypt,
    FormatEncrypted,
    FormatUrl,
    UploadRemote,
    PostBuild,
}

impl std::fmt::Display for WireKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Encrypt => "encrypt",
            Self::FormatEncrypted => "format-encrypted",
            Self::FormatUrl => "format-url",
            Self::UploadRemote => "upload-remote",
            Self::PostBuild => "post-build",
        };
        f.write_str(s)
    }
}

/// Argument schema entry. Optional; modules can skip it and accept
/// raw `key=value` strings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestArg {
    pub key: String,
    #[serde(default, rename = "type")]
    pub arg_type: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub required: bool,
    #[serde(default)]
    pub default: Option<String>,
}

/// `pumpbin-module.toml` content. Read once at startup; never re-read.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    /// Module id. Must be unique across all installed modules. Used
    /// in `--post`, `--encrypt`, `module test`, etc.
    pub name: String,

    /// One-line description shown in `module list`.
    pub description: String,

    /// Which hook this module implements.
    pub kind: WireKind,

    /// Module's own version string. Free-form; used in `module list`
    /// and error messages. Convention: SemVer.
    #[serde(default = "default_version")]
    pub version: String,

    /// Highest wire protocol the module understands. Pumpbin refuses
    /// to dispatch to a module declaring a protocol > host's.
    #[serde(default = "default_protocol")]
    pub protocol: u32,

    /// Which platforms the module's executable runs on. `["any"]` means
    /// the manifest author guarantees portability (e.g., a Python
    /// script). Pumpbin checks this against `cfg!(target_os = ...)`.
    #[serde(default = "default_platforms")]
    pub platforms: Vec<String>,

    /// Executable to spawn. Resolved relative to the manifest's
    /// directory. May be a script (`my-module.py`); pumpbin will not
    /// re-invoke a shell, so the file must be executable on its own
    /// (`#!/usr/bin/env python3` etc.).
    pub executable: String,

    /// Optional arg schema. If present, `module list --options --id <id>`
    /// renders it; if absent, the module accepts arbitrary `k=v` pairs.
    #[serde(default)]
    pub args: Vec<ManifestArg>,
}

fn default_version() -> String {
    "0.0.0".to_string()
}

fn default_protocol() -> u32 {
    PROTOCOL_VERSION
}

fn default_platforms() -> Vec<String> {
    vec!["any".to_string()]
}

/// Per-invocation header sent on stdin frame 0.
///
/// Modules SHOULD echo the request's `protocol` back in the response
/// header so pumpbin can verify they actually spoke the version they
/// were given.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestHeader {
    pub protocol: u32,
    pub kind: WireKind,
    /// Module id, for the module's own logging convenience.
    pub id: String,
    /// CLI-supplied args. Modules SHOULD treat unknown keys as errors
    /// and missing required keys as errors. The host does no
    /// validation against the manifest's arg schema in this PR;
    /// pushing that to host-side adds complexity for marginal value.
    #[serde(default)]
    pub args: Vec<String>,
}

/// Response header on stdout frame 0. Optional `error` short-circuits
/// the payload — if `error.is_some()`, pumpbin reads the body anyway
/// (it might contain partial output for debugging) but treats the
/// invocation as failed.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResponseHeader {
    pub protocol: u32,
    /// Host-visible status. Modules SHOULD set this for partial
    /// success; absence means full success.
    #[serde(default)]
    pub error: Option<String>,
    /// For `encrypt` and `format-encrypted` modules: placeholder
    /// replacement pairs (hex-encoded). Pumpbin patches the loader
    /// binary at each `holder` with the corresponding `replace_by`
    /// bytes.
    #[serde(default)]
    pub pass: Vec<WirePass>,
    /// For `format-url` and `upload-remote`: the returned string
    /// (the rewritten URL, or the upload URL).
    #[serde(default)]
    pub string: Option<String>,
}

/// Hex-encoded `Pass`. Hex keeps the JSON ASCII-safe and printable;
/// the host decodes on receipt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WirePass {
    pub holder_hex: String,
    pub replace_by_hex: String,
}

impl WirePass {
    pub fn encode(holder: &[u8], replace_by: &[u8]) -> Self {
        Self {
            holder_hex: hex_encode(holder),
            replace_by_hex: hex_encode(replace_by),
        }
    }

    pub fn decode(&self) -> anyhow::Result<crate::plugin_system::Pass> {
        Ok(crate::plugin_system::Pass {
            holder: hex_decode(&self.holder_hex)?,
            replace_by: hex_decode(&self.replace_by_hex)?,
        })
    }
}

/// 4-byte LE length prefix + payload. Used for both the JSON header
/// and the raw payload on both stdin and stdout. Returns
/// `Ok(None)` only on clean EOF before the length prefix; any other
/// EOF (mid-prefix or mid-payload) is an error.
/// Maximum frame size: 256 MiB. Rejects length prefixes above this
/// to prevent unbounded allocation from a malicious or buggy module.
const MAX_FRAME_SIZE: usize = 256 * 1024 * 1024;

pub fn read_frame<R: std::io::Read>(r: &mut R) -> std::io::Result<Option<Vec<u8>>> {
    let mut len_buf = [0u8; 4];
    let mut filled = 0;
    loop {
        match r.read(&mut len_buf[filled..]) {
            Ok(0) if filled == 0 => return Ok(None),
            Ok(0) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    format!("read_frame: partial length prefix ({filled} of 4 bytes)"),
                ));
            }
            Ok(n) => {
                filled += n;
                if filled == 4 {
                    break;
                }
            }
            Err(e) => return Err(e),
        }
    }
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > MAX_FRAME_SIZE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("read_frame: length prefix {len} exceeds maximum ({MAX_FRAME_SIZE})"),
        ));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)?;
    Ok(Some(buf))
}

pub fn write_frame<W: std::io::Write>(w: &mut W, payload: &[u8]) -> std::io::Result<()> {
    let len = u32::try_from(payload.len()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "write_frame: payload too large ({} > u32::MAX)",
                payload.len()
            ),
        )
    })?;
    w.write_all(&len.to_le_bytes())?;
    w.write_all(payload)?;
    Ok(())
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn hex_decode(s: &str) -> anyhow::Result<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        anyhow::bail!("hex string has odd length: {}", s.len());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|e| anyhow::anyhow!("hex parse @ {i}: {e}"))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_roundtrip() {
        let mut buf = Vec::new();
        write_frame(&mut buf, b"hello").unwrap();
        let mut cursor = std::io::Cursor::new(buf);
        let out = read_frame(&mut cursor).unwrap().unwrap();
        assert_eq!(out, b"hello");
    }

    #[test]
    fn frame_eof_returns_none() {
        let mut cursor = std::io::Cursor::new(Vec::<u8>::new());
        assert!(read_frame(&mut cursor).unwrap().is_none());
    }

    #[test]
    fn frame_partial_prefix_errors() {
        let mut cursor = std::io::Cursor::new(vec![0x05, 0x00]);
        assert!(read_frame(&mut cursor).is_err());
    }

    #[test]
    fn hex_roundtrip() {
        let bytes = b"\x00\xff\x10\x80";
        let s = hex_encode(bytes);
        assert_eq!(s, "00ff1080");
        assert_eq!(hex_decode(&s).unwrap(), bytes);
    }

    #[test]
    fn manifest_parses_minimal() {
        let toml = r#"
            name = "strip-ts"
            description = "Zero PE timestamps"
            kind = "post-build"
            executable = "strip-ts"
        "#;
        let m: Manifest = toml::from_str(toml).unwrap();
        assert_eq!(m.name, "strip-ts");
        assert_eq!(m.kind, WireKind::PostBuild);
        assert_eq!(m.protocol, PROTOCOL_VERSION);
        assert_eq!(m.platforms, vec!["any".to_string()]);
        assert!(m.args.is_empty());
    }

    #[test]
    fn manifest_parses_with_args() {
        let toml = r#"
            name = "sign-mimic"
            description = "Lift sig from donor PE"
            kind = "post-build"
            executable = "sign-mimic"
            version = "0.2.1"
            platforms = ["linux", "windows"]

            [[args]]
            key = "donor"
            type = "path"
            required = true
            description = "Donor signed PE"
        "#;
        let m: Manifest = toml::from_str(toml).unwrap();
        assert_eq!(m.args.len(), 1);
        assert_eq!(m.args[0].key, "donor");
        assert!(m.args[0].required);
        assert_eq!(m.platforms.len(), 2);
    }
}
