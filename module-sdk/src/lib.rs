//! `pumpbin-module-sdk` — tiny helper for Rust-authored PumpBin modules.
//!
//! Implements wire protocol **v1**: u32 LE length-prefixed JSON
//! header + raw bytes payload, on both stdin and stdout. The host
//! sends a request, the module emits a response, exit code signals
//! success.
//!
//! See `pumpbin/MODULES.md` for the protocol spec; this crate is
//! pure convenience, not the spec itself. Authors who don't want
//! the dep can implement the framing in ~30 lines of any language.
//!
//! # Example (post-build module)
//!
//! ```no_run
//! use pumpbin_module_sdk::{post_build, Result};
//!
//! fn main() -> Result<()> {
//!     post_build(|_args, implant| {
//!         // mutate `implant` in place
//!         implant.push(0xAA);
//!         Ok(())
//!     })
//! }
//! ```

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::{Read, Write};

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub const PROTOCOL_VERSION: u32 = 1;

pub type Args = BTreeMap<String, String>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Kind {
    Encrypt,
    FormatEncrypted,
    FormatUrl,
    UploadRemote,
    PostBuild,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestHeader {
    pub protocol: u32,
    pub kind: Kind,
    pub id: String,
    #[serde(default)]
    pub args: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResponseHeader {
    pub protocol: u32,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub pass: Vec<WirePass>,
    #[serde(default)]
    pub string: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WirePass {
    pub holder_hex: String,
    pub replace_by_hex: String,
}

impl WirePass {
    pub fn new(holder: &[u8], replace_by: &[u8]) -> Self {
        Self {
            holder_hex: hex_encode(holder),
            replace_by_hex: hex_encode(replace_by),
        }
    }
}

/// Parse host-supplied `key=value` strings into a map.
/// Values may contain `=`; only the first `=` splits the pair.
pub fn parse_args(args: &[String]) -> Result<Args> {
    let mut parsed = BTreeMap::new();
    for arg in args {
        let Some((key, value)) = arg.split_once('=') else {
            return Err(format!("expected key=value, got: {arg}").into());
        };
        if key.trim().is_empty() {
            return Err(format!("empty arg key in: {arg}").into());
        }
        parsed.insert(key.trim().to_string(), value.to_string());
    }
    Ok(parsed)
}

/// Return an optional arg value by key.
pub fn arg<'a>(args: &'a Args, key: &str) -> Option<&'a str> {
    args.get(key).map(String::as_str)
}

/// Return a required arg value by key.
pub fn required_arg<'a>(args: &'a Args, key: &str) -> Result<&'a str> {
    arg(args, key).ok_or_else(|| format!("missing required arg: {key}").into())
}

// ── public entry points (one per kind) ────────────────────────────────

/// Drive a **post-build** module: read implant bytes from stdin,
/// hand them to `f` for mutation, write the result back to stdout.
pub fn post_build<F>(f: F) -> Result<()>
where
    F: FnOnce(&[String], &mut Vec<u8>) -> std::result::Result<(), Box<dyn std::error::Error>>,
{
    let (header, mut payload) = read_request(Kind::PostBuild)?;
    if let Err(e) = f(&header.args, &mut payload) {
        write_error(&format!("{e}"))?;
        return Err(e);
    }
    write_response(
        ResponseHeader {
            protocol: PROTOCOL_VERSION,
            ..Default::default()
        },
        &payload,
    )
}

/// Drive an **encrypt** module. The closure returns the encrypted
/// bytes and any number of placeholder-replacement `Pass` entries.
pub fn encrypt<F>(f: F) -> Result<()>
where
    F: FnOnce(
        &[String],
        &[u8],
    ) -> std::result::Result<(Vec<u8>, Vec<WirePass>), Box<dyn std::error::Error>>,
{
    let (header, payload) = read_request(Kind::Encrypt)?;
    match f(&header.args, &payload) {
        Ok((encrypted, pass)) => write_response(
            ResponseHeader {
                protocol: PROTOCOL_VERSION,
                pass,
                ..Default::default()
            },
            &encrypted,
        ),
        Err(e) => {
            write_error(&format!("{e}"))?;
            Err(e)
        }
    }
}

/// Drive a **format-url** module: returns a rewritten URL string.
pub fn format_url<F>(f: F) -> Result<()>
where
    F: FnOnce(&[String], &str) -> std::result::Result<String, Box<dyn std::error::Error>>,
{
    let (header, payload) = read_request(Kind::FormatUrl)?;
    let url = std::str::from_utf8(&payload)
        .map_err(|e| format!("format-url payload must be UTF-8: {e}"))?;
    match f(&header.args, url) {
        Ok(out) => write_response(
            ResponseHeader {
                protocol: PROTOCOL_VERSION,
                string: Some(out.clone()),
                ..Default::default()
            },
            out.as_bytes(),
        ),
        Err(e) => {
            write_error(&format!("{e}"))?;
            Err(e)
        }
    }
}

/// Drive a **format-encrypted** module: reshapes encrypted bytes
/// and may emit additional `Pass` entries for placeholders the
/// reshape introduces.
pub fn format_encrypted<F>(f: F) -> Result<()>
where
    F: FnOnce(
        &[String],
        &[u8],
    ) -> std::result::Result<(Vec<u8>, Vec<WirePass>), Box<dyn std::error::Error>>,
{
    let (header, payload) = read_request(Kind::FormatEncrypted)?;
    match f(&header.args, &payload) {
        Ok((formatted, pass)) => write_response(
            ResponseHeader {
                protocol: PROTOCOL_VERSION,
                pass,
                ..Default::default()
            },
            &formatted,
        ),
        Err(e) => {
            write_error(&format!("{e}"))?;
            Err(e)
        }
    }
}

/// Drive an **upload-remote** module: takes shellcode, returns
/// the URL where it landed.
pub fn upload_remote<F>(f: F) -> Result<()>
where
    F: FnOnce(&[String], &[u8]) -> std::result::Result<String, Box<dyn std::error::Error>>,
{
    let (header, payload) = read_request(Kind::UploadRemote)?;
    match f(&header.args, &payload) {
        Ok(url) => write_response(
            ResponseHeader {
                protocol: PROTOCOL_VERSION,
                string: Some(url.clone()),
                ..Default::default()
            },
            url.as_bytes(),
        ),
        Err(e) => {
            write_error(&format!("{e}"))?;
            Err(e)
        }
    }
}

// ── framing primitives ────────────────────────────────────────────────

fn read_request(expected_kind: Kind) -> Result<(RequestHeader, Vec<u8>)> {
    let mut stdin = std::io::stdin().lock();
    let header_bytes = read_frame(&mut stdin)?
        .ok_or_else(|| "module SDK: stdin closed before header".to_string())?;
    let header: RequestHeader = serde_json::from_slice(&header_bytes)?;
    if header.protocol > PROTOCOL_VERSION {
        return Err(format!(
            "module SDK: host speaks protocol {} which this module (v{}) doesn't",
            header.protocol, PROTOCOL_VERSION
        )
        .into());
    }
    if header.kind != expected_kind {
        return Err(format!(
            "module SDK: this module was authored for kind={:?} but host requested kind={:?}",
            expected_kind, header.kind
        )
        .into());
    }
    let payload = read_frame(&mut stdin)?
        .ok_or_else(|| "module SDK: stdin closed before payload".to_string())?;
    Ok((header, payload))
}

fn write_response(header: ResponseHeader, payload: &[u8]) -> Result<()> {
    let mut stdout = std::io::stdout().lock();
    write_frame(&mut stdout, &serde_json::to_vec(&header)?)?;
    write_frame(&mut stdout, payload)?;
    stdout.flush()?;
    Ok(())
}

fn write_error(msg: &str) -> Result<()> {
    let header = ResponseHeader {
        protocol: PROTOCOL_VERSION,
        error: Some(msg.to_string()),
        ..Default::default()
    };
    let mut stdout = std::io::stdout().lock();
    write_frame(&mut stdout, &serde_json::to_vec(&header)?)?;
    write_frame(&mut stdout, &[])?;
    stdout.flush()?;
    Ok(())
}

fn read_frame<R: Read>(r: &mut R) -> Result<Option<Vec<u8>>> {
    let mut len_buf = [0u8; 4];
    let n = r.read(&mut len_buf)?;
    if n == 0 {
        return Ok(None);
    }
    if n != 4 {
        return Err(format!("module SDK: partial length prefix ({n}/4 bytes)").into());
    }
    let len = u32::from_le_bytes(len_buf) as usize;
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)?;
    Ok(Some(buf))
}

fn write_frame<W: Write>(w: &mut W, payload: &[u8]) -> Result<()> {
    let len = u32::try_from(payload.len())
        .map_err(|_| format!("payload too large: {} bytes > u32::MAX", payload.len()))?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_args_splits_on_first_equals() {
        let args = vec!["name=value=with=equals".to_string()];
        let parsed = parse_args(&args).unwrap();
        assert_eq!(arg(&parsed, "name"), Some("value=with=equals"));
    }

    #[test]
    fn required_arg_errors_when_missing() {
        let parsed = Args::new();
        assert!(required_arg(&parsed, "donor").is_err());
    }
}
