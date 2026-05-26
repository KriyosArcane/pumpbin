//! Format conversion for shellcode bytes.
//!
//! v1.4.0 first chip of Phase 2. The CLI `convert` subcommand wraps
//! this module. Operators feed in a raw `.bin` shellcode and get out
//! the same bytes in a different *representation* (hex string, C
//! literal array, C# byte[], Python bytes literal, base64 blob).
//! Useful for embedding shellcode in source code that gets compiled
//! into something other than the PumpBin implant flow (alt loaders,
//! research papers, training material).
//!
//! Pure formatting — no donut wrapping, no msfvenom shimming. If the
//! input is raw bytes, the output is the same raw bytes in a
//! different ASCII envelope.

use base64::Engine;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputFormat {
    Raw,
    Hex,
    C,
    Csharp,
    Python,
    Base64,
}

impl OutputFormat {
    pub fn from_str_ci(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "raw" | "bin" => Some(Self::Raw),
            "hex" => Some(Self::Hex),
            "c" | "c-array" => Some(Self::C),
            "csharp" | "cs" => Some(Self::Csharp),
            "python" | "py" => Some(Self::Python),
            "base64" | "b64" => Some(Self::Base64),
            _ => None,
        }
    }
}

/// Convert input bytes to the requested output representation. `Raw`
/// returns the bytes unchanged; the other variants return ASCII text.
pub fn convert(input: &[u8], format: OutputFormat) -> Vec<u8> {
    match format {
        OutputFormat::Raw => input.to_vec(),
        OutputFormat::Hex => hex_string(input).into_bytes(),
        OutputFormat::C => render_c_array(input).into_bytes(),
        OutputFormat::Csharp => render_csharp_array(input).into_bytes(),
        OutputFormat::Python => render_python_bytes(input).into_bytes(),
        OutputFormat::Base64 => base64::engine::general_purpose::STANDARD
            .encode(input)
            .into_bytes(),
    }
}

/// Parse a hex-encoded string back to bytes. Mirror of `convert` for
/// the round-trip path used in tests. Accepts whitespace and the
/// common `,` / `:` separators between bytes.
pub fn parse_hex(s: &str) -> anyhow::Result<Vec<u8>> {
    let cleaned: String = s
        .chars()
        .filter(|c| !c.is_whitespace() && *c != ',' && *c != ':')
        .collect();
    if !cleaned.len().is_multiple_of(2) {
        anyhow::bail!("hex length is odd ({})", cleaned.len());
    }
    let mut out = Vec::with_capacity(cleaned.len() / 2);
    for i in (0..cleaned.len()).step_by(2) {
        let byte = u8::from_str_radix(&cleaned[i..i + 2], 16)?;
        out.push(byte);
    }
    Ok(out)
}

fn hex_string(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn render_c_array(bytes: &[u8]) -> String {
    let mut s = String::new();
    s.push_str("unsigned char shellcode[] = {");
    for (i, b) in bytes.iter().enumerate() {
        if i % 12 == 0 {
            s.push_str("\n    ");
        }
        s.push_str(&format!("0x{b:02x}"));
        if i + 1 != bytes.len() {
            s.push_str(", ");
        }
    }
    s.push_str("\n};\n");
    s
}

fn render_csharp_array(bytes: &[u8]) -> String {
    let mut s = String::new();
    s.push_str("byte[] shellcode = new byte[] {");
    for (i, b) in bytes.iter().enumerate() {
        if i % 12 == 0 {
            s.push_str("\n    ");
        }
        s.push_str(&format!("0x{b:02x}"));
        if i + 1 != bytes.len() {
            s.push_str(", ");
        }
    }
    s.push_str("\n};\n");
    s
}

fn render_python_bytes(bytes: &[u8]) -> String {
    let mut s = String::from("shellcode = b\"");
    for b in bytes {
        s.push_str(&format!("\\x{b:02x}"));
    }
    s.push_str("\"\n");
    s
}
