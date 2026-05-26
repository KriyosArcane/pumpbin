//! URL formatter module for PumpBin (remote mode).
//!
//! Demonstrates the `format_url_remote` hook. In remote mode, an operator
//! provides a URL to the hosted shellcode. This module can transform that URL
//! before it's embedded in the binary — useful for adding query parameters,
//! prepending a CDN prefix, or encoding the URL.
//!
//! # Hooks exported
//! - `format_url_remote` — transforms the operator-supplied URL
//! - `plugin_schema` — declares config fields
//!
//! # Config fields
//! - `url_prefix` (optional): prepended to every URL (e.g. `https://cdn.example.com/`)
//! - `url_suffix` (optional): appended to every URL (e.g. `?v=2`)
//! - `encoding` (choice): `none` | `base64` — encode the URL before embedding
//!
//! # Usage
//! 1. Compile: `cargo build --release --target wasm32-wasip1`
//! 2. In PumpBin Maker: use alongside a remote-mode binary template.
//!    The template's URL holder must be large enough for the encoded URL.

use pumpbin_plugin_sdk::*;

#[plugin_fn]
pub fn plugin_schema() -> FnResult<Json<PluginConfigSchema>> {
    Ok(Json(PluginConfigSchema::new(vec![
        PluginConfigField::new("url_prefix", "text")
            .description("String prepended to the operator URL before embedding.")
            .default(""),
        PluginConfigField::new("url_suffix", "text")
            .description("String appended to the operator URL before embedding.")
            .default(""),
        PluginConfigField::new("encoding", "choice")
            .description("How to encode the final URL string in the binary.")
            .default("none")
            .options(vec!["none", "base64"]),
    ])))
}

#[plugin_fn]
pub fn format_url_remote(
    Json(input): Json<FormatUrlRemoteInput>,
) -> FnResult<Json<FormatUrlRemoteOutput>> {
    let prefix = pumpbin_config!("url_prefix").unwrap_or_default();
    let suffix = pumpbin_config!("url_suffix").unwrap_or_default();
    let encoding = pumpbin_config!("encoding").unwrap_or_else(|| "none".to_string());

    let mut url = format!("{}{}{}", prefix, input.url, suffix);

    if encoding == "base64" {
        url = base64_encode(url.as_bytes());
    }

    Ok(Json(FormatUrlRemoteOutput { formatted_url: url }))
}

/// Minimal base64 encoder (RFC 4648 standard alphabet, no padding stripped).
fn base64_encode(input: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::with_capacity((input.len() + 2) / 3 * 4);

    for chunk in input.chunks(3) {
        let b0 = chunk[0] as usize;
        let b1 = chunk.get(1).copied().unwrap_or(0) as usize;
        let b2 = chunk.get(2).copied().unwrap_or(0) as usize;

        out.push(CHARS[b0 >> 2]);
        out.push(CHARS[((b0 & 3) << 4) | (b1 >> 4)]);
        out.push(if chunk.len() > 1 { CHARS[((b1 & 0xf) << 2) | (b2 >> 6)] } else { b'=' });
        out.push(if chunk.len() > 2 { CHARS[b2 & 0x3f] } else { b'=' });
    }

    String::from_utf8(out).unwrap_or_default()
}
