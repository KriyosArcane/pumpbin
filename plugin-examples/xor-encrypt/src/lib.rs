//! Single-byte XOR encryption plugin for PumpBin.
//!
//! This is the simplest possible encryption plugin — a good starting point
//! when learning the PumpBin plugin API.
//!
//! # How it works
//! 1. Reads an optional `xor_key` config value (1–255). If absent, generates
//!    a random non-zero byte.
//! 2. XORs every shellcode byte with the key.
//! 3. Returns the key as a `Pass` so PumpBin replaces the `XOR_KEY_HOLDER`
//!    placeholder in the binary template.
//!
//! # Binary template requirements
//! The loader binary must contain the byte sequence `\x00\x00XOR\x00\x00`
//! (7 bytes) as the key placeholder. See `plugin-examples/xor-loader/`.
//!
//! # Usage
//! 1. Compile: `cargo build --release --target wasm32-wasip1`
//! 2. In PumpBin Maker: add the .wasm alongside a compatible loader binary.

use pumpbin_plugin_sdk::{extism_pdk::Error as ExtismError, *};

/// The key placeholder embedded in the loader binary.
/// Must be exactly 1 byte of actual key space. We use a 7-byte holder so
/// PumpBin can find it reliably via memmem.
const KEY_HOLDER: &[u8; 7] = b"\x00\x00XOR\x00\x00";

#[plugin_fn]
pub fn plugin_schema() -> FnResult<Json<PluginConfigSchema>> {
    Ok(Json(PluginConfigSchema::new(vec![
        PluginConfigField::new("xor_key", "number")
            .description("XOR key byte (1–255). Leave empty to generate randomly per implant.")
            .default(""),
        PluginConfigField::new("multi_byte", "boolean")
            .description("If true, uses all 7 placeholder bytes as a multi-byte XOR key.")
            .default("false"),
    ])))
}

#[plugin_fn]
pub fn encrypt_shellcode(
    Json(input): Json<EncryptShellcodeInput>,
) -> FnResult<Json<EncryptShellcodeOutput>> {
    let multi_byte = pumpbin_config!("multi_byte")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false);

    if multi_byte {
        encrypt_multi_byte(input)
    } else {
        encrypt_single_byte(input)
    }
}

fn encrypt_single_byte(input: EncryptShellcodeInput) -> FnResult<Json<EncryptShellcodeOutput>> {
    // Resolve key: config value or random
    let key: u8 = pumpbin_config!("xor_key")
        .and_then(|s| s.parse::<u8>().ok())
        .filter(|&k| k != 0)
        .unwrap_or_else(|| {
            let mut buf = [0u8; 1];
            loop {
                getrandom::getrandom(&mut buf).unwrap_or_default();
                if buf[0] != 0 {
                    break;
                }
            }
            buf[0]
        });

    let encrypted: Vec<u8> = input.shellcode.iter().map(|b| b ^ key).collect();

    // Build the replacement bytes: key at index 2, rest null
    let mut holder_replace = [0u8; 7];
    holder_replace[2] = key; // 'R' position — arbitrary, must match loader

    Ok(Json(EncryptShellcodeOutput {
        encrypted,
        pass: vec![Pass {
            holder: KEY_HOLDER.to_vec(),
            replace_by: holder_replace.to_vec(),
        }],
    }))
}

fn encrypt_multi_byte(input: EncryptShellcodeInput) -> FnResult<Json<EncryptShellcodeOutput>> {
    // Generate a random 7-byte key
    let mut key = [0u8; 7];
    getrandom::getrandom(&mut key)
        .map_err(|e| ExtismError::msg(format!("getrandom: {e}")))?;
    // Ensure none are zero (avoids memmem match issues)
    for byte in key.iter_mut() {
        if *byte == 0 {
            *byte = 0xFF;
        }
    }

    let encrypted: Vec<u8> = input
        .shellcode
        .iter()
        .enumerate()
        .map(|(i, b)| b ^ key[i % 7])
        .collect();

    Ok(Json(EncryptShellcodeOutput {
        encrypted,
        pass: vec![Pass {
            holder: KEY_HOLDER.to_vec(),
            replace_by: key.to_vec(),
        }],
    }))
}
