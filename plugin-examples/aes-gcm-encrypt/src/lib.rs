//! AES-256-GCM encryption plugin for PumpBin.
//!
//! Works with `examples/create_thread_encrypt` — that binary expects:
//!   - A 32-byte AES key at placeholder `$$KKKKKKKKKKKKKKKKKKKKKKKKKKKK$$`
//!   - A 12-byte GCM nonce at placeholder `$$NNNNNNNN$$`
//!
//! The plugin generates a fresh random key + nonce per invocation, encrypts
//! the shellcode, and returns both values as `Pass` entries for PumpBin to
//! inject into the binary.
//!
//! # Usage
//! 1. Compile: `cargo build --release --target wasm32-wasip1`
//! 2. In PumpBin Maker: add the .wasm as the module for a plugin that uses
//!    the `create_thread_encrypt` binary template.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use pumpbin_plugin_sdk::{extism_pdk::Error as ExtismError, *};

// These byte strings MUST match the constants in the binary loader template.
// create_thread_encrypt/src/main.rs uses:
//   const KEY:   &[u8; 32] = b"$$KKKKKKKKKKKKKKKKKKKKKKKKKKKK$$";
//   const NONCE: &[u8; 12] = b"$$NNNNNNNN$$";
const KEY_HOLDER: &[u8; 32] = b"$$KKKKKKKKKKKKKKKKKKKKKKKKKKKK$$";
const NONCE_HOLDER: &[u8; 12] = b"$$NNNNNNNN$$";

/// Advertise config schema. AES-GCM generates keys randomly — no user input
/// needed, but we expose an optional `tag_size` hint for documentation.
#[plugin_fn]
pub fn plugin_schema() -> FnResult<Json<PluginConfigSchema>> {
    Ok(Json(PluginConfigSchema::new(vec![
        PluginConfigField::new("aad", "text")
            .description("Optional additional authenticated data (hex string). Leave empty for none.")
            .default(""),
    ])))
}

#[plugin_fn]
pub fn encrypt_shellcode(
    Json(input): Json<EncryptShellcodeInput>,
) -> FnResult<Json<EncryptShellcodeOutput>> {
    // Generate random 32-byte key and 12-byte nonce
    let mut key_bytes = [0u8; 32];
    let mut nonce_bytes = [0u8; 12];
    getrandom::getrandom(&mut key_bytes)
        .map_err(|e| ExtismError::msg(format!("getrandom key: {e}")))?;
    getrandom::getrandom(&mut nonce_bytes)
        .map_err(|e| ExtismError::msg(format!("getrandom nonce: {e}")))?;

    let cipher = Aes256Gcm::new_from_slice(&key_bytes)
        .map_err(|e| ExtismError::msg(format!("AES init failed: {e}")))?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Optional AAD from config
    let aad_hex = pumpbin_config!("aad").unwrap_or_default();
    let aad = if aad_hex.is_empty() {
        vec![]
    } else {
        hex_decode(&aad_hex).unwrap_or_default()
    };

    // Encrypt with optional AAD
    let encrypted = if aad.is_empty() {
        cipher.encrypt(nonce, input.shellcode.as_slice())
    } else {
        use aes_gcm::aead::Payload;
        cipher.encrypt(nonce, Payload { msg: input.shellcode.as_slice(), aad: &aad })
    }
    .map_err(|e| ExtismError::msg(format!("AES-GCM encrypt failed: {e}")))?;

    Ok(Json(EncryptShellcodeOutput {
        encrypted,
        pass: vec![
            // Replace the 32-byte key placeholder with the actual key
            Pass {
                holder: KEY_HOLDER.to_vec(),
                replace_by: key_bytes.to_vec(),
            },
            // Replace the 12-byte nonce placeholder with the actual nonce
            Pass {
                holder: NONCE_HOLDER.to_vec(),
                replace_by: nonce_bytes.to_vec(),
            },
        ],
    }))
}

/// Minimal hex decoder (avoids pulling in another crate).
fn hex_decode(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}
