//! Single-byte XOR `EncryptModule`. Replaces the
//! `plugin-examples/xor-encrypt` WASM plugin (single-byte variant).
//!
//! Loader contract:
//!   - 7-byte placeholder `\x00\x00XOR\x00\x00`. The actual key is
//!     written at offset 2 (the 'R' position); the surrounding zeros
//!     are padding.
//!
//! A non-zero random key byte is generated per call.

use anyhow::Result;
use rand::RngCore;

use crate::modules::EncryptModule;
use crate::plugin_system::{EncryptShellcodeOutput, Pass};

pub const KEY_HOLDER: &[u8; 7] = b"\x00\x00XOR\x00\x00";

pub struct Xor;

impl EncryptModule for Xor {
    fn id(&self) -> &'static str {
        "xor"
    }

    fn description(&self) -> &'static str {
        "Single-byte XOR with random non-zero key"
    }

    fn encrypt(&self, shellcode: &[u8]) -> Result<EncryptShellcodeOutput> {
        let mut rng = rand::thread_rng();
        let mut key = 0u8;
        while key == 0 {
            let mut b = [0u8; 1];
            rng.fill_bytes(&mut b);
            key = b[0];
        }

        let encrypted: Vec<u8> = shellcode.iter().map(|b| b ^ key).collect();

        let mut replace = [0u8; 7];
        replace[2] = key;

        Ok(EncryptShellcodeOutput {
            encrypted,
            pass: vec![Pass {
                holder: KEY_HOLDER.to_vec(),
                replace_by: replace.to_vec(),
            }],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_then_decrypt_roundtrip() {
        let m = Xor;
        let shellcode = b"\x90\x90\x90\xc3 example shellcode";
        let out = m.encrypt(shellcode).unwrap();
        assert_eq!(out.pass.len(), 1);
        assert_eq!(out.pass[0].holder, KEY_HOLDER);
        assert_eq!(out.pass[0].replace_by.len(), 7);

        let key = out.pass[0].replace_by[2];
        assert_ne!(key, 0);
        let decrypted: Vec<u8> = out.encrypted.iter().map(|b| b ^ key).collect();
        assert_eq!(decrypted, shellcode);
    }
}
