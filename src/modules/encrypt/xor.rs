//! Single-byte XOR `EncryptModule`.
//!
//! Loader contract: 12-byte placeholder `$$XXXXXXXX$$`. The actual key byte
//! is written at offset 2; the remaining bytes are zeroed.
//!
//! A non-zero random key byte is generated per call.

use anyhow::Result;
use rand::RngCore;

use crate::modules::EncryptModule;
use crate::plugin_system::{EncryptShellcodeOutput, Pass};

pub const KEY_HOLDER: &[u8; 12] = b"$$XXXXXXXX$$";

pub struct Xor;

impl EncryptModule for Xor {
    fn id(&self) -> &'static str {
        "xor"
    }

    fn description(&self) -> &'static str {
        "Single-byte XOR with random non-zero key"
    }

    fn encrypt(&self, shellcode: &[u8]) -> Result<EncryptShellcodeOutput> {
        let mut rng = rand::rng();
        let mut key = 0u8;
        while key == 0 {
            let mut b = [0u8; 1];
            rng.fill_bytes(&mut b);
            key = b[0];
        }

        let encrypted: Vec<u8> = shellcode.iter().map(|b| b ^ key).collect();

        let mut replace = [0u8; 12];
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
