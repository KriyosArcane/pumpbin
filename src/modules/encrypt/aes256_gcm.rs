//! Native AES-256-GCM `EncryptModule`.
//!
//! Loader contract:
//!   - 32-byte key placeholder `$$KKKKKKKKKKKKKKKKKKKKKKKKKKKK$$`
//!   - 12-byte nonce placeholder `$$NNNNNNNN$$`
//!
//! Random key + nonce per call. The key/nonce are returned in
//! `Pass` entries so the binary patcher can rewrite the placeholders.

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    AeadCore, Aes256Gcm,
};
use anyhow::{anyhow, Result};
use zeroize::Zeroize;

use crate::modules::EncryptModule;
use crate::plugin_system::{EncryptShellcodeOutput, Pass};

pub const KEY_HOLDER: &[u8; 32] = b"$$KKKKKKKKKKKKKKKKKKKKKKKKKKKK$$";
pub const NONCE_HOLDER: &[u8; 12] = b"$$NNNNNNNN$$";

pub struct AesGcm;

impl EncryptModule for AesGcm {
    fn id(&self) -> &'static str {
        "aes-gcm"
    }

    fn description(&self) -> &'static str {
        "AES-256-GCM with random key/nonce per generation"
    }

    fn encrypt(&self, shellcode: &[u8]) -> Result<EncryptShellcodeOutput> {
        let mut key = Aes256Gcm::generate_key(&mut OsRng);
        let mut nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let cipher = Aes256Gcm::new(&key);
        let encrypted = cipher
            .encrypt(&nonce, shellcode)
            .map_err(|e| anyhow!("AES-GCM encrypt failed: {e}"))?;

        let output = EncryptShellcodeOutput {
            encrypted,
            pass: vec![
                Pass {
                    holder: KEY_HOLDER.to_vec(),
                    replace_by: key.to_vec(),
                },
                Pass {
                    holder: NONCE_HOLDER.to_vec(),
                    replace_by: nonce.to_vec(),
                },
            ],
        };

        key.zeroize();
        nonce.zeroize();

        Ok(output)
    }
}
