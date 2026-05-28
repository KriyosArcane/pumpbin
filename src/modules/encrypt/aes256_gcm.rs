//! Native AES-256-GCM `EncryptModule`. Replaces the
//! `plugin-examples/aes-gcm-encrypt` WASM plugin.
//!
//! Loader contract (unchanged from the WASM version):
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
        let key = Aes256Gcm::generate_key(&mut OsRng);
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let cipher = Aes256Gcm::new(&key);
        let encrypted = cipher
            .encrypt(&nonce, shellcode)
            .map_err(|e| anyhow!("AES-GCM encrypt failed: {e}"))?;

        Ok(EncryptShellcodeOutput {
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
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes_gcm::Key;

    #[test]
    fn id_and_description_are_stable() {
        let m = AesGcm;
        assert_eq!(m.id(), "aes-gcm");
        assert!(!m.description().is_empty());
    }

    #[test]
    fn encrypt_then_decrypt_roundtrip() {
        let m = AesGcm;
        let shellcode = b"\x90\x90\x90\xc3 example shellcode payload";

        let out = m.encrypt(shellcode).unwrap();
        assert_eq!(out.pass.len(), 2);

        let key_pass = &out.pass[0];
        assert_eq!(key_pass.holder, KEY_HOLDER);
        assert_eq!(key_pass.replace_by.len(), 32);

        let nonce_pass = &out.pass[1];
        assert_eq!(nonce_pass.holder, NONCE_HOLDER);
        assert_eq!(nonce_pass.replace_by.len(), 12);

        let key = Key::<Aes256Gcm>::from_slice(&key_pass.replace_by);
        let nonce = aes_gcm::Nonce::from_slice(&nonce_pass.replace_by);
        let cipher = Aes256Gcm::new(key);
        let decrypted = cipher.decrypt(nonce, out.encrypted.as_slice()).unwrap();

        assert_eq!(decrypted, shellcode);
    }

    #[test]
    fn each_call_yields_unique_key_and_nonce() {
        let m = AesGcm;
        let a = m.encrypt(b"x").unwrap();
        let b = m.encrypt(b"x").unwrap();
        assert_ne!(a.pass[0].replace_by, b.pass[0].replace_by);
        assert_ne!(a.pass[1].replace_by, b.pass[1].replace_by);
    }
}
