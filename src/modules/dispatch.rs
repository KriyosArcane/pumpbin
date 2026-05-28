//! Module dispatch by string id.
//!
//! Lookup order, per kind:
//!   1. Static (compiled-in) registry — shipped built-ins.
//!   2. External (folder-autodetect) registry — user drop-ins.
//!
//! First match wins. Unknown ids return a clear error listing what
//! IS available so operators can fix typos.

use anyhow::{anyhow, Result};

use crate::modules::external::{self, wire::WireKind};
use crate::modules::{
    encrypt_modules, format_encrypted_modules, format_url_modules, post_build_modules,
    upload_remote_modules, FormatEncryptedOutput,
};
use crate::plugin_system::EncryptShellcodeOutput;

pub fn encrypt(id: &str, shellcode: &[u8]) -> Result<EncryptShellcodeOutput> {
    if let Some(m) = encrypt_modules().iter().find(|m| m.id() == id) {
        return m.encrypt(shellcode);
    }
    if let Some(ext) = external::registry().get(id) {
        if ext.kind() == WireKind::Encrypt {
            let (resp, body) = external::invoke(ext, WireKind::Encrypt, &[], shellcode)?;
            let pass = resp
                .pass
                .iter()
                .map(|p| p.decode())
                .collect::<Result<Vec<_>>>()?;
            return Ok(EncryptShellcodeOutput {
                encrypted: body,
                pass,
            });
        }
    }
    Err(anyhow!(
        "encrypt module not found: '{id}' (available: {:?})",
        available_ids_for(WireKind::Encrypt)
    ))
}

pub fn format_encrypted(id: &str, encrypted: &[u8]) -> Result<FormatEncryptedOutput> {
    if let Some(m) = format_encrypted_modules().iter().find(|m| m.id() == id) {
        return m.format(encrypted);
    }
    if let Some(ext) = external::registry().get(id) {
        if ext.kind() == WireKind::FormatEncrypted {
            let (resp, body) = external::invoke(ext, WireKind::FormatEncrypted, &[], encrypted)?;
            let pass = resp
                .pass
                .iter()
                .map(|p| p.decode())
                .collect::<Result<Vec<_>>>()?;
            return Ok(FormatEncryptedOutput {
                formatted: body,
                pass,
            });
        }
    }
    Err(anyhow!(
        "format_encrypted module not found: '{id}' (available: {:?})",
        available_ids_for(WireKind::FormatEncrypted)
    ))
}

pub fn format_url(id: &str, url: &str) -> Result<String> {
    if let Some(m) = format_url_modules().iter().find(|m| m.id() == id) {
        return m.format(url);
    }
    if let Some(ext) = external::registry().get(id) {
        if ext.kind() == WireKind::FormatUrl {
            let (resp, _body) = external::invoke(ext, WireKind::FormatUrl, &[], url.as_bytes())?;
            return resp
                .string
                .ok_or_else(|| anyhow!("format_url module '{id}' returned no string in response"));
        }
    }
    Err(anyhow!(
        "format_url module not found: '{id}' (available: {:?})",
        available_ids_for(WireKind::FormatUrl)
    ))
}

pub fn upload_remote(id: &str, shellcode: &[u8]) -> Result<String> {
    if let Some(m) = upload_remote_modules().iter().find(|m| m.id() == id) {
        return m.upload(shellcode);
    }
    if let Some(ext) = external::registry().get(id) {
        if ext.kind() == WireKind::UploadRemote {
            let (resp, _body) = external::invoke(ext, WireKind::UploadRemote, &[], shellcode)?;
            return resp
                .string
                .ok_or_else(|| anyhow!("upload_remote module '{id}' returned no string"));
        }
    }
    Err(anyhow!(
        "upload_remote module not found: '{id}' (available: {:?})",
        available_ids_for(WireKind::UploadRemote)
    ))
}

pub fn post_build(id: &str, args: &[String], implant: &mut Vec<u8>) -> Result<()> {
    if let Some(m) = post_build_modules().iter().find(|m| m.id() == id) {
        return m.apply(args, implant);
    }
    if let Some(ext) = external::registry().get(id) {
        if ext.kind() == WireKind::PostBuild {
            let (_resp, body) = external::invoke(ext, WireKind::PostBuild, args, implant)?;
            *implant = body;
            return Ok(());
        }
    }
    Err(anyhow!(
        "post_build module not found: '{id}' (available: {:?})",
        available_ids_for(WireKind::PostBuild)
    ))
}

fn available_ids_for(kind: WireKind) -> Vec<String> {
    let mut out: Vec<String> = match kind {
        WireKind::Encrypt => encrypt_modules()
            .iter()
            .map(|m| m.id().to_string())
            .collect(),
        WireKind::FormatEncrypted => format_encrypted_modules()
            .iter()
            .map(|m| m.id().to_string())
            .collect(),
        WireKind::FormatUrl => format_url_modules()
            .iter()
            .map(|m| m.id().to_string())
            .collect(),
        WireKind::UploadRemote => upload_remote_modules()
            .iter()
            .map(|m| m.id().to_string())
            .collect(),
        WireKind::PostBuild => post_build_modules()
            .iter()
            .map(|m| m.id().to_string())
            .collect(),
    };
    for ext in external::registry().all() {
        if ext.kind() == kind {
            out.push(ext.id().to_string());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_unknown_id_errors() {
        let err = encrypt("does-not-exist", b"x").unwrap_err();
        assert!(err.to_string().contains("encrypt module not found"));
    }

    #[test]
    fn encrypt_aes_gcm_roundtrips() {
        let shellcode = b"\xcc\xcc\xcc\xc3";
        let out = encrypt("aes-gcm", shellcode).unwrap();
        assert!(!out.encrypted.is_empty());
        assert_eq!(out.pass.len(), 2);
    }

    #[test]
    fn post_build_unknown_id_errors() {
        let mut buf = Vec::new();
        let err = post_build("does-not-exist", &[], &mut buf).unwrap_err();
        assert!(err.to_string().contains("post_build module not found"));
    }
}
