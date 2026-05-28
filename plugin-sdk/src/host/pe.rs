//! PE32+ inspection and patching helpers, host-provided.
//!
//! Replaces hand-rolled PE parsing inside plugins. The host uses
//! `goblin` to do the actual work; plugins just call these thin
//! wrappers.
//!
//! All helpers are no-ops on non-PE input and return a structured
//! error (`HostError::Host(...)`) rather than silently corrupting the
//! buffer.
//!
//! # Example
//!
//! ```rust,ignore
//! use pumpbin_plugin_sdk::host::pe;
//!
//! let stripped = pe::strip_debug(&final_binary)?;
//! let with_meta = pe::set_version_info(&stripped, &[
//!     ("CompanyName",     "Acme"),
//!     ("FileDescription", "Helper"),
//!     ("FileVersion",     "1.0.0.0"),
//!     ("ProductName",     "Acme Helper"),
//!     ("ProductVersion",  "1.0.0.0"),
//! ])?;
//! ```

use extism_pdk::host_fn;
use serde::{Deserialize, Serialize};

use super::{decode, encode, unwrap_response, HostError};

// ── wire types (shared with pumpbin/src/host_helpers/pe.rs) ──────────

/// Input to `pe_set_version_info`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetVersionInfoInput {
    pub bin: Vec<u8>,
    /// Ordered list of `(key, value)` string-version pairs. Keys are
    /// VS_VERSION_INFO StringFileInfo names (e.g. `CompanyName`,
    /// `FileDescription`, `FileVersion`, `ProductName`,
    /// `ProductVersion`, `LegalCopyright`, `OriginalFilename`,
    /// `InternalName`). Unknown keys are written verbatim.
    pub fields: Vec<(String, String)>,
}

/// Input to `pe_get_section`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetSectionInput {
    pub bin: Vec<u8>,
    pub name: String,
}

/// Output of `pe_get_section`. Byte range is `[offset, offset+size)`
/// in the input buffer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetSectionOutput {
    pub offset: u32,
    pub size: u32,
}

/// Input to `pe_set_icon`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetIconInput {
    pub bin: Vec<u8>,
    pub icon: Vec<u8>,
}

// ── extern host imports ──────────────────────────────────────────────

#[host_fn("pumpbin:host/v1")]
extern "ExtismHost" {
    fn pe_recompute_checksum(input: Vec<u8>) -> Vec<u8>;
    fn pe_get_section(input: Vec<u8>) -> Vec<u8>;
    fn pe_strip_debug(input: Vec<u8>) -> Vec<u8>;
    fn pe_set_version_info(input: Vec<u8>) -> Vec<u8>;
    fn pe_set_icon(input: Vec<u8>) -> Vec<u8>;
}

// ── safe SDK wrappers ────────────────────────────────────────────────

/// Recompute `IMAGE_OPTIONAL_HEADER.CheckSum` per Microsoft's
/// `CheckSumMappedFile`. No-op on non-PE input.
pub fn recompute_checksum(bin: &[u8]) -> Result<Vec<u8>, HostError> {
    let payload = encode(&bin.to_vec())?;
    let raw = unsafe { pe_recompute_checksum(payload) }
        .map_err(|e| HostError::Wire(format!("pe_recompute_checksum host call: {e}")))?;
    unwrap_response(raw)
}

/// Locate a section by name (e.g. `.rsrc`, `.text`). Returns the file
/// offset and size on disk, or `None` if absent.
pub fn get_section(bin: &[u8], name: &str) -> Result<Option<GetSectionOutput>, HostError> {
    let payload = encode(&GetSectionInput {
        bin: bin.to_vec(),
        name: name.to_string(),
    })?;
    let raw = unsafe { pe_get_section(payload) }
        .map_err(|e| HostError::Wire(format!("pe_get_section host call: {e}")))?;
    unwrap_response(raw)
}

/// Zero out the `IMAGE_DEBUG_DIRECTORY` entries and the data they
/// point at. Returns the modified binary (checksum will need a
/// follow-up [`recompute_checksum`] call).
pub fn strip_debug(bin: &[u8]) -> Result<Vec<u8>, HostError> {
    let payload = encode(&bin.to_vec())?;
    let raw = unsafe { pe_strip_debug(payload) }
        .map_err(|e| HostError::Wire(format!("pe_strip_debug host call: {e}")))?;
    unwrap_response(raw)
}

/// Patch (or add) VS_VERSION_INFO StringFileInfo entries. Replaces
/// the entire StringFileInfo block; the operator chooses every
/// visible key/value pair.
pub fn set_version_info(bin: &[u8], fields: &[(&str, &str)]) -> Result<Vec<u8>, HostError> {
    let payload = encode(&SetVersionInfoInput {
        bin: bin.to_vec(),
        fields: fields
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect(),
    })?;
    let raw = unsafe { pe_set_version_info(payload) }
        .map_err(|e| HostError::Wire(format!("pe_set_version_info host call: {e}")))?;
    unwrap_response(raw)
}

/// Replace the first icon group resource (RT_GROUP_ICON id 1) with
/// the supplied `.ico` file bytes. Caller is responsible for
/// recomputing the checksum.
pub fn set_icon(bin: &[u8], icon: &[u8]) -> Result<Vec<u8>, HostError> {
    let payload = encode(&SetIconInput {
        bin: bin.to_vec(),
        icon: icon.to_vec(),
    })?;
    let raw = unsafe { pe_set_icon(payload) }
        .map_err(|e| HostError::Wire(format!("pe_set_icon host call: {e}")))?;
    unwrap_response(raw)
}

// Bring `decode` into scope for unwrap_response (rustc otherwise warns).
#[allow(dead_code)]
fn _ensure_decode_imported() -> Result<Vec<u8>, HostError> {
    decode::<Vec<u8>>(&[])
}
