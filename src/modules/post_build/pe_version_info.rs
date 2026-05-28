//! `PostBuildModule` that patches VS_VERSION_INFO StringFileInfo
//! entries in a generated PE. Replaces the WASM
//! `plugin-examples/pe-version-info`.
//!
//! Args are `key=value` pairs. Valid keys: `CompanyName`,
//! `FileDescription`, `FileVersion`, `InternalName`, `LegalCopyright`,
//! `OriginalFilename`, `ProductName`, `ProductVersion`.

use anyhow::{anyhow, Result};

use crate::modules::post_build::parse_kv_args;
use crate::modules::{ArgSpec, PostBuildModule};
use crate::pe::{patch_version_info, read_version_info};

const VALID_KEYS: &[&str] = &[
    "CompanyName",
    "FileDescription",
    "FileVersion",
    "InternalName",
    "LegalCopyright",
    "OriginalFilename",
    "ProductName",
    "ProductVersion",
];

/// Reserved arg name (not a VS_VERSION_INFO key): path to a donor PE
/// whose version info we copy into the implant. Explicit key=value
/// args override fields cloned from the donor.
const FROM_DONOR_KEY: &str = "from_donor";

pub struct PeVersionInfo;

impl PostBuildModule for PeVersionInfo {
    fn id(&self) -> &'static str {
        "pe-version-info"
    }

    fn description(&self) -> &'static str {
        "Patch VS_VERSION_INFO StringFileInfo entries in a PE"
    }

    fn args(&self) -> Vec<ArgSpec> {
        vec![
            ArgSpec::new("from_donor", "path").described(
                "Path to a donor PE. All its VS_VERSION_INFO entries are cloned; \
                 explicit key=value args override individual fields.",
            ),
            ArgSpec::new("CompanyName", "string").described("Replace the CompanyName VS_VERSION_INFO entry"),
            ArgSpec::new("FileDescription", "string").described("Replace the FileDescription entry"),
            ArgSpec::new("FileVersion", "string").described("Replace the FileVersion entry (e.g. '6.1.7600.16385')"),
            ArgSpec::new("InternalName", "string").described("Replace the InternalName entry"),
            ArgSpec::new("LegalCopyright", "string").described("Replace the LegalCopyright entry"),
            ArgSpec::new("OriginalFilename", "string").described("Replace the OriginalFilename entry"),
            ArgSpec::new("ProductName", "string").described("Replace the ProductName entry"),
            ArgSpec::new("ProductVersion", "string").described("Replace the ProductVersion entry"),
        ]
    }

    fn apply(&self, args: &[String], implant: &mut Vec<u8>) -> Result<()> {
        let kv = parse_kv_args(args)?;

        // Validate keys: allow VS_VERSION_INFO keys and the reserved
        // `from_donor` arg.
        for (k, _) in &kv {
            if k == FROM_DONOR_KEY {
                continue;
            }
            if !VALID_KEYS.contains(&k.as_str()) {
                anyhow::bail!(
                    "pe-version-info: unknown key '{k}' (valid: {:?} or '{FROM_DONOR_KEY}')",
                    VALID_KEYS
                );
            }
        }

        // Start with donor's values (if any), then overlay explicit args.
        let mut overlay: std::collections::BTreeMap<String, String> =
            std::collections::BTreeMap::new();
        if let Some((_, donor_path)) = kv.iter().find(|(k, _)| k == FROM_DONOR_KEY) {
            let donor_bytes = std::fs::read(donor_path)
                .map_err(|e| anyhow!("pe-version-info: read donor '{donor_path}': {e}"))?;
            for (k, v) in read_version_info(&donor_bytes) {
                if VALID_KEYS.contains(&k.as_str()) {
                    overlay.insert(k, v);
                }
            }
        }
        for (k, v) in &kv {
            if k != FROM_DONOR_KEY {
                overlay.insert(k.clone(), v.clone());
            }
        }

        let patches: Vec<(&str, String)> = overlay
            .iter()
            .map(|(k, v)| (k.as_str(), v.clone()))
            .collect();
        patch_version_info(implant, &patches);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_key_is_rejected() {
        let m = PeVersionInfo;
        let mut buf = Vec::new();
        let err = m.apply(&["NotARealField=x".into()], &mut buf).unwrap_err();
        assert!(err.to_string().contains("unknown key"));
    }

    #[test]
    fn malformed_arg_is_rejected() {
        let m = PeVersionInfo;
        let mut buf = Vec::new();
        let err = m.apply(&["CompanyName".into()], &mut buf).unwrap_err();
        assert!(err.to_string().contains("expected key=value"));
    }

    #[test]
    fn non_pe_input_is_a_noop_not_an_error() {
        let m = PeVersionInfo;
        let mut buf = b"not a PE".to_vec();
        m.apply(&["CompanyName=Acme".into()], &mut buf).unwrap();
        assert_eq!(buf, b"not a PE");
    }
}
