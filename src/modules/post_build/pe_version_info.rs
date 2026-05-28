//! `PostBuildModule` that patches VS_VERSION_INFO StringFileInfo
//! entries in a generated PE. Replaces the WASM
//! `plugin-examples/pe-version-info`.
//!
//! Args are `key=value` pairs. Valid keys: `CompanyName`,
//! `FileDescription`, `FileVersion`, `InternalName`, `LegalCopyright`,
//! `OriginalFilename`, `ProductName`, `ProductVersion`.

use anyhow::Result;

use crate::modules::post_build::parse_kv_args;
use crate::pe::patch_version_info;
use crate::modules::{ArgSpec, PostBuildModule};

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
        for (k, _) in &kv {
            if !VALID_KEYS.contains(&k.as_str()) {
                anyhow::bail!(
                    "pe-version-info: unknown key '{k}' (valid: {:?})",
                    VALID_KEYS
                );
            }
        }
        let patches: Vec<(&str, String)> =
            kv.iter().map(|(k, v)| (k.as_str(), v.clone())).collect();
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
