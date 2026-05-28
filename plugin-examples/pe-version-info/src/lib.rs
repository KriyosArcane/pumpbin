//! `pe-version-info` — patch VS_VERSION_INFO StringFileInfo entries
//! in the final PE binary.
//!
//! Rewritten for PumpBin SDK v2 (v1.5.0): the 277-LOC hand-rolled
//! UTF-16LE TLV walker that lived here pre-v1.5.0 is now provided by
//! the host as `pumpbin_plugin_sdk::host::pe::set_version_info`. The
//! walker code itself moved verbatim into
//! `pumpbin/src/host_helpers/pe.rs` so byte-for-byte output is
//! preserved.

use pumpbin_plugin_sdk::host::pe;
use pumpbin_plugin_sdk::*;

#[plugin_fn]
pub fn plugin_schema() -> FnResult<Json<PluginConfigSchema>> {
    Ok(Json(
        PluginConfigSchema::new(vec![
            PluginConfigField::new("company_name", "text")
                .description("CompanyName string in the PE Details tab."),
            PluginConfigField::new("file_description", "text")
                .description("FileDescription string in the PE Details tab."),
            PluginConfigField::new("file_version", "text")
                .description("FileVersion string, e.g. \"1.0.0.0\"."),
            PluginConfigField::new("internal_name", "text")
                .description("InternalName string in the PE Details tab."),
            PluginConfigField::new("legal_copyright", "text")
                .description("LegalCopyright string in the PE Details tab."),
            PluginConfigField::new("original_filename", "text")
                .description("OriginalFilename string in the PE Details tab."),
            PluginConfigField::new("product_name", "text")
                .description("ProductName string in the PE Details tab."),
            PluginConfigField::new("product_version", "text")
                .description("ProductVersion string, e.g. \"1.0\"."),
        ])
        .with_runtime(RuntimeConfig {
            timeout_ms: 3000,
            allowed_hosts: vec![],
            on_error: OnError::Abort,
            sdk_version: Some(PUMPBIN_SDK_VERSION),
        }),
    ))
}

#[plugin_fn]
pub fn post_binary(Json(input): Json<PostBinaryInput>) -> FnResult<Json<PostBinaryOutput>> {
    let patches: &[(&str, &str)] = &[
        ("CompanyName", "company_name"),
        ("FileDescription", "file_description"),
        ("FileVersion", "file_version"),
        ("InternalName", "internal_name"),
        ("LegalCopyright", "legal_copyright"),
        ("OriginalFilename", "original_filename"),
        ("ProductName", "product_name"),
        ("ProductVersion", "product_version"),
    ];

    let resolved: Vec<(&str, String)> = patches
        .iter()
        .filter_map(|(key, cfg)| pumpbin_config!(cfg).map(|v| (*key, v)))
        .collect();

    if resolved.is_empty() {
        return Ok(Json(PostBinaryOutput {
            final_binary: input.final_binary,
            changed: false,
        }));
    }

    let fields: Vec<(&str, &str)> = resolved.iter().map(|(k, v)| (*k, v.as_str())).collect();
    let patched = pe::set_version_info(&input.final_binary, &fields)
        .map_err(|e| extism_pdk::Error::msg(format!("pe::set_version_info: {e}")))?;

    Ok(Json(PostBinaryOutput {
        final_binary: patched,
        changed: true,
    }))
}
