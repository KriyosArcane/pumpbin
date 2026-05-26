//! Authenticode signing stub module for PumpBin.
//!
//! Demonstrates the `post_binary` hook. This is a stub — real Authenticode
//! signing requires an external tool (osslsigncode) or a native WASM crypto
//! library, which is out of scope for this example.
//!
//! To do real signing, use the host-side `self_sign = true` runtime config
//! option with openssl + osslsigncode installed on the host.

use pumpbin_plugin_sdk::*;

#[plugin_fn]
pub fn plugin_schema() -> FnResult<Json<PluginConfigSchema>> {
    Ok(Json(PluginConfigSchema::new(vec![
        PluginConfigField::new("cert_b64", "file_base64")
            .description("Base64-encoded PKCS#12 (.pfx) certificate for signing.")
            .default(""),
        PluginConfigField::new("cert_password", "password")
            .description("Password for the PKCS#12 certificate.")
            .default(""),
        PluginConfigField::new("self_sign", "boolean")
            .description("Generate a self-signed certificate on the host (requires openssl + osslsigncode).")
            .default("false"),
        PluginConfigField::new("sign_cn", "text")
            .description("Common Name for the self-signed certificate (used when self_sign=true).")
            .default("PumpBin Dev Certificate"),
    ])))
}

#[plugin_fn]
pub fn post_binary(Json(input): Json<PostBinaryInput>) -> FnResult<Json<PostBinaryOutput>> {
    let cert_b64 = pumpbin_config!("cert_b64").unwrap_or_default();

    // With no cert, skip — the host-side self_sign path handles actual signing.
    if cert_b64.is_empty() {
        return Ok(Json(PostBinaryOutput {
            final_binary: input.final_binary,
            changed: false,
        }));
    }

    // Stub: in production this would call a WASM-compatible signing library.
    // For now we pass through unchanged and let the host-side signer do the work.
    Ok(Json(PostBinaryOutput {
        final_binary: input.final_binary,
        changed: false,
    }))
}
