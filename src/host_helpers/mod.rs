//! Host helper ABI exposed to WASM plugins (PumpBin v1.5.0, SDK v2).
//!
//! The SDK (`pumpbin-plugin-sdk::host`) declares
//! `extern "ExtismHost"` imports in the `pumpbin:host/v1` namespace;
//! this module registers the matching `extism::Function`s via
//! `with_function` in `plugin_system.rs::manifest_from_wasm_with_policy`.
//!
//! Wire format: each helper takes a bincode-serialized input `Vec<u8>`
//! and returns a bincode-serialized `Result<T, String>` `Vec<u8>`. The
//! helper itself never panics — every error path produces an
//! `Err(String)` that surfaces in the plugin as `HostError::Host`.

use bincode::config::Configuration;
use extism::Function;
use serde::{Deserialize, Serialize};

pub mod log;
pub mod pe;

/// Wire-format namespace shared with `pumpbin_plugin_sdk::host`.
/// Bumped on incompatible changes.
pub const HOST_HELPER_NAMESPACE: &str = "pumpbin:host/v1";

pub(crate) fn bincode_config() -> Configuration {
    bincode::config::standard()
}

pub(crate) fn decode<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, String> {
    bincode::serde::decode_from_slice(bytes, bincode_config())
        .map(|(v, _)| v)
        .map_err(|e| format!("bincode decode: {e}"))
}

pub(crate) fn encode<T: Serialize>(v: &T) -> Result<Vec<u8>, String> {
    bincode::serde::encode_to_vec(v, bincode_config()).map_err(|e| format!("bincode encode: {e}"))
}

/// Encode a `Result<T, String>` into the wire bytes the SDK expects.
/// Falls back to an encoded `Err(String)` if bincode itself errors,
/// so callers never have to handle host-side encode failure.
pub(crate) fn encode_response<T: Serialize>(res: Result<T, String>) -> Vec<u8> {
    encode(&res).unwrap_or_else(|e| {
        encode::<Result<(), String>>(&Err(format!("encode_response failure: {e}")))
            .expect("encoding an Err(String) must not fail")
    })
}

/// Return the full vector of host functions to attach to every plugin
/// load. Each helper's `register()` already sets the namespace via
/// `Function::with_namespace`, so callers feed this straight into
/// `PluginBuilder::with_functions`.
pub fn host_functions() -> Vec<Function> {
    let mut fns = Vec::new();
    fns.extend(pe::register());
    fns.extend(log::register());
    fns
}
