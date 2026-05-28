//! Host-provided helpers — BOF-style imports for WASM plugins.
//!
//! Added in PumpBin v1.5.0 (SDK v2). Each submodule wraps a family of
//! `#[host_fn]` declarations against the `pumpbin:host/v1` namespace.
//! The host registers them via `extism::PluginBuilder::with_function`
//! in `pumpbin/src/host_helpers.rs`.
//!
//! Wire protocol: each helper takes its inputs as a bincode-serialized
//! `Vec<u8>` and returns a bincode-serialized `Result<T, String>`
//! `Vec<u8>`. The SDK wrapper hides this — plugin authors call typed
//! Rust functions and get typed Rust results back.
//!
//! Available families:
//! - [`pe`] — PE32+ inspection and patching.
//! - [`log`] — emit structured logs into the host's `tracing` JSONL.

use serde::{Deserialize, Serialize};

pub mod log;
pub mod pe;

/// Errors a host helper can surface to its caller.
#[derive(Debug)]
pub enum HostError {
    /// The host returned an error payload (validation, decode, ...).
    Host(String),
    /// (De)serialization between SDK and host failed.
    Wire(String),
}

impl core::fmt::Display for HostError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            HostError::Host(s) => write!(f, "host helper rejected call: {s}"),
            HostError::Wire(s) => write!(f, "host helper wire-format error: {s}"),
        }
    }
}

impl std::error::Error for HostError {}

/// Shared bincode config — keep this identical on both sides of the
/// wire or both ends silently disagree.
pub(crate) fn bincode_config() -> impl bincode::config::Config {
    bincode::config::standard()
}

/// Encode a value to bytes via `serde` + bincode.
pub(crate) fn encode<T: Serialize>(v: &T) -> Result<Vec<u8>, HostError> {
    bincode::serde::encode_to_vec(v, bincode_config())
        .map_err(|e| HostError::Wire(format!("encode: {e}")))
}

/// Decode bytes to a value via `serde` + bincode.
pub(crate) fn decode<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, HostError> {
    bincode::serde::decode_from_slice(bytes, bincode_config())
        .map(|(v, _)| v)
        .map_err(|e| HostError::Wire(format!("decode: {e}")))
}

/// Unwrap a host response: `Result<T, String>` bytes → `Result<T, HostError>`.
pub(crate) fn unwrap_response<T>(bytes: Vec<u8>) -> Result<T, HostError>
where
    T: for<'de> Deserialize<'de>,
{
    let res: Result<T, String> = decode(&bytes)?;
    res.map_err(HostError::Host)
}
