//! Host-provided logging — route plugin events through the same
//! `tracing` JSONL the host writes.
//!
//! All log helpers take a single UTF-8 message. The host refuses
//! non-UTF8 input to prevent shellcode byte leakage into the log file
//! (see `tests/log_redaction.rs`).
//!
//! # Example
//!
//! ```rust,ignore
//! use pumpbin_plugin_sdk::host::log;
//!
//! log::info("starting AES-GCM encrypt")?;
//! log::warn("falling back to soft RNG")?;
//! ```

use extism_pdk::host_fn;

use super::{unwrap_response, HostError};

#[host_fn("pumpbin:host/v1")]
extern "ExtismHost" {
    fn log_info(msg: Vec<u8>) -> Vec<u8>;
    fn log_warn(msg: Vec<u8>) -> Vec<u8>;
    fn log_error(msg: Vec<u8>) -> Vec<u8>;
}

/// Emit an info-level log event.
pub fn info(msg: &str) -> Result<(), HostError> {
    let raw = unsafe { log_info(msg.as_bytes().to_vec()) }
        .map_err(|e| HostError::Wire(format!("log_info host call: {e}")))?;
    unwrap_response::<()>(raw)
}

/// Emit a warn-level log event.
pub fn warn(msg: &str) -> Result<(), HostError> {
    let raw = unsafe { log_warn(msg.as_bytes().to_vec()) }
        .map_err(|e| HostError::Wire(format!("log_warn host call: {e}")))?;
    unwrap_response::<()>(raw)
}

/// Emit an error-level log event.
pub fn error(msg: &str) -> Result<(), HostError> {
    let raw = unsafe { log_error(msg.as_bytes().to_vec()) }
        .map_err(|e| HostError::Wire(format!("log_error host call: {e}")))?;
    unwrap_response::<()>(raw)
}
