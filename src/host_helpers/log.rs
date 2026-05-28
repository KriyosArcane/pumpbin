//! `host::log::{info,warn,error}` — route plugin events into the
//! host's `tracing` JSONL.
//!
//! Each function takes a UTF-8 message. Non-UTF8 input is rejected
//! with `Err(String)` rather than silently coerced — this is the
//! mitigation for the log-leak risk called out in the Phase A plan
//! (a plugin must not be able to log raw shellcode bytes into the
//! host's JSONL).

use extism::{Function, UserData, ValType};

use super::{encode_response, HOST_HELPER_NAMESPACE};

/// Register all log host functions.
pub fn register() -> Vec<Function> {
    vec![
        make("log_info", Level::Info),
        make("log_warn", Level::Warn),
        make("log_error", Level::Error),
    ]
}

#[derive(Clone, Copy)]
enum Level {
    Info,
    Warn,
    Error,
}

fn make(name: &'static str, level: Level) -> Function {
    Function::new(
        name,
        [ValType::I64],
        [ValType::I64],
        UserData::<()>::default(),
        move |current, inputs, outputs, _ud| {
            let raw = current
                .memory_get_val::<Vec<u8>>(&inputs[0])
                .map_err(|e| anyhow::anyhow!("read input memory: {e}"))?;
            let response = handle(level, &raw);
            let bytes = encode_response::<()>(response);
            // memory_set_val writes the new memory handle into outputs[0]
            current
                .memory_set_val(&mut outputs[0], bytes)
                .map_err(|e| anyhow::anyhow!("write output memory: {e}"))?;
            Ok(())
        },
    )
    .with_namespace(HOST_HELPER_NAMESPACE)
}

fn handle(level: Level, raw: &[u8]) -> Result<(), String> {
    // The SDK wrapper always sends the bincoded `Vec<u8>` of the
    // message bytes. Decode that first, then enforce UTF-8 on the
    // inner bytes.
    let msg_bytes: Vec<u8> = super::decode(raw)?;
    let msg = std::str::from_utf8(&msg_bytes)
        .map_err(|e| format!("log message must be valid UTF-8: {e}"))?;
    match level {
        Level::Info => tracing::info!(target: "pumpbin::plugin", "{msg}"),
        Level::Warn => tracing::warn!(target: "pumpbin::plugin", "{msg}"),
        Level::Error => tracing::error!(target: "pumpbin::plugin", "{msg}"),
    }
    Ok(())
}
