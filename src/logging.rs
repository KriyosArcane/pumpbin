//! `tracing` initialization for the PumpBin CLI.
//!
//! - A `fmt` layer writing human-readable lines to stderr (so stdout stays
//!   reserved for machine output).
//! - An `EnvFilter` driven by `PUMPBIN_LOG` (e.g. `PUMPBIN_LOG=debug` or
//!   `PUMPBIN_LOG=pumpbin=debug`). Default level is `info`.
//!
//! # Idempotency
//!
//! `init()` is safe to call more than once.

use tracing_subscriber::fmt::time::SystemTime;
use tracing_subscriber::EnvFilter;

/// Configuration passed by the binary entry point before calling `init`.
#[derive(Debug, Clone)]
pub struct LoggingConfig {
    /// Override the default level. `None` means read `PUMPBIN_LOG` or fall
    /// back to `info`.
    pub level_override: Option<String>,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level_override: None,
        }
    }
}

/// Initialize the global tracing subscriber. Returns `Ok(())` on the first
/// call and `Ok(())` (silently) if a subscriber is already installed. Never
/// panics; logging-init failure should not abort the binary.
pub fn init(config: LoggingConfig) -> std::io::Result<()> {
    // Build the env filter. Precedence:
    //   1. config.level_override (CLI --log-level flag)
    //   2. PUMPBIN_LOG env var
    //   3. default: "info"
    let filter = if let Some(level) = config.level_override.as_deref() {
        EnvFilter::try_new(level).unwrap_or_else(|_| EnvFilter::new("info"))
    } else {
        EnvFilter::try_from_env("PUMPBIN_LOG").unwrap_or_else(|_| EnvFilter::new("info"))
    };

    let _ = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_target(false)
        .with_timer(SystemTime)
        .with_env_filter(filter)
        .try_init();
    Ok(())
}
