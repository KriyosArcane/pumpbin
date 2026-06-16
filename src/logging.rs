//! `tracing` initialization for the PumpBin CLI.
//!
//! Pre-1.1.6 PumpBin had `tracing`-shaped intentions in the plan but no
//! initialized subscriber, so `tracing::info!()` calls would have been
//! silently dropped. v1.1.6 wires:
//!
//! - A `fmt` layer writing human-readable lines to stderr (so stdout stays
//!   reserved for machine output once the `--json` flag lands in Phase 1).
//! - A JSON layer writing structured records to
//!   `$XDG_DATA_HOME/PumpBin/logs/<build-id>.jsonl`. One file per process
//!   invocation; rotation is by-invocation (no in-process rotation needed).
//! - An `EnvFilter` driven by `PUMPBIN_LOG` (e.g. `PUMPBIN_LOG=debug` or
//!   `PUMPBIN_LOG=info,extism=warn`). Default level is `info`.
//!
//! # Secret handling
//!
//! The `#[tracing::instrument(skip(...))]` annotations on hot library
//! functions are the only thing standing between shellcode bytes and the
//! JSON log file. **Audit every `#[instrument]` site for `skip(bin,
//! shellcode_src, pass, runtime_config)` or equivalent.** The
//! `tests/log_redaction.rs` regression test catches accidental leaks.
//!
//! # Idempotency
//!
//! `init()` is safe to call more than once. The second call is a no-op (we install the subscriber via
//! `try_init` which returns Err if one is already set). This matters when
//! tests link the library and a test invocation transitively calls into
//! code that calls `init()`.

use std::path::PathBuf;
use std::sync::OnceLock;
use tracing_subscriber::fmt::time::SystemTime;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

/// Configuration passed by the binary entry point before calling `init`.
#[derive(Debug, Clone)]
pub struct LoggingConfig {
    /// Disable the JSON file sink entirely. Console layer still installed.
    pub no_log_file: bool,
    /// Override the default level. `None` means read `PUMPBIN_LOG` or fall
    /// back to `info`.
    pub level_override: Option<String>,
    /// Override the log file directory. `None` means use
    /// `$XDG_DATA_HOME/PumpBin/logs/`.
    pub log_dir_override: Option<PathBuf>,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            no_log_file: std::env::var_os("PUMPBIN_NO_LOG").is_some(),
            level_override: None,
            log_dir_override: None,
        }
    }
}

/// Unique identifier for this process invocation, used as the log filename
/// stem so concurrent / repeat runs don't clobber each other.
fn build_id() -> &'static str {
    static ID: OnceLock<String> = OnceLock::new();
    ID.get_or_init(|| {
        let ts = chrono::Local::now().format("%Y%m%d-%H%M%S");
        let pid = std::process::id();
        format!("{ts}-{pid}")
    })
    .as_str()
}

fn default_log_dir() -> Option<PathBuf> {
    let mut base = dirs::data_dir()?;
    base.push("PumpBin");
    base.push("logs");
    Some(base)
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

    // Always install the human-readable stderr layer.
    let console_layer = tracing_subscriber::fmt::layer()
        .with_writer(std::io::stderr)
        .with_target(false)
        .with_timer(SystemTime);

    let registry = tracing_subscriber::registry()
        .with(filter)
        .with(console_layer);

    // Build the JSON file layer as an Option — None acts as a no-op layer
    // (tracing-subscriber implements Layer for Option<L>), so all failure
    // cases collapse into a single try_init() call.
    let json_layer = if config.no_log_file {
        None
    } else {
        config
            .log_dir_override
            .or_else(default_log_dir)
            .and_then(|log_dir| {
                std::fs::create_dir_all(&log_dir)
                    .map_err(|e| {
                        eprintln!("pumpbin: cannot create log dir {}: {e}", log_dir.display());
                    })
                    .ok()?;
                let log_path = log_dir.join(format!("{}.jsonl", build_id()));
                std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&log_path)
                    .map_err(|e| {
                        eprintln!("pumpbin: cannot open log file {}: {e}", log_path.display());
                    })
                    .ok()
            })
            .map(|file| {
                tracing_subscriber::fmt::layer()
                    .with_writer(std::sync::Mutex::new(file))
                    .json()
                    .with_target(true)
                    .with_timer(SystemTime)
            })
    };

    let _ = registry.with(json_layer).try_init();
    Ok(())
}

/// Convenience for the most common case: read env + default config + init.
/// Returns the path of the JSON log file (if any) so the binary can print
/// it once on startup.
pub fn init_default() -> Option<PathBuf> {
    let config = LoggingConfig::default();
    let log_path = if config.no_log_file {
        None
    } else {
        config
            .log_dir_override
            .clone()
            .or_else(default_log_dir)
            .map(|d| d.join(format!("{}.jsonl", build_id())))
    };
    let _ = init(config);
    log_path
}
