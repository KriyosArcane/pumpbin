//! Demo PumpBin post-build module in Rust.
//!
//! The `pumpbin-module-sdk` crate handles the wire protocol; you
//! provide a closure that mutates the implant bytes.

use pumpbin_module_sdk::{arg, parse_args, post_build, Result};

fn main() -> Result<()> {
    post_build(|args, implant| {
        let args = parse_args(args)?;

        // For demo: if `marker=...` is given, use that byte;
        // otherwise default to 0xAA.
        let marker: u8 = arg(&args, "marker")
            .and_then(|s| u8::from_str_radix(s.trim_start_matches("0x"), 16).ok())
            .unwrap_or(0xAA);

        // ── your transformation goes here ──────────────────────
        implant.push(marker);
        // ──────────────────────────────────────────────────────

        Ok(())
    })
}
