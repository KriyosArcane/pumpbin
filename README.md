<div align="center">
  <a href="https://github.com/KriyosArcane/pumpbin/releases/latest">
    <img alt="GitHub Release" src="https://img.shields.io/github/v/release/KriyosArcane/pumpbin?sort=semver&filter=v*.*.*&display_name=tag&style=for-the-badge&labelColor=%2324273a&color=%238aadf4"></a>

  <a href="https://github.com/KriyosArcane/pumpbin/actions">
    <img alt="CI" src="https://img.shields.io/github/actions/workflow/status/KriyosArcane/pumpbin/rust.yml?branch=main&style=for-the-badge&labelColor=%2324273a&label=CI"></a>

  <a href="https://github.com/KriyosArcane/pumpbin/blob/main/LICENSE">
    <img alt="GitHub License" src="https://img.shields.io/github/license/KriyosArcane/pumpbin?style=for-the-badge&labelColor=%2324273a&color=%23eed49f"></a>
</div>

# PumpBin

<p align="center">
  <img src="logo/pumpbin-256x256.png" height="30%" width="30%">
</p>

PumpBin is an implant build pipeline for red teams. You write a shellcode loader, package it as a `.b1n`, and stamp shellcode into it with post-build transforms applied automatically.

## Description

Researchers write the loader. Operators run `generate`. The `.b1n` plugin pack bundles everything between them: the loader binary, the placeholder markers, and an optional default transform chain.

PumpBin is not a C2 and not a shellcode generator. It fits between them. Use any shellcode source (msfvenom, Donut, custom) and any C2.

## Features

- Scaffolds a Rust loader crate from a single command
- Auto-detects platform and binary type from the `.b1n`
- Composable post-build module chain per generation
- Built-in AES-256-GCM and XOR encryption modules
- WIN_CERTIFICATE blob grafting onto the implant PE (defeats unsigned-binary string/YARA checks; does not pass WinVerifyTrust without a target-side SIP registry patch)
- In-place equal-length hex byte substitutions for neutralizing YARA byte patterns
- VS_VERSION_INFO StringFileInfo field patching; `from_donor=` clones all 8 string fields (CompanyName, FileDescription, FileVersion, InternalName, LegalCopyright, OriginalFilename, ProductName, ProductVersion) from a donor PE
- Drop-in module support: any language, no recompile, no registration
- Pre-flight YARA scan before deploy
- Dry-run mode to preview output before writing
- `--json` output on `inspect`, `convert`, `build`, and `list-modules` for scripting
- Profile-driven builds via `pumpbin.toml`
- `--randomize-markers` replaces default `$$SHELLCODE$$` / `$$99999$$` placeholder bytes with a unique-per-scaffold random pair to eliminate static template signatures

## Legal

This tool is intended for authorized penetration testing and red team operations only. Use against systems you do not have explicit permission to test is illegal. The authors accept no liability for misuse.

## Requirements

- Rust toolchain (stable) for building loaders
- `yara` binary for `check` subcommand (optional)
- Linux, macOS, or Windows

## Installation

```bash
git clone https://github.com/KriyosArcane/pumpbin.git
cd pumpbin
cargo build --release --bin pumpbin-cli
```

Add `target/release/pumpbin-cli` to your PATH.

GUI build (Linux only):

```bash
sudo apt-get install libwayland-dev libxkbcommon-dev libgtk-3-dev libssl-dev
cargo build --release --bin pumpbin --features gui
```

## Usage

**Scaffold a loader, build it, and pack it in one command:**

```bash
pumpbin-cli new-loader myloader --platform windows --pack
```

**Generate an implant:**

```bash
pumpbin-cli generate -p myloader -s payload.bin
```

`-p myloader` resolves to `myloader/myloader.b1n` automatically. Output defaults to `myloader.exe` in the current directory (extension matches the target platform and type).

**Preview before writing:**

```bash
pumpbin-cli generate -p myloader -s payload.bin --dry-run
```

**Apply post-build transforms:**

```bash
# Graft a stolen cert and patch a YARA byte pattern
pumpbin-cli generate -p myloader -s payload.bin \
    --post cert-graft:donor=/path/to/signed.exe \
    --post byte-patch:patches=4831d2:4833d2

# Long form (backwards-compatible)
pumpbin-cli generate -p myloader -s payload.bin \
    --post cert-graft \
    --post-arg cert-graft=donor=/path/to/signed.exe
```

**Pre-flight scan:**

```bash
pumpbin-cli check implant.exe --yara-rules /path/to/elastic-rules/
```

**Find donor PEs with embedded signatures for cert grafting:**

```bash
pumpbin-cli list-donors /Windows/System32/
```

## Commands

| Command | Description |
|---|---|
| `generate` | Stamp shellcode into a loader. |
| `batch` | Stamp a directory of shellcodes. |
| `build` | Profile-driven build from `pumpbin.toml`. |
| `new-loader` | Scaffold a Rust loader crate. |
| `pack` | Build a scaffolded crate and produce a `.b1n`. |
| `create-b1n` | Pack any pre-built binary into a `.b1n`. |
| `inspect` | Dump `.b1n` metadata. `--brief` for one-liner. `--json` for scripting. |
| `verify` | PE format, checksum, Authenticode, and marker check. |
| `list-modules` | Show installed modules. `--json` for scripting. |
| `module-test` | Test a module in isolation. `--debug` dumps wire frames. |
| `list-donors` | Scan a directory for PEs with embedded (not catalog-only) Authenticode signatures. |
| `check` | Pre-flight YARA scan. |
| `convert` | Reformat shellcode bytes (hex, C array, C#, Python, base64). |
| `completions` | Print shell completion script. |

## Modules

Modules are post-build transforms. Drop-in modules go in `~/.config/pumpbin/modules/<id>/` with a TOML manifest and an executable. Any language. No recompile.

**Built-in modules:**

| Kind | ID | Description |
|---|---|---|
| encrypt | `aes-gcm` | AES-256-GCM, random key and nonce per build. |
| encrypt | `xor` | Single-byte XOR, random non-zero key. |
| format-url | `url-passthrough` | Embed URL as-is for remote-mode builds. |
| post-build | `pe-version-info` | Patch VS_VERSION_INFO StringFileInfo fields. `from_donor=<path>` clones all 8 string fields from a donor PE. |
| post-build | `byte-patch` | In-place equal-length hex substitutions. Useful for neutralizing YARA byte patterns. |
| post-build | `cert-graft` | Graft a donor PE's WIN_CERTIFICATE blob onto the implant. Defeats unsigned-binary string checks. Does not pass WinVerifyTrust without a SIP registry patch on the target. For full Authenticode and `.rsrc` clone use [trustmebro](https://github.com/KriyosArcane/TrustMeBro-Rust). |

See [MODULES.md](MODULES.md) for the full authoring spec.

## Baking transforms into a .b1n

Add `[[package.metadata.pumpbin.post]]` blocks to your loader crate's `Cargo.toml`. Every `generate` run applies them automatically.

```toml
[package.metadata.pumpbin]
name = "myloader"
platform = "windows"

[[package.metadata.pumpbin.post]]
id = "cert-graft"
config = { donor = "/path/to/signed.exe" }

[[package.metadata.pumpbin.post]]
id = "pe-version-info"
config = { from_donor = "/path/to/signed.exe" }
```

## Acknowledgments

Based on the original [b1n](https://github.com/B3nd1k/b1n) project.
