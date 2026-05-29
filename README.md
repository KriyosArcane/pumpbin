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

PumpBin is an implant generation platform for red teams. Write a shellcode loader, package it as a `.b1n`, stamp shellcode into it, and apply post-build transforms in one command.

Not a C2. Not a shellcode generator. Sits between them.

## Quick start

You have a compiled loader binary with PumpBin markers. One command to an implant:

```
$ pumpbin-cli stamp loader.exe payload.bin
[*] Detecting platform from loader.exe (MZ -> windows)
[*] Assembling .b1n from loader.exe
[*] Injecting shellcode
[+] wrote stamp.exe
```

You are writing the loader from scratch:

```
$ pumpbin-cli new-loader myloader --platform windows --pack
[*] Scaffolded loader crate at myloader
[*] cargo build (profile: release)
[*] Packed .b1n -> myloader/myloader.b1n
[+] Scaffolded and packed: myloader/myloader.b1n

$ pumpbin-cli generate -p myloader -s payload.bin
[*] Loading plugin myloader/myloader.b1n
[*] Auto-detected target: Windows / Exe
[*] Injecting shellcode
[+] Generation complete -> myloader.exe
```

## Commands

```
$ pumpbin-cli --help

Usage: pumpbin-cli [OPTIONS] <COMMAND>

Commands:
  stamp        Pack a loader binary and stamp shellcode in one step
  generate     Stamp shellcode into an existing .b1n
  batch        Stamp shellcode from a directory of .bin files
  new-loader   Scaffold a new Rust loader crate
  pack         Build a loader crate and produce a .b1n
  create-b1n   Pack a pre-built binary into a .b1n
  inspect      Inspect a .b1n or check a loader binary for markers
  build        Build from a pumpbin.toml profile
  module       List and test modules
  check        Pre-flight YARA scan
  convert      Reformat shellcode bytes
  list-donors  Find PEs with embedded Authenticode signatures
  completions  Print shell completion script
```

## stamp

```
$ pumpbin-cli stamp --help

Usage: pumpbin-cli stamp [OPTIONS] <LOADER> <SHELLCODE>

Arguments:
  <LOADER>     Compiled loader binary (PE, ELF, or Mach-O)
  <SHELLCODE>  Raw shellcode file (.bin)

Options:
  -o, --output <OUTPUT>       Output path  [default: stamp.<ext>]
      --post <ID[:K=V,K=V]>  Post-build module, repeat to chain
      --save-b1n <PATH>       Save the intermediate .b1n for later reuse

Advanced:
      --platform <PLATFORM>  Override auto-detected platform
  -t, --type <TYPE>          Binary type (exe, lib)  [default: exe]
      --marker <MARKER>      Shellcode placeholder  [default: $$SHELLCODE$$]
```

Apply transforms at stamp time:

```
$ pumpbin-cli stamp loader.exe payload.bin \
    --post cert-graft:donor=/path/to/signed.exe \
    --post byte-patch:patches=4831d2:4833d2 \
    --output implant.exe
[*] Detecting platform from loader.exe (MZ -> windows)
[*] Assembling .b1n from loader.exe
[*] Injecting shellcode
[+] wrote implant.exe
```

Save the `.b1n` for future reuse:

```
$ pumpbin-cli stamp loader.exe payload.bin --save-b1n loader.b1n
[*] Detecting platform from loader.exe (MZ -> windows)
[*] Assembling .b1n from loader.exe
[*] stamp: saved .b1n -> loader.b1n
[*] Injecting shellcode
[+] wrote stamp.exe
```

## generate

```
$ pumpbin-cli generate -h

Usage: pumpbin-cli generate [OPTIONS] --plugin <PLUGIN> --shellcode <SHELLCODE>

Options:
  -p, --plugin <PLUGIN>        .b1n plugin pack or crate directory
  -s, --shellcode <SHELLCODE>  Shellcode file (.bin) or remote URL
  -o, --output <OUTPUT>        Output path  [default: <name>.<ext>]
      --post <ID[:K=V,K=V]>   Post-build module, repeat to chain
      --dry-run                Preview without writing

Advanced:
      --platform <PLATFORM>        Target platform (auto-detected from .b1n)
  -t, --type <TYPE>                Binary type (auto-detected from .b1n)
      --module-config <KEY=VALUE>  Override module config
```

Preview before generating:

```
$ pumpbin-cli generate -p myloader -s payload.bin --dry-run

DRY RUN: nothing will be written

  Plugin:       myloader (v0.1.0)
  Target:       Windows / Exe
  Output:       myloader.exe
  Shellcode:    payload.bin (460 B)
  Module chain: (none)
```

## Post-build modules

Attach transforms with `--post`. Order matters. Two forms:

```
# Plain id
--post cert-graft

# With args (comma-separated key=value after the colon)
--post cert-graft:donor=/path/to/signed.exe
--post byte-patch:patches=4831d2:4833d2,mode=all
--post pe-version-info:from_donor=/path/to/signed.exe
```

List installed modules:

```
$ pumpbin-cli module list

encrypt:
  aes-gcm (built-in) - AES-256-GCM with random key/nonce per generation
  xor (built-in) - Single-byte XOR with random non-zero key
format_url:
  url-passthrough (built-in) - Embeds the operator URL verbatim
post_build:
  pe-version-info (built-in) - Patch VS_VERSION_INFO StringFileInfo entries in a PE
  byte-patch (built-in) - Apply in-place hex byte substitutions to the implant
  cert-graft (built-in) - Graft a donor PE's WIN_CERTIFICATE onto the implant
```

Show args for a specific module:

```
$ pumpbin-cli module list --options --id byte-patch

post_build:
  byte-patch (built-in) - Apply in-place hex byte substitutions to the implant
    patches: string (required)
        Comma-separated <hex_from>:<hex_to> pairs; each pair must be equal length
    mode: string [default: all]
        `all` (replace every occurrence) or `first` (replace only first)
```

Drop-in modules go in `~/.config/pumpbin/modules/<id>/`. A TOML manifest and an executable in any language. See [MODULES.md](MODULES.md).

## inspect

Works on `.b1n` files and compiled loader binaries.

Check a loader for markers before stamping:

```
$ pumpbin-cli inspect myloader/target/release/myloader

file:      myloader/target/release/myloader (306480 bytes)
format:    linux

markers:
  shellcode    "$$SHELLCODE$$"   offset 0x4824
  size-holder  "$$99999$$"       offset 0x6B23

capacity:  4096 bytes (4 KiB)

verdict:   SUITABLE: ready for pumpbin-cli stamp
```

One-line summary of a `.b1n`:

```
$ pumpbin-cli inspect myloader/myloader.b1n --brief

myloader                 linux/exe                        0 modules
```

If markers are missing, print a language guide:

```
$ pumpbin-cli inspect loader.exe --help-markers
```

## check

Pre-flight YARA scan before deploying:

```
$ pumpbin-cli check implant.exe --yara-rules /path/to/elastic-rules/
clean: no YARA matches in implant.exe against /path/to/elastic-rules/
```

Exits non-zero with matching rule names on a hit.

## list-donors

Find PEs with embedded Authenticode signatures for use with `cert-graft`:

```
$ pumpbin-cli list-donors /Windows/System32/

  embedded (1929416 B at 0x0D04B000)  /Windows/System32/MRT.exe
  catalog-only  /Windows/System32/cmd.exe

1 embedded, 42 catalog-only, 0 errored
```

## Installation

```
git clone https://github.com/KriyosArcane/pumpbin.git
cd pumpbin
cargo build --release --bin pumpbin-cli
```

GUI build (Linux):

```
sudo apt-get install libwayland-dev libxkbcommon-dev libgtk-3-dev libssl-dev
cargo build --release --bin pumpbin --features gui
```

## Legal

For authorized penetration testing and red team operations only. The authors accept no liability for misuse.

## Acknowledgments

Based on the original [b1n](https://github.com/B3nd1k/b1n) project. Release history: [CHANGELOG.md](CHANGELOG.md).
