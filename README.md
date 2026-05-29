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

PumpBin is an implant build pipeline for red teams. You write a shellcode loader, package it as a `.b1n`, and stamp shellcode into it. Post-build transforms run at the same time: signature grafting, YARA-pattern patching, version-info cloning. One command from shellcode to finished implant.

It is not a C2. It is not a shellcode generator. It sits between them.

## Quick start

### Starting point A: you have a compiled loader binary

```
$ pumpbin-cli stamp loader.exe payload.bin
```

Platform is auto-detected from the binary magic bytes. Output defaults to `stamp.exe` in the current directory.

With transforms and explicit output:

```
$ pumpbin-cli stamp loader.exe payload.bin \
    --post cert-graft:donor=/path/to/signed.exe \
    --post byte-patch:patches=4831d2:4833d2 \
    --output implant.exe
```

### Starting point B: you are writing the loader

```
$ pumpbin-cli new-loader myloader --platform windows --pack
$ pumpbin-cli generate -p myloader -s payload.bin
```

Preview what will happen before writing:

```
$ pumpbin-cli generate -p myloader -s payload.bin --dry-run

DRY RUN — nothing will be written

  Plugin:       myloader (v0.1.0)
  Target:       Windows / Exe
  Output:       myloader.exe
  Shellcode:    payload.bin (460 B)
  Module chain: (none)
```

## Commands

```
$ pumpbin-cli --help

Implant build pipeline — stamp shellcode into a loader, apply post-build transforms, get an implant.

Usage: pumpbin-cli [OPTIONS] <COMMAND>

Commands:
  generate     Generate an implant from a plugin and shellcode
  batch        Generate multiple implants from a directory of shellcodes
  stamp        Pack a pre-built loader binary and immediately stamp shellcode into it
  pack         Build a scaffolded loader crate and produce a .b1n
  new-loader   Scaffold a new PumpBin-ready loader crate
  create-b1n   Create a .b1n from a pre-built binary (low-level)
  inspect      Inspect a .b1n or check a loader binary for markers
  build        Build from a pumpbin.toml profile file
  module       List and test modules
  check        Pre-flight YARA scan
  convert      Reformat shellcode (hex, C array, Python, base64, ...)
  list-donors  Find PEs with embedded Authenticode signatures
  completions  Print shell completion script
```

## stamp

```
$ pumpbin-cli stamp --help

Usage: pumpbin-cli stamp [OPTIONS] <LOADER> <SHELLCODE>

Arguments:
  <LOADER>     Compiled loader binary (PE, ELF, or Mach-O)
  <SHELLCODE>  Raw shellcode file (.bin) to stamp into the loader

Options:
  -o, --output <OUTPUT>       Output path for the generated implant
      --post <ID[:K=V,K=V]>  Post-build module. Repeat to chain multiple.
      --save-b1n <PATH>       Also write the intermediate .b1n for later reuse

Advanced:
      --platform <PLATFORM>  Override auto-detected platform (windows, linux, darwin)
  -t, --type <TYPE>          Binary type (exe, lib)  [default: exe]
      --marker <MARKER>      Shellcode placeholder marker  [default: $$SHELLCODE$$]
```

## generate

```
$ pumpbin-cli generate --help

Usage: pumpbin-cli generate [OPTIONS] --plugin <PLUGIN> --shellcode <SHELLCODE>

Options:
  -p, --plugin <PLUGIN>        .b1n plugin pack or crate directory
  -s, --shellcode <SHELLCODE>  Shellcode file (.bin) or remote URL
  -o, --output <OUTPUT>        Output file path
      --post <ID[:K=V,K=V]>   Post-build module. Repeat to chain multiple.
      --dry-run                Preview without writing

Advanced:
      --platform <PLATFORM>       Target platform (auto-detected from .b1n)
  -t, --type <TYPE>               Binary type (auto-detected from .b1n)
      --module-config <KEY=VALUE> Override module config
```

## Post-build modules

Modules run after stamping. Two forms:

```
# Plain id
--post cert-graft

# With args (comma-separated key=value)
--post cert-graft:donor=/path/to/signed.exe,mode=fast
--post byte-patch:patches=4831d2:4833d2,mode=all
```

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
  cert-graft (built-in) - Graft a donor PE's WIN_CERTIFICATE blob onto the implant
```

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

Works on both `.b1n` files and compiled loader binaries:

```
$ pumpbin-cli inspect myloader/target/release/myloader

file:      myloader/target/release/myloader (306480 bytes)
format:    linux

markers:
  shellcode    "$$SHELLCODE$$"   offset 0x4824
  size-holder  "$$99999$$"       offset 0x6B23

capacity:  4096 bytes (4 KiB)

verdict:   SUITABLE — ready for pumpbin-cli stamp
```

```
$ pumpbin-cli inspect myloader/myloader.b1n --brief

myloader   linux/exe   0 modules
```

If markers are missing, use `--help-markers` for a language guide:

```
$ pumpbin-cli inspect loader.exe --help-markers
```

## check

Pre-flight YARA scan before deploying:

```
$ pumpbin-cli check implant.exe --yara-rules /path/to/elastic-rules/
```

Exits 0 if clean, non-zero with matching rule names on a hit.

## Find signature donors

```
$ pumpbin-cli list-donors /Windows/System32/

  embedded (1929416 B at 0x0D04B000)  /Windows/System32/MRT.exe
  catalog-only  /Windows/System32/cmd.exe
  ...

1 embedded, 42 catalog-only, 0 errored
```

## Installation

```
git clone https://github.com/KriyosArcane/pumpbin.git
cd pumpbin
cargo build --release --bin pumpbin-cli
```

GUI (Linux, requires Iced/wgpu deps):

```
sudo apt-get install libwayland-dev libxkbcommon-dev libgtk-3-dev libssl-dev
cargo build --release --bin pumpbin --features gui
```

## Legal

For authorized penetration testing and red team operations only. The authors accept no liability for misuse.

## Acknowledgments

Based on the original [b1n](https://github.com/B3nd1k/b1n) project. Release history: [CHANGELOG.md](CHANGELOG.md).
