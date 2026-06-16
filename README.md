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

PumpBin is an implant generation platform for red teams that bring their own loaders. A maldev engineer packages a loader as a `.b1n` loader pack, shares it with the team, and operators stamp shellcode into it with optional modules.

Not a C2. Not a shellcode generator. Sits between them.

## Legal and Authorized Use

PumpBin is for authorized penetration testing, red team operations, and security research only. Do not use it on systems or payloads you do not own or have explicit permission to test.

## Installation

Prerequisites: Rust and Cargo. Install them with [rustup](https://rustup.rs/) if they are not already available.

```
git clone https://github.com/KriyosArcane/pumpbin.git
cd pumpbin
cargo build --release --bin pumpbin-cli
```

## Workflow overview

A `.b1n` is a loader pack: a compiled loader template plus PumpBin metadata, marker rules, and optional modules. Most CLI use falls into one of these paths:

| You have | Use | Result |
| --- | --- | --- |
| A compiled loader binary and shellcode | `pumpbin-cli stamp loader.exe payload.bin` | One stamped implant, with an optional saved `.b1n` |
| A `.b1n` or scaffolded loader crate and shellcode | `pumpbin-cli generate --pack loader.b1n --shellcode payload.bin` | One implant from a reusable pack |
| No loader yet | `pumpbin-cli new-loader myloader --pack` | A Rust loader crate and ready-to-use `.b1n` |
| Many shellcode files | `pumpbin-cli batch --pack loader.b1n --directory payloads/` | One implant per payload |
| A repeatable build profile | `pumpbin-cli build -f pumpbin.toml` | A profile-driven implant build |

## Quick start

### Path A: stamp an existing loader

Use this when you already have a compiled PE, ELF, or Mach-O loader with PumpBin markers embedded:

```
$ pumpbin-cli stamp loader.exe payload.bin
PB  loader.exe            win/exe  [*] reading loader
PB  loader.exe            win/exe  [*] injecting shellcode (460 B)
PB  loader.exe            win/exe  [+] wrote stamp.exe
```

Run `pumpbin-cli inspect loader.exe` first if you are not sure the markers survived the compiler.

### Path B: create a loader from scratch

```
$ pumpbin-cli new-loader myloader --platform windows --pack
PB  myloader              win/exe  [*] cargo build (release)
PB  myloader              win/exe  [+] packed -> myloader/myloader.b1n
wrote myloader/myloader.b1n
Scaffolded and packed: myloader/myloader.b1n

$ pumpbin-cli generate --pack myloader/myloader.b1n --shellcode payload.bin
PB  myloader.b1n          win/exe  [*] loading pack
PB  myloader.b1n          win/exe  [*] injecting shellcode (460 B)
PB  myloader.b1n          win/exe  [+] wrote myloader.exe
```

`generate --pack` also accepts a scaffolded crate directory, so `--pack myloader` is valid after `new-loader --pack`. The short form is `-p`.

## Team Loader Pack Workflow

PumpBin is built for teams that already have their own loaders:

```
# 1. Scaffold or adapt a loader locally.
$ pumpbin-cli new-loader team-loader --platform windows

# 2. Customize the loader source with your own technique, checks, and stubs.
$ $EDITOR team-loader/src/main.rs

# 3. Build and package it as a reusable loader pack.
$ pumpbin-cli pack team-loader/ --output team-loader.b1n

# 4. Inspect the pack before sharing it.
$ pumpbin-cli inspect team-loader.b1n

# 5. Teammates stamp their own payloads and append modules as needed.
$ pumpbin-cli generate --pack team-loader.b1n --shellcode payload.bin \
  --post byte-patch:patches=4831d2:4833d2
```

The `.b1n` contains the compiled template, metadata, marker rules, and baked module chain. It does not require operators to rebuild the loader source.

Loader packs can include a default post-build chain. Operators can append more modules at stamp time with `--post`; appended modules run after the baked chain.

## Marker reference

PumpBin loaders need two markers:

- `$$SHELLCODE$$` marks the start of the placeholder region PumpBin overwrites with shellcode.
- `$$99999$$` is the default size holder the loader reads at runtime.

Two rules matter when converting an existing loader.

1. Your shellcode starts at index 0 after stamping.

PumpBin overwrites the entire placeholder region, including the `$$SHELLCODE$$` prefix itself. Once stamped, byte 0 of your buffer is byte 0 of your shellcode. Do not skip the first 13 bytes. Do not add any offset for the marker. Read from `[0]`.

2. Stop the release compiler from deleting your buffer.

In Rust, wrap the functions returning your shellcode buffer and size holder in `std::hint::black_box` and mark them `#[inline(never)]`. Without those, the compiler can conclude the placeholder parse always fails and remove the buffer. Run `pumpbin-cli inspect` after building to confirm the markers are still present.

## Writing a Loader

Scaffold a new Rust loader crate with `new-loader`:

```
$ pumpbin-cli new-loader myloader --platform windows --no-rwx --pack
```

This generates a Cargo crate under `myloader/` containing:

- A `src/main.rs` with PumpBin markers (`$$SHELLCODE$$` and `$$99999$$`) already embedded in a shellcode buffer.
- `--no-rwx` uses `VirtualAlloc(RW)` then `VirtualProtect(RX)` instead of a single `RWX` allocation.
- `--pack` automatically runs `cargo build --release` and packages the result into `myloader/myloader.b1n`, ready for `pumpbin-cli generate`.

After scaffolding, edit `src/main.rs` to change the injection technique, add sandbox checks, or wire in a decryption stub. Rebuild with `pumpbin-cli pack myloader/` any time you change the source. Run `pumpbin-cli inspect` on the compiled binary to confirm the markers survived the optimizer.

## Commands

Use the workflow overview above to pick the command, then use `--help` on that command for the full current option set.

Global output flags:

```
--json                 Emit machine-readable JSON on stdout
--no-log               Disable the JSON log file sink
--log-level <FILTER>   Override tracing level, e.g. debug or info,extism=warn
```

```
$ pumpbin-cli --help

Usage: pumpbin-cli [OPTIONS] <COMMAND>

Commands:
  stamp        Pack a loader binary and stamp shellcode in one step
  generate     Stamp shellcode into an existing .b1n loader pack
  batch        Stamp shellcode from a directory of .bin files
  new-loader   Scaffold a new Rust loader crate
  pack         Build a loader crate and produce a .b1n
  create-b1n   Pack a pre-built binary into a .b1n loader pack
  inspect      Inspect a .b1n pack or check a loader binary for markers
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
      --save-b1n <PATH>       Save the intermediate .b1n pack for later reuse
      --dry-run                Preview without writing

Advanced:
      --platform <PLATFORM>  Override auto-detected platform
  -t, --type <TYPE>          Binary type (exe, lib)  [default: exe]
      --marker <MARKER>      Shellcode placeholder  [default: $$SHELLCODE$$]
      --size-holder <STRING> Size-holder marker  [default: $$99999$$]
      --name <STRING>        Ephemeral .b1n name  [default: stamp]
```

With post-build transforms:

```
$ pumpbin-cli stamp loader.exe payload.bin \
    --post cert-graft:donor=/path/to/signed.exe \
    --post byte-patch:patches=4831d2:4833d2 \
    --output implant.exe
PB  loader.exe            win/exe  [*] reading loader
PB  loader.exe            win/exe  [*] injecting shellcode (460 B) + cert-graft, byte-patch
PB  loader.exe            win/exe  [+] wrote implant.exe
```

Save the `.b1n` for reuse with `generate`:

```
$ pumpbin-cli stamp loader.exe payload.bin --save-b1n loader.b1n
PB  loader.exe            win/exe  [*] reading loader
PB  loader.exe            win/exe  [*] saved .b1n -> loader.b1n
PB  loader.exe            win/exe  [*] injecting shellcode (460 B)
PB  loader.exe            win/exe  [+] wrote stamp.exe
```

## generate

```
$ pumpbin-cli generate -h

Usage: pumpbin-cli generate [OPTIONS] --pack <PACK> --shellcode <SHELLCODE>

Options:
  -p, --pack <PACK>            .b1n loader pack or crate directory
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
$ pumpbin-cli generate --pack myloader --shellcode payload.bin --dry-run

DRY RUN: nothing will be written

  Pack:         myloader (v0.1.0)
  Target:       Linux / Exe
  Output:       myloader.elf
  Shellcode:    payload.bin (460 B)
  Module chain: (none)
```

## batch

Generate one implant per shellcode file in a directory:

```
$ pumpbin-cli batch --pack loader.b1n --directory payloads/ --output-dir out/
```

Useful options: `--extension` changes the matched file extension, `--platform` and `--type` override auto-detection, and `--module-config` passes module settings.

## pack

Build a scaffolded loader crate and package the resulting binary into a `.b1n`:

```
$ pumpbin-cli pack myloader/
```

Use `--skip-build` to package an already-built artifact, `--profile` to change the Cargo profile, or `--output` to choose the `.b1n` path.

## create-b1n

Pack a pre-built template binary into a reusable `.b1n` without scaffolding a crate:

```
$ pumpbin-cli create-b1n \
    --output loader.b1n \
    --name loader \
    --template loader.exe \
    --platform windows \
    --type exe
```

Add `--encrypt-module <ID>` to bake in a pre-stamp shellcode transform, and repeat `--post <ID[:K=V,K=V]>` to bake post-build modules into the pack.

Use `--post-config <IDX:KEY=VALUE>` when you need to configure a baked post-build module by chain index:

```
$ pumpbin-cli create-b1n \
  --output loader.b1n \
  --name loader \
  --template loader.exe \
  --platform windows \
  --type exe \
  --post cert-graft \
  --post-config 0:donor=/path/to/signed.exe
```

## build

Build from a declarative `pumpbin.toml` profile:

```
$ pumpbin-cli build -f pumpbin.toml
```

Profiles capture the pack source, target, shellcode source, module config, and output path for repeatable local or CI builds.

Minimal profile:

```toml
schema = "pumpbin.profile/v1"

[pack]
source = "loader.b1n"

[target]
platform = "windows"
binary_type = "exe"

[shellcode]
source = "file"
path = "payload.bin"

[output]
path = "implant.exe"
```

## Modules

Modules are small transforms that run at specific points in the build pipeline. They are inspired by NetExec modules and BOF-style workflows: drop in a module, declare its args, test it in isolation, and chain it into a loader pack or a one-off build.

Current module phases:

| Phase | When it runs | Typical use |
| --- | --- | --- |
| `encrypt` | Before shellcode is stamped | Encrypt payload and emit placeholder replacements for keys/nonces |
| `post-build` | After the implant is stamped | Patch bytes, graft cert blobs, clone version info, run finish transforms |

PumpBin ships built-in Rust modules and supports external drop-in modules. External modules are directories with a `pumpbin-module.toml` manifest plus an executable. PumpBin reads the manifest during discovery and does not execute the module until you explicitly use it.

The module pipeline is intentionally linear. That keeps builds readable, reproducible, and easy to audit.

## Post-build modules

Attach transforms with `--post`. Order matters. Two forms:

```
--post cert-graft
--post cert-graft:donor=/path/to/signed.exe
--post byte-patch:patches=4831d2:4833d2,mode=all
--post pe-version-info:from_donor=/path/to/signed.exe
```

Inline `--post` args use `key=value` pairs after the module id. Multiple args are comma-separated. Values may contain commas when the following comma does not start a new `key=value` pair; this is how `byte-patch` accepts multiple patch pairs:

```
$ pumpbin-cli generate --pack loader.b1n --shellcode payload.bin \
  --post byte-patch:patches=4831d2:4833d2,4831c0:4833c0,mode=first
```

Module args are validated before the module runs. Required args, unknown args, basic types, default values, and file/path args are checked from the module schema. Use `--dry-run` for a fast preflight.

For non-post phases, pass module args with scoped config keys:

```
$ pumpbin-cli generate --pack loader.b1n --shellcode payload.bin \
  --module-config module:xor-demo-encrypt.key=0x41
```

When the same post-build module appears more than once, use `--post-config IDX:KEY=VALUE` for index-specific baked-chain config. Inline `--post module:key=value` args are shared by module id.

List installed modules:

```
$ pumpbin-cli module list

encrypt:
  aes-gcm (built-in) - AES-256-GCM with random key/nonce per generation
  xor (built-in) - Single-byte XOR with random non-zero key
post_build:
  pe-version-info (built-in) - Patch VS_VERSION_INFO StringFileInfo entries in a PE
  byte-patch (built-in) - Apply in-place hex byte substitutions to the implant (equal-length pairs only)
  cert-graft (built-in) - Graft a donor PE's WIN_CERTIFICATE onto the implant (cert blob only; use external `trustmebro` for full clone)
```

Show args for a specific module:

```
$ pumpbin-cli module list --options --id byte-patch

post_build:
  byte-patch (built-in) - Apply in-place hex byte substitutions to the implant (equal-length pairs only)
    patches: string (required)
        Comma-separated <hex_from>:<hex_to> pairs; each pair must be equal length
    mode: string [default: all]
        `all` (replace every occurrence) or `first` (replace only first)
```

Some modules also declare constraints. PumpBin checks target constraints and incompatible post-build combinations before generation, so PE-specific modules fail early on non-Windows targets:

```
$ pumpbin-cli module list --options --id cert-graft

post_build:
  cert-graft (built-in) - Graft a donor PE's WIN_CERTIFICATE onto the implant (cert blob only; use external `trustmebro` for full clone)
    constraints: target platform: Windows
    donor: path (required)
        Path to a donor PE with an embedded Authenticode signature
```

Drop-in modules go in `~/.config/pumpbin/modules/<id>/`. A TOML manifest and an executable in any language. See [MODULES.md](MODULES.md). Example external modules live under `examples/modules/`, including Python `encrypt` and `post-build` templates.

Test a module in isolation while authoring it:

```
$ pumpbin-cli module test byte-patch --input implant.exe --arg patches=4831d2:4833d2 --output patched.exe
```

Use `--debug` to dump wire protocol frames to stderr for external modules.

External modules run as subprocesses with the current user's privileges. PumpBin does not sandbox them. Inspect modules before installing them, and treat the module directory like any other executable path.

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

Print a language guide for embedding markers:

```
$ pumpbin-cli inspect loader.exe --help-markers
```

Verify a generated PE or compare two packs:

```
$ pumpbin-cli inspect implant.exe --verify
$ pumpbin-cli inspect old.b1n --diff new.b1n
```

NOT SUITABLE means the markers are missing or the optimizer removed them. If you see NOT SUITABLE on an already-stamped implant, that is expected. The markers were consumed during stamping.

## convert

Reformat shellcode bytes for source embedding or transport:

```
$ pumpbin-cli convert -i payload.bin -f c -o payload.h
```

Formats: `raw`, `hex`, `c`, `csharp`, `python`, and `base64`.

## check

Pre-flight YARA scan before deploying:

```
$ pumpbin-cli check implant.exe --yara-rules /path/to/elastic-rules/
clean: no YARA matches in implant.exe against /path/to/elastic-rules/
```

Exits non-zero with matching rule names on a hit.

## list-donors

Find PEs with embedded Authenticode signatures for `cert-graft`:

```
$ pumpbin-cli list-donors /Windows/System32/ --embedded-only

  embedded (1929416 B at 0x0D04B000)  /Windows/System32/MRT.exe

1 embedded, 0 catalog-only, 0 errored (43 files scanned)
```

## completions

Print a shell completion script:

```
$ pumpbin-cli completions zsh > _pumpbin-cli
```

Supported shells: `bash`, `zsh`, `fish`, `powershell`, and `elvish`.

## Acknowledgments

Based on the original [b1n](https://github.com/B3nd1k/b1n) project. Release history: [CHANGELOG.md](CHANGELOG.md).
