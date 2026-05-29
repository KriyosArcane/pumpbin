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

PumpBin is an implant build pipeline. You write a shellcode loader once, package it as a `.b1n` plugin pack, then stamp any shellcode into it. Post-build transforms run at the same time: signature grafting, YARA-pattern patching, version-info cloning. One command from shellcode to finished implant.

It is not a C2. It is not a shellcode generator. It sits between them.

## Quick start

```bash
# Scaffold a loader crate and build it in one step
pumpbin-cli new-loader myloader --platform windows --pack

# Preview exactly what will happen before writing anything
pumpbin-cli generate -p myloader -s payload.bin --dry-run

# Stamp shellcode. Target is auto-detected from the .b1n.
pumpbin-cli generate -p myloader -s payload.bin
```

`-p myloader` resolves to `myloader/myloader.b1n` automatically. Output defaults to `myloader.exe` in the current directory.

## Post-build transforms

Attach transforms with `--post`. Two equivalent forms:

```bash
# Short form: id and args together
pumpbin-cli generate -p myloader -s payload.bin \
    --post cert-graft:donor=/path/to/signed.exe \
    --post byte-patch:patches=4831d2:4833d2

# Long form
pumpbin-cli generate -p myloader -s payload.bin \
    --post cert-graft --post-arg cert-graft=donor=/path/to/signed.exe
```

Bake a default chain into the `.b1n` once so operators never type `--post` at all. See [MODULES.md](MODULES.md).

## Pre-flight scan

```bash
pumpbin-cli check implant.exe --yara-rules /path/to/rules/
```

Calls `yara`, exits non-zero with matching rule names on a hit. Run this before deploying to avoid burning a sandbox on a static detection.

## How it works

```
shellcode.bin -> encrypt module -> encrypted blob -+
                                                   |
loader.b1n    -> stamp placeholder -------------> implant bytes
                                                   |
               post-build modules <----------------+
               (cert-graft, byte-patch, pe-version-info...)
                                                   |
                                            implant.exe
```

A `.b1n` bundles the loader binary, placeholder markers, and an optional default transform chain. Researchers ship the `.b1n`. Operators run `generate`. Modules are composable and language-agnostic: any executable that speaks a length-prefixed JSON wire protocol qualifies.

## CLI reference

| Command | What it does |
|---|---|
| `generate` | Stamp shellcode. `--dry-run` previews without writing. |
| `batch` | Stamp a whole directory of shellcodes. |
| `build` | Profile-driven build from `pumpbin.toml`. |
| `new-loader` | Scaffold a Rust loader crate. `--pack` builds it immediately. |
| `pack` | Build a scaffolded crate and produce a `.b1n`. |
| `create-b1n` | Pack any pre-built binary into a `.b1n` without scaffolding. |
| `inspect` | Inspect a `.b1n`. `--brief` for a one-liner. `--diff` to compare two. |
| `verify` | Authenticode, checksum, and marker sanity check. |
| `list-modules` | Show installed modules. `--json` for scripting. |
| `module-test` | Exercise a single module. `--debug` dumps wire frames. |
| `list-donors` | Scan a directory for PEs with embedded signatures. |
| `check` | Pre-flight YARA scan before deploy. |
| `convert` | Reformat shellcode bytes (hex, C array, Python, base64). |
| `completions` | Emit shell completion script. |

## Built-in modules

Drop-in modules live in `~/.config/pumpbin/modules/<id>/`. They need a TOML manifest and an executable. No source-code changes, no recompile, no registration.

| Kind | ID | What it does |
|---|---|---|
| encrypt | `aes-gcm` | AES-256-GCM with a random key and nonce per build. |
| encrypt | `xor` | Single-byte XOR with a random non-zero key. |
| format-url | `url-passthrough` | Embeds the URL as-is for remote-mode builds. |
| post-build | `pe-version-info` | Patch VS_VERSION_INFO fields. `from_donor=<path>` clones all eight fields from a donor PE. |
| post-build | `byte-patch` | In-place equal-length hex substitutions. Useful for breaking specific YARA byte patterns without changing behavior. |
| post-build | `cert-graft` | Graft a donor PE's WIN_CERTIFICATE blob onto the implant. Defeats unsigned-file string checks. For a full Authenticode and `.rsrc` clone, use the external [trustmebro](https://github.com/KriyosArcane/TrustMeBro-Rust) module. |

Full authoring spec, wire protocol, and examples: [MODULES.md](MODULES.md).

## Building

```bash
git clone https://github.com/KriyosArcane/pumpbin.git
cd pumpbin
cargo build --release --bin pumpbin-cli
```

The CLI has no system dependencies. The GUI requires Iced/wgpu:

```bash
# Linux GUI deps
sudo apt-get install libwayland-dev libxkbcommon-dev libgtk-3-dev libssl-dev
cargo build --release --bin pumpbin --features gui
```

## License

MIT. See [LICENSE](LICENSE).

## Status

v2.0 is the current release. The pre-2.0 Extism/WASM plugin model is replaced by statically-linked Rust modules and a language-agnostic drop-in wire protocol. All `.b1n` packs built since v1.0.0 continue to load.

Based on the original [b1n](https://github.com/B3nd1k/b1n) project. Release history: [CHANGELOG.md](CHANGELOG.md).
