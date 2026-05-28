<div align="center">
  <a href="https://github.com/KriyosArcane/pumpbin/releases/latest">
    <img alt="GitHub Release" src="https://img.shields.io/github/v/release/KriyosArcane/pumpbin?sort=semver&filter=v*.*.*&display_name=tag&style=for-the-badge&labelColor=%2324273a&color=%238aadf4"></a>

  <a href="https://github.com/KriyosArcane/pumpbin/actions">
    <img alt="CI" src="https://img.shields.io/github/actions/workflow/status/KriyosArcane/pumpbin/rust.yml?branch=main&style=for-the-badge&labelColor=%2324273a&label=CI"></a>

  <a href="https://github.com/KriyosArcane/pumpbin/blob/main/LICENSE">
    <img alt="GitHub License" src="https://img.shields.io/github/license/KriyosArcane/pumpbin?style=for-the-badge&labelColor=%2324273a&color=%23eed49f"></a>
</div>

# 🎃 PumpBin

<p align="center">
  <img src="logo/pumpbin-256x256.png" height="30%" width="30%">
</p>

Implant build pipeline. Write a loader once, package it as a `.b1n`,
stamp shellcode into it from a CLI. Not a C2, not a shellcode
generator — fits between them.

## Quick start

```bash
# 1. Scaffold a Windows loader (a buildable Rust crate)
pumpbin-cli new-loader myloader --platform windows

# 2. Build it and pack it as a .b1n
cd myloader
cargo build --release
./pumpbin-pack.sh

# 3. Stamp your shellcode into the loader
pumpbin-cli generate \
    --plugin myloader.b1n --shellcode payload.bin \
    --platform windows --type exe --output implant.exe
```

You now have `implant.exe`. That's the whole loop.

### Going further

Run transforms over the implant at build time — sign with a stolen
cert, patch out YARA-matched bytes, clone version info from a donor PE,
etc. Each transform is a `--post <module> --post-arg <module>=k=v`
pair:

```bash
pumpbin-cli generate ... \
    --post cert-graft --post-arg cert-graft=donor=/path/to/signed.exe
```

`pumpbin-cli list-modules` shows what's installed.
[MODULES.md](MODULES.md) explains how to write your own.

`pumpbin-cli check implant.exe --yara-rules <dir>` does a pre-flight
local YARA scan so you don't burn a sandbox round-trip on a static hit.

## CLI

```
generate / batch / build       stamp shellcode into a loader
new-loader                     scaffold a Cargo crate (Rust loader)
create-b1n / inspect / verify  pack + audit .b1n plugin packs
list-modules / module-test     list and exercise modules
list-donors                    find PEs with embedded signatures
check                          pre-flight YARA scan
convert / completions          shellcode reformat / shell completion
```

## Modules

Five kinds: `encrypt`, `format-encrypted`, `format-url`,
`upload-remote`, `post-build`. Built-in or drop-in
(`~/.config/pumpbin/modules/<id>/` with a TOML manifest + executable
speaking a length-prefixed JSON wire protocol). Built-ins shadow
externals on id collision.

Shipped built-ins:

| kind | id | what |
|---|---|---|
| encrypt | `aes-gcm` | AES-256-GCM, random key/nonce per build |
| encrypt | `xor` | single-byte XOR |
| format-url | `url-passthrough` | embeds URL as-is |
| post-build | `pe-version-info` | patch VS_VERSION_INFO; supports `from_donor=<path>` |
| post-build | `byte-patch` | in-place hex substitutions, equal-length pairs |
| post-build | `cert-graft` | graft a donor PE's WIN_CERTIFICATE blob |

Full module authoring spec: **[MODULES.md](MODULES.md)**.

## Building

```bash
git clone https://github.com/KriyosArcane/pumpbin.git
cd pumpbin
cargo build --release --bin pumpbin-cli      # CLI

# GUI (Linux deps: libwayland-dev libxkbcommon-dev libgtk-3-dev libssl-dev)
cargo build --release --bin pumpbin
```

## CI

Library + CLI tested on Linux/macOS/Windows. GUI binary builds on
Linux only (Iced/wgpu deps are flaky on hosted macOS/Windows runners).
v2.0 was end-to-end verified on macOS Ventura 13.7.8 under
`dockur/macos`: build, scaffold, pack, stamp, reverse-shell callback
all green; 40/40 lib tests pass natively on Darwin.

## License

MIT — see [LICENSE](LICENSE).

## Status

v2.0 is current. The pre-2.0 Extism/WASM plugin model is retired in
favor of statically-linked Rust modules + a language-agnostic drop-in
protocol. `.b1n` packs built since v1.0.0 still load. Active
development on `feature/*` branches; release history in
[CHANGELOG.md](CHANGELOG.md). Based on the original
[b1n](https://github.com/B3nd1k/b1n) project.
