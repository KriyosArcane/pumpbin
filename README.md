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

PumpBin is an implant build pipeline. You write a shellcode loader once,
package it as a `.b1n` plugin pack, then stamp any shellcode into it and
apply post-build transforms — signature grafting, YARA-pattern patching,
version-info cloning — in a single command. Not a C2, not a shellcode
generator. It fits between them.

## Quick start

```bash
# 1. Scaffold a loader crate and build it immediately
pumpbin-cli new-loader myloader --platform windows --pack

# 2. Preview what generate will do before writing anything
pumpbin-cli generate -p myloader -s payload.bin --dry-run

# 3. Stamp shellcode — target is auto-detected from the .b1n
pumpbin-cli generate -p myloader -s payload.bin
```

`-p myloader` resolves to `myloader/myloader.b1n` automatically.
Output defaults to `myloader.exe` in the current directory.

### Post-build transforms

Add transforms after stamping. Two forms — pick whichever is more readable:

```bash
# Short form: module id + args in one flag
pumpbin-cli generate -p myloader -s payload.bin \
    --post cert-graft:donor=/path/to/signed.exe \
    --post byte-patch:patches=4831d2:4833d2

# Long form (backwards-compatible)
pumpbin-cli generate -p myloader -s payload.bin \
    --post cert-graft --post-arg cert-graft=donor=/path/to/signed.exe
```

Bake a default chain into the `.b1n` once so operators never need to
pass `--post` at all — see [MODULES.md](MODULES.md).

### Pre-flight scan

```bash
pumpbin-cli check implant.exe --yara-rules /path/to/rules/
```

Shells out to `yara` and exits non-zero with rule names on a hit. Catch
static detections before burning a sandbox round-trip.

## How it works

```
shellcode.bin ──→ encrypt module ──→ encrypted blob ──┐
                                                        │
loader.b1n  ────→ stamp placeholder ───────────────────→ implant bytes
                                                        │
                  post-build modules ←──────────────────┘
                  (cert-graft, byte-patch, pe-version-info...)
                                                        │
                                                 implant.exe
```

A `.b1n` bundles the loader binary, the placeholder markers, and an
optional default transform chain. Researchers ship the `.b1n`;
operators run `generate`. The transform chain is composable and
language-agnostic — any executable that speaks a simple
length-prefixed JSON wire protocol qualifies as a module.

## CLI reference

| Command | What it does |
|---|---|
| `generate` | Stamp shellcode; `--dry-run` previews without writing |
| `batch` | Stamp a whole directory of shellcodes |
| `build` | Profile-driven build from `pumpbin.toml` |
| `new-loader` | Scaffold a Rust loader crate (`--pack` builds it immediately) |
| `pack` | Build a scaffolded crate and produce a `.b1n` |
| `create-b1n` | Ad-hoc: pack any pre-built binary into a `.b1n` |
| `inspect` | Inspect a `.b1n`; `--brief` for a one-liner, `--diff` to compare two |
| `verify` | Authenticode + checksum + marker sanity check |
| `list-modules` | Show installed modules; `--json` for scripting |
| `module-test` | Exercise a single module; `--debug` dumps wire frames |
| `list-donors` | Scan a dir for PEs with embedded (not catalog-only) signatures |
| `check` | Pre-flight YARA scan before deploy |
| `convert` | Reformat shellcode bytes (hex / C array / Python / base64) |
| `completions` | Emit shell completion script |

## Built-in modules

Modules are composable post-build transforms. Drop-in modules live
in `~/.config/pumpbin/modules/<id>/` and need only a TOML manifest
and an executable — any language, no recompile, no registration.

**Shipped built-ins:**

| Kind | ID | What it does |
|---|---|---|
| encrypt | `aes-gcm` | AES-256-GCM with random key/nonce per build |
| encrypt | `xor` | Single-byte XOR with random non-zero key |
| format-url | `url-passthrough` | Embeds URL as-is (remote-mode builds) |
| post-build | `pe-version-info` | Patch VS_VERSION_INFO string fields; `from_donor=<path>` clones all eight fields from a donor PE in one arg |
| post-build | `byte-patch` | In-place equal-length hex substitutions — useful for breaking specific YARA byte patterns without changing behavior |
| post-build | `cert-graft` | Graft a donor PE's WIN_CERTIFICATE blob; defeats "no signature" string checks. For a full Authenticode + `.rsrc` clone, use the external [`trustmebro`](https://github.com/KriyosArcane/TrustMeBro-Rust) module |

See [MODULES.md](MODULES.md) for the full authoring spec: wire protocol,
manifest format, Python and Rust examples.

## Building

```bash
git clone https://github.com/KriyosArcane/pumpbin.git
cd pumpbin
cargo build --release --bin pumpbin-cli
```

The CLI has no system dependencies. The GUI adds Iced/wgpu:

```bash
# Linux GUI deps
sudo apt-get install libwayland-dev libxkbcommon-dev libgtk-3-dev libssl-dev
cargo build --release --bin pumpbin --features gui
```

## CI

All tests run on Linux, macOS, and Windows. The GUI binary is
Linux-only in CI (Iced/wgpu deps are unreliable on hosted
macOS/Windows runners; the library they delegate to is tested
cross-platform).

v2.0 was end-to-end verified on macOS Ventura 13.7.8 under
`dockur/macos` (QEMU/KVM): scaffold → pack → stamp → reverse-shell
callback all green; 53 lib tests + 116 integration tests pass natively
on Darwin.

## License

MIT — see [LICENSE](LICENSE).

## Status

v2.0 is the current release. The pre-2.0 Extism/WASM plugin model is
retired in favor of statically-linked Rust modules + a language-agnostic
drop-in wire protocol. All `.b1n` packs built since v1.0.0 continue to
load.

Based on the original [b1n](https://github.com/B3nd1k/b1n) project.
Release history: [CHANGELOG.md](CHANGELOG.md).
