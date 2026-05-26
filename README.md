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

**PumpBin is an implant generation platform.** Headless-first, scriptable,
plugin-driven (WASM via Extism), opinionated about OPSEC.

It is **not a C2**. It is the build pipeline that turns a binary template +
a shellcode + a chain of WASM transforms into a working implant on disk.
Pair it with the C2 or post-exploitation framework of your choice.

```
$ pumpbin-cli build -f pumpbin.toml --json | jq .data
{
  "output_path": "out/implant.exe",
  "bytes_written": 4233,
  "sbom_path": "out/implant.exe.pbom.json"
}
```

## Why this exists

Modern red-team teams split into operators and capability researchers.
Researchers produce digital weapons; operators field them. The standard
workflow is one of:

1. **Operator hands shellcode to researcher**, who hand-builds the implant.
   Slow, doesn't scale, every build is one-off.
2. **Researcher writes a loader template and a small build program**.
   Operators feed shellcode into the build program. Faster, scales, but
   every researcher reinvents the build program and its UI.

PumpBin is the second method, generalized. Researchers write a Rust
shellcode loader, embed a placeholder, package it as a `.b1n` plugin
pack. Operators run `pumpbin-cli build -f pumpbin.toml` and get an
implant. The build pipeline (encryption, signing, formatting) is shared
WASM modules everyone can compose.

## Where it fits next to other tools

| Tool | Role | PumpBin's relationship |
|---|---|---|
| **Cobalt Strike** | C2 + beacon framework | Generates beacon shellcode; PumpBin packages it into a custom loader |
| **AdaptixC2** | C2 + extender plugins | Same — Adaptix produces shellcode, PumpBin produces the carrier binary |
| **Sliver / Mythic / Havoc** | C2 + implants | Adaptix/Sliver can produce stagers; PumpBin re-wraps the stager in your loader |
| **NetExec** | Network execution / post-ex | Orthogonal — NetExec runs *after* you've landed, PumpBin builds the thing you land |
| **EvadeX, Donut, msfvenom** | Shellcode generation + format | Upstream of PumpBin; their output is PumpBin's input |

PumpBin is the **carrier-binary build pipeline**, not the C2, not the
shellcode generator. Everything else integrates upstream of it.

## Quick start (CLI, headless)

```bash
# 1. Write a 10-line build profile.
cat > pumpbin.toml <<EOF
schema = "pumpbin.profile/v1"
[plugin]    source = "/opt/plugins/stealth-aes.b1n"
[target]    platform = "windows"; binary_type = "exe"
[shellcode] source = "file"; path = "payload.bin"
[output]    path = "out/implant.exe"; sbom = true
EOF

# 2. Build. Get an implant + an SBOM.
pumpbin-cli build -f pumpbin.toml --json
# {"schema":"pumpbin.cli/v1","ok":true,"data":{
#   "output_path":"out/implant.exe","bytes_written":4233,
#   "sbom_path":"out/implant.exe.pbom.json"}}

# 3. Inspect a plugin pack before adding it to your registry.
pumpbin-cli inspect /opt/plugins/stealth-aes.b1n
# Path: ... | Plugin: stealth-aes | sha256s | runtime policy | config fields

# 4. Convert shellcode for use outside the PumpBin flow.
pumpbin-cli convert --input payload.bin --format python > shellcode.py

# 5. Verify what you built.
pumpbin-cli verify --binary out/implant.exe
```

## What ships in the box

- **`pumpbin`** — Iced 0.13 GUI (Generator + Maker workspaces). Click-driven.
- **`pumpbin-cli`** — clap 4 CLI. Headless, scriptable, JSON output.
  Subcommands: `generate`, `batch`, `build`, `inspect`, `verify`,
  `convert`, `create-b1n`, `completions`.
- **`pumpbin-plugin-sdk`** — Rust crate for writing Extism WASM modules.
  Implements the `encrypt_shellcode`, `format_encrypted_shellcode`,
  `format_url_remote`, `upload_final_shellcode_remote`, `post_binary`,
  `plugin_schema` hook contract.
- **`plugin-examples/`** — reference plugins.
  - `aes-gcm-encrypt`, `xor-encrypt` — encryption modules
  - `url-format` — Remote-mode URL formatter
  - `pe-version-info` — VS_VERSION_INFO patcher
  - `signers/cert-blob-steal` — lift a WIN_CERTIFICATE blob from a
    donor signed PE and graft it onto the implant

## Operational features (v1.4.x)

- **Profile-driven builds** — `pumpbin.toml` is the single source of
  truth for a reproducible build
- **Structured errors** — every failure carries a stable `PB-Exxxx` code
  (see `src/error.rs` for the table)
- **JSON logs** — `$XDG_DATA_HOME/PumpBin/logs/<timestamp>-<pid>.jsonl`
  on every run. No shellcode bytes ever land in the log (regression-
  guarded by `tests/log_redaction.rs`)
- **SBOMs** — set `output.sbom = true`, get a `<output>.pbom.json` with
  plugin sha256, modules sha256s, shellcode sha256, runtime config
  (passwords redacted), builder identity, duration
- **WASM sandbox policy** — every module declares its own `timeout_ms`,
  `allowed_hosts`, `on_error`, `sdk_version`. Default: 3s timeout, no
  network, abort on error
- **OPSEC profile** — `~/.config/pumpbin/opsec.toml` enforces team-wide
  rules (e.g. `require_sbom = true`)
- **Memory hygiene** — shellcode buffers are wiped on drop via
  `zeroize::ZeroizeOnDrop`
- **Atomic writes** — every output file goes through `tempfile + persist`;
  no half-written binaries on crash
- **Plugin signing** — cert-blob-steal plugin lifts a donor signature
  blob onto the implant. Defeats string-match "unsigned" detection;
  does not defeat `WinVerifyTrust` (honest documentation)

## CI / cross-platform

| Job | Linux | macOS | Windows |
|---|---|---|---|
| `cargo fmt --check` | ✅ | — | — |
| `cargo clippy -D warnings` | ✅ | — | — |
| `cargo test --lib --tests` | ✅ | ✅ | ✅ |
| `cargo deny check` | ✅ | — | — |
| `cargo build --release --bin pumpbin` (GUI) | ✅ | — | — |
| `cargo build --release --bin pumpbin-cli` (CLI smoke) | ✅ | ✅ | ✅ |

The Iced 0.13 wgpu deps are flaky to install on macOS/Windows CI
runners, so the GUI binary is Linux-only in CI. The library code path
that CLI + GUI both delegate into **is** tested cross-platform.

## Building from source

```bash
git clone https://github.com/KriyosArcane/pumpbin.git
cd pumpbin

# CLI only (no Iced/wgpu deps required):
cargo build --release --bin pumpbin-cli

# GUI (needs wayland + gtk3 + ssl on Linux):
sudo apt-get install libwayland-dev libxkbcommon-dev libgtk-3-dev libssl-dev
cargo build --release --bin pumpbin

# Plugin examples (compiled to wasm32-wasip1):
cd plugin-examples
cargo build --release --target wasm32-wasip1
```

## License

MIT — see [LICENSE](LICENSE).

## Status

PumpBin is **actively developed** by KriyosArcane based on the original
b1n project. v1.x ships incremental improvements (every CHANGELOG entry
documents what changed and why); v2.0 is planned to cut the legacy
single-WASM `.b1n` format. Until then, every `.b1n` built since v1.0.0
keeps working.

For the full release-by-release history, see [CHANGELOG.md](CHANGELOG.md).
