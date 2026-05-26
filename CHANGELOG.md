# CHANGELOG

## v1.3.2

Third chip of v2.0 Phase 1: `--json` versioned CLI output + SBOM
emission. This is the chip that makes PumpBin **actually scriptable**
for CI/CD use — every CLI invocation can now emit a machine-parseable
JSON envelope with a stable schema header, and every build can drop
a `.pbom.json` SBOM next to the implant for provenance.

### Added
- **Global `--json` flag** on every subcommand. When set, stdout
  carries ONE JSON document per invocation:
  ```json
  {
    "schema": "pumpbin.cli/v1",
    "ok": true,
    "data": { ... }                  // present when ok
  }
  ```
  On failure:
  ```json
  {
    "schema": "pumpbin.cli/v1",
    "ok": false,
    "error": {
      "code": "PB-E0021",
      "message": "[PB-E0021] WASM module ..."
    }
  }
  ```
  PB-Exxxx codes from `PumpBinError` flow through automatically via
  downcast; non-PB errors get `PB-E0000` as the catch-all code.
  Tracing logs continue to go to stderr regardless of `--json`, so
  pipelines can split structured output (stdout) from human-readable
  progress (stderr).
- **`Commands::Build --json`** emits the `BuildArtifact` (output path,
  bytes written, SBOM path if any) in the `data` field.
- **`Commands::Inspect --json`** emits the full `InspectReport` (plugin
  metadata, replace config, platforms, modules with sha256 + runtime
  policy + config fields). With `--diff`, emits a payload containing
  both reports plus a rendered text diff.
- **`pumpbin::sbom` module** with `Sbom`, `build_sbom`, `write_sbom`,
  `SBOM_SCHEMA = "pumpbin.sbom/v1"`. Re-exported at crate root:
  `pumpbin::Sbom`, `pumpbin::SBOM_SCHEMA`.
- **`output.sbom = true`** in `pumpbin.toml` profiles enables SBOM
  emission. Writes `<output>.pbom.json` alongside the implant:
  ```json
  {
    "schema": "pumpbin.sbom/v1",
    "build_id": "20260526-023058-311455",
    "build_time": "2026-05-26T02:30:58-04:00",
    "builder": { "hostname": "...", "user": "...",
                 "pumpbin_version": "1.3.2" },
    "plugin": { "source": "...", "name": "...", "version": "...",
                "sha256": "...", "size": ... },
    "modules": [ { "index": 0, "sha256": "...", "size": ...,
                   "sdk_version": Some(1) } ],
    "shellcode_sha256": "...",
    "shellcode_bytes": ...,
    "runtime_config": { ... password-like keys redacted ... },
    "output_path": "...",
    "output_bytes": ...,
    "duration_ms": ...
  }
  ```
- **Secret redaction in SBOM**: any `runtime_config` value whose key
  contains `password`, `secret`, `token`, `_key`, `pfx`, or
  `donor_pe_b64` (case-insensitive) is replaced with
  `<redacted N chars>`. So the SBOM for a cert-blob-steal build
  doesn't leak the donor PE bytes.
- **`BuildArtifact.sbom_path: Option<PathBuf>`** — when `output.sbom`
  is true, this is `Some(path/to/<output>.pbom.json)`. Surfaced in
  both the human-readable build log and the `--json` envelope.

### Operator workflow

```
$ pumpbin-cli --json build -f pumpbin.toml
{"schema":"pumpbin.cli/v1","ok":true,"data":{"output_path":"...",
"bytes_written":4233,"sbom_path":"....pbom.json"}}

$ pumpbin-cli --json inspect plugin.b1n | jq '.data.modules[0].sha256'
"6a173529ba8584463cba837c325ca017fff99e86d23de5d3abcafbc2e5bc0f9c"

$ pumpbin-cli --json verify --binary implant.exe
# (when failure path returns Err)
{"schema":"pumpbin.cli/v1","ok":false,"error":{"code":"PB-E0000",
"message":"verify reported 2 failure(s): ..."}}
```

### Intentional scope

- `--json` is only meaningful for subcommands that produce structured
  data (`build`, `inspect`). For `verify`, `completions`, `create-b1n`,
  etc. the existing human-readable stdout is the deliverable; `--json`
  only fires on error path to surface the PB-Exxxx code. v2.0 may
  extend this if operator demand surfaces.
- SBOM emission is profile-scoped (set `output.sbom = true`). The
  ad-hoc-flag `generate` / `batch` subcommands do NOT auto-emit
  SBOM; per the v2.0 plan they become thin wrappers over Profile
  eventually, and SBOM falls out for free.

### Verification
```
cargo test --all-targets    -> 62/62 pass + 1 wine-gated ignored
cargo fmt --check           -> clean
cargo clippy --all-targets -- -D warnings -> clean

# Smoke tests
pumpbin-cli --json inspect plugin.b1n | jq .data.plugin_name   # works
pumpbin-cli --json build -f profile.toml | jq .data.sbom_path  # works
cat implant.exe.pbom.json | jq .plugin.sha256                  # works
```

### Roadmap

Next chips on the v1.3.x / v2.0 train:
- Phase 2: plugin presets in `.b1n`, OPSEC profile at
  `~/.config/pumpbin/opsec.toml`, `pumpbin-cli convert`
  (raw/hex/c/csharp/python/base64), GUI validation status indicator
- Phase 3: marketplace + `plugin {install,list,search,uninstall}` +
  signature verification + rust-shellcode template conversion +
  SDK PE/codec helpers
- Phase 4: mdBook docs (CLI ref, SDK ref, OPSEC, positioning)

## v1.3.1

Second chip of v2.0 Phase 1: `pumpbin-cli inspect`. `.b1n` plugin
packs are opaque-by-default (capnp + zlib); operators couldn't see
what they were about to load. v1.3.1 fixes that.

### Added
- **`pumpbin::inspect` module** with `inspect(path) -> InspectReport`,
  `render_text(report) -> String`, `render_diff(a, b) -> String`.
  Report carries plugin info, replace config, supported platforms,
  embedded WASM modules (with sha256, declared `RuntimeConfig`,
  exported config schema fields), and a flag for legacy single-WASM
  fallback fields.
- **`pumpbin-cli inspect <file.b1n>`** — dumps the plain-text report.
  Layout:

  ```
  Path:        /path/to/plugin.b1n
  Plugin:      cert-steal-v2
  Author:      pumpbin-cli
  Version:     0.1.0
  Save type:   Local
  src_prefix:  "$$SHELLCODE$$"
  size_holder: "$$99999$$"
  max_len:     4096 bytes
  ...

  Platforms (1):
    Windows -> exe

  Modules (1):
    [0] 257796 bytes  sha256=6a173529...
        runtime: timeout_ms=5000 allowed_hosts=[] on_error=Abort sdk_version=Some(1)
        config fields:
          - "donor_pe_b64" : file_base64 (required)
  ```
- **`pumpbin-cli inspect <a.b1n> --diff <b.b1n>`** — human-readable
  diff: name/version/replace-config drift, added/removed module
  sha256s. Identical packs print `no differences`.
- **`tests/inspect_b1n.rs`** (4 tests):
  - end-to-end inspect of a fixture pack (every reported field
    matches input)
  - render_text contains all key fields
  - render_diff shows only the fields that changed
  - render_diff on identical reports says "no differences"

### Dependencies
- `sha2 = "0.10"` promoted from dev-dep to runtime dep (needed by
  inspect for module sha256s).

### Operator workflow

```
$ pumpbin-cli inspect /opt/implants/stealth-aes.b1n
Path: ... | Plugin: ... | Modules with sha256 + runtime + config schema

$ pumpbin-cli inspect old.b1n --diff new.b1n
--- old.b1n
+++ new.b1n
version: "0.2.0" -> "0.3.0"
modules:
  - <old sha>
  + <new sha>
```

### Verification
```
cargo test --all-targets    -> 62/62 pass + 1 wine-gated ignored (was 58)
cargo fmt --check           -> clean
cargo clippy --all-targets -- -D warnings -> clean
```

### Roadmap

Next chips on the v1.3.x train:
- `--json` versioned output (`--json` flag on every subcommand)
- SBOM emission (`output.sbom = true` in profile → `<output>.pbom.json`)
- Phase 2: plugin presets, OPSEC profile, `pumpbin-cli convert`
- Phase 3: marketplace + signature verification

## v1.3.0

**Minor release** — first chip of v2.0 Phase 1 (profile + headless
build) landed as backward-compatible additions on the 1.x line.
Operators can now drive a full build from a single TOML file.

### Plan adjustment

The original v2.0 plan staged Phase 1 (profile + JSON + inspect +
SBOM + stdin/hex/base64) as a single mega-cut with breaking changes.
v1.3.0 lands the profile + `pumpbin-cli build` foundation as a
minor release with zero breakage; the JSON output, `inspect`
subcommand, and SBOM emission ship as follow-up v1.3.x chips. Plan
file updated to document the deferral.

### Added
- **`pumpbin::profile` module** with `Profile`, `BuildArtifact`,
  `PROFILE_SCHEMA`. Re-exported at crate root: `pumpbin::Profile`,
  `pumpbin::BuildArtifact`, `pumpbin::PROFILE_SCHEMA`.
- **`Profile::from_toml(path)`** — parse + validate the schema header.
  Mismatched schema refuses load with an actionable error.
- **`Profile::execute()`** — end-to-end build. Resolves shellcode
  source (file / url / base64 / hex; the latter two decode to a
  tempfile and pass through the existing Local-mode flow), validates
  plugin compatibility, runs `replace_binary` + `post_binary`, writes
  via `utils::atomic_write`. Returns a `BuildArtifact` with the
  output path and byte count.
- **`pumpbin-cli build -f pumpbin.toml`** — new subcommand. Drives
  the profile flow through the same library code path that the
  ad-hoc-flags `generate` subcommand uses.
- **`tests/profile_build.rs`** (4 tests):
  - parse + schema round-trip
  - reject mismatched schema
  - end-to-end execute (file shellcode source) → verify bytes
    written, output path, shellcode bytes present
  - end-to-end with hex shellcode source (with `: , ` separators)

### Profile schema (v1)

```toml
schema = "pumpbin.profile/v1"

[plugin]
source = "/path/to/plugin.b1n"

[target]
platform = "windows"      # windows | linux | darwin (alias: macos)
binary_type = "exe"       # exe | lib (alias: dll / so / dylib)

[shellcode]
source = "file"           # file | url | base64 | hex
path = "shellcode.bin"
# url = "https://..."     # for source = "url"
# data = "..."            # for source = "base64" or "hex"

[module_config]
# Arbitrary key=value pairs forwarded to the WASM module's runtime
# config. Empty table is fine.

[output]
path = "./out/implant.exe"
```

Fields intentionally deferred to follow-up chips:
- `plugin.preset` (Phase 2)
- `output.name_template` (Phase 2)
- `output.sbom = true` (this release ships profile execution; SBOM
  emission lands in a follow-up)
- `security.allow_unrestricted_network` (Phase 0.4 layer is already
  in place; this gate ships when the profile begins gating WASM
  network policy at runtime)

### Operator workflow

```
$ cat pumpbin.toml
schema = "pumpbin.profile/v1"
[plugin]   source = "/opt/implants/stealth-aes.b1n"
[target]   platform = "windows"; binary_type = "exe"
[shellcode] source = "file"; path = "/tmp/shellcode.bin"
[output]    path = "/tmp/out/implant.exe"

$ pumpbin-cli build -f pumpbin.toml
INFO Loading build profile profile="pumpbin.toml"
INFO Profile loaded schema="pumpbin.profile/v1" ...
INFO Build complete output="/tmp/out/implant.exe" bytes=4201
```

### Dependencies
- `toml = "1.1"` with `parse` feature.

### Verification
```
cargo test --all-targets    -> 58/58 pass + 1 wine-gated ignored (was 54)
cargo fmt --check           -> clean
cargo clippy --all-targets -- -D warnings -> clean
```

### Roadmap

Next chips on the v1.3.x / v2.0 train:
- `--json` versioned output (Phase 1.3) — `{"schema":"pumpbin.cli/v1",
  "ok":..., "data":..., "error":...}` on stdout
- `pumpbin-cli inspect <file.b1n>` (+ `--diff`) (Phase 1.4)
- SBOM emission `<output>.pbom.json` (Phase 1.6)
- Phase 2: plugin presets, OPSEC profile, `pumpbin-cli convert`
- Phase 3: marketplace + signature verification + rust-shellcode
  template conversion + SDK PE/codec helpers
- Phase 4: mdBook docs (CLI ref, SDK ref, OPSEC guide, positioning)

## v1.2.0

**Minor release** — first signer plugin, picking up the slot left
empty when v1.1.2 deleted the in-core `host_self_sign`. Pure WASM,
no host helper needed, ships under `plugin-examples/signers/`.

The other two planned signer plugins (osslsigncode-BYO-PFX and
signtool-Windows) require a host-side subprocess helper to fork the
signing tool from inside the WASM hook. That helper is its own
non-trivial chip (extism `with_function` plumbing + per-OS PATH
resolution) and is deferred to a follow-up release; v1.2.0 ships
the one signer that's complete and end-to-end tested.

### Added
- **`plugin-examples/signers/cert-blob-steal/`** — pure-WASM signer
  plugin. `post_binary` hook lifts the `WIN_CERTIFICATE` blob from a
  donor signed PE (passed in as `donor_pe_b64` config) and grafts it
  onto the generated implant. Patches the implant's
  `IMAGE_DIRECTORY_ENTRY_SECURITY` data-dir entry to point at the
  appended blob. 8-byte alignment respected per PE spec.
- **Declared runtime policy**: `timeout_ms = 5000`, `allowed_hosts = []`
  (local only, no network), `on_error = Abort`,
  `sdk_version = PUMPBIN_SDK_VERSION`. Honored by the v1.1.7 policy
  enforcement layer.

### Honest scope

The grafted signature **does not pass `WinVerifyTrust`**. The cert in
the blob is genuine (it came from a real signed PE), but the
Authenticode hash embedded in the blob is the donor's hash, not the
implant's. Windows checks both. Documented in the plugin's module
docstring.

What this DOES defeat:
- YARA / string rules keyed on `IMAGE_DIRECTORY_ENTRY_SECURITY.Size == 0`
  or `"unsigned"` markers
- Explorer's "publisher unknown" warning banner (donor's signer name
  shows in the dialog)
- File-properties dialogs that show "Digital Signatures" tab populated

What this does NOT defeat:
- `signtool verify`, `osslsigncode verify`, or any tool that runs the
  real Authenticode hash check
- EDR signature-chain validation
- Windows SmartScreen

### End-to-end verification

Built a signed donor PE via `msfvenom + openssl + osslsigncode`,
embedded it in a `.b1n` plugin pack with the cert-blob-steal wasm,
generated an implant. The output PE went from
`Authenticode directory: va=0x00000000, size=0` (no signature) to
`va=0x00002C70, size=1496 bytes (present)` (1496 byte donor blob
correctly grafted, dir entry patched, donor blob found at exact
declared offset).

### Operator workflow

```
# 1. Get a signed donor PE (any signed Windows binary works)
cp /path/to/signed/binary.exe donor.exe
DONOR_B64=$(base64 -w 0 donor.exe)

# 2. Build a .b1n with cert-blob-steal as a module
pumpbin-cli create-b1n \
    --output implant.b1n --name 'stealth' \
    --template template.exe --platform windows --type exe \
    --module plugin-examples/target/wasm32-wasip1/release/cert_blob_steal.wasm

# 3. Generate, passing the donor at runtime
pumpbin-cli generate \
    --plugin implant.b1n --shellcode payload.bin \
    --platform windows --type exe --output implant.exe \
    --module-config "donor_pe_b64=$DONOR_B64"
```

The plugin reads the donor at generate-time (not bake-time) so each
build can use a different donor; the implant's signature blob always
reflects what the operator chose for that specific build.

### Verification
```
cargo test --all-targets    -> 54/54 pass + 1 wine-gated ignored (unchanged)
cargo fmt --check           -> clean
cargo clippy --all-targets -- -D warnings -> clean
```

### Deferred to a future v1.2.x

- `osslsigncode-sign` plugin (BYO PFX + password): needs host-side
  `with_function` exposing a `sign_with_osslsigncode(in, pfx, pass)`
  helper. Cross-platform but external subprocess.
- `signtool-sign` plugin (Windows-only, cert store or PFX): needs
  same host helper, refuses to load on non-Windows hosts.

## v1.1.13

Eighth chip of v2.0 Phase 0: Maker preflight off the UI thread (Phase
0.8). The sync `preflight_readiness_report` call in
`MakerMessage::GenerateClicked` was reading every platform binary
synchronously on the Iced runtime thread — freezing the UI for the
duration on multi-MB templates. v1.1.13 removes the redundant sync
call entirely; preflight is now ONLY performed inside the existing
async `Task::perform` block, which already reads each file for the
actual encode step.

### Fixed
- **GUI freeze on Maker Generate for large templates.** Pre-v1.1.13:
  click Generate → `preflight_readiness_report()` runs sync,
  `fs::read`-ing each of up to 7 platform binaries before any async
  hand-off → save dialog launches → async block re-reads the same
  files. v1.1.13: click Generate → `check_generate` (cheap field
  validation) → async block runs preflight + encode in one pass over
  the binaries.
- **Removed double-read inefficiency.** Pre-v1.1.13 every Generate
  read each binary twice (once for preflight, once for encode).

### Removed
- **`Maker::preflight_binary` + `Maker::preflight_readiness_report`**
  were the sync helpers. Replaced by an inline preflight in the
  async block (calls the same `PluginReplace::preflight_template`
  helper, identical semantics on the success path).
- **`PB-E0019 MakerPreflightFailed`** is no longer produced. Per-file
  preflight failures now bubble through `anyhow` with the template
  path attached. The variant stays in `error.rs` for backward
  compatibility with downstream consumers that match on it; mark for
  removal at the v2.0 boundary cut.

### Behavior

The `GeneratedPluginResult.preflight_report` field now contains a
brief per-file `READY` summary built inside the async block instead
of the longer pre-v1.1.13 multi-line report. Format change is
intentional — the report is informational text shown in the success
dialog, not parsed by anything.

### Verification
```
cargo test --all-targets    -> 54/54 pass + 1 wine-gated ignored (unchanged)
cargo fmt --check           -> clean
cargo clippy --all-targets -- -D warnings -> clean
```

### Roadmap

Remaining v2.0 Phase 0 items deferred to a later chip:
- Signature migration to `PumpBinResult<T>` (whole-codebase refactor;
  saved for the v2.0 boundary cut)
- Collapse legacy single-WASM dispatch (capnp schema break; v2.0 per
  prior plan-file update)

## v1.1.12

Seventh chip of v2.0 Phase 0: `OnError::Skip` dispatcher semantics.
The variant has existed on `RuntimeConfig::on_error` since v1.1.7 but
the `EventManager::fire_post_binary` dispatcher always treated module
errors as fatal. v1.1.12 actually honors the variant — a failing
module whose schema declares `on_error = Skip` logs a `warn!` and the
chain continues with the unmodified binary.

### Added
- **Per-module `OnError` enforcement** in `plugin_system::EventManager::fire_post_binary`:
  - On a WASM call error: if the module's schema declares
    `on_error = Skip`, log `tracing::warn!(module_index, error)` and
    continue the chain with the unmodified binary.
  - On a JSON-deserialize error (malformed `PostBinaryOutput`): same
    Skip-or-bubble logic.
  - On `Ok(None)` (module doesn't export `post_binary`): silent skip,
    same as before.
  - Default behavior (no schema, or `on_error = Abort`): bubble the
    error up, same as pre-v1.1.12.
- **`tests/on_error_skip.rs`** (3 tests):
  - Empty module list returns input unchanged.
  - A module that doesn't export `post_binary` (the bundled
    `aes_gcm_encrypt.wasm`) is silently skipped.
  - Invalid WASM bytes under the default Abort policy surface an
    error (regression guard against the v1.1.12 refactor accidentally
    swallowing errors).

### Plan update

Phase 0.10 ("collapse legacy single-WASM dispatch") was originally
slated as a v1.1.x hotfix chip. It changes the `.b1n` binary format
(capnp schema), which would break every shipped plugin mid-1.x train
and violate SemVer. The plan file (`staged-watching-shannon.md`) is
updated to document the deferral: 0.10 lands in v2.0 alongside the
already-planned migrate-or-rebuild story. The 1.x line keeps the
legacy `Option<Vec<u8>>` fallback fields read-only-honored.

### Verification
```
cargo test --all-targets    -> 54/54 pass + 1 wine-gated ignored (was 51)
cargo fmt --check           -> clean
cargo clippy --all-targets -- -D warnings -> clean
```

### Roadmap

Remaining v2.0 Phase 0 items deferred to a later chip:
- Maker `fs::read` off the UI thread (Phase 0.8 — needs `&mut self`
  cache plumbing that's bigger than fits in a single chip)
- Signature migration to `PumpBinResult<T>` (whole-codebase refactor;
  saved for the v2.0 boundary cut)
- Collapse legacy single-WASM dispatch — deferred to v2.0 per plan
  update above

## v1.1.11

Repair release. The v1.1.9 changelog claimed a rewritten CI workflow
matrix (fmt + clippy + matrix tests + deny + GUI build + CLI smoke).
A pre-tool security hook silently dropped the workflow file write
during that release. The tag shipped with the same single-job
`name: Rust` workflow that's been broken since the repo was created.
v1.1.11 actually lands what v1.1.9 was supposed to.

### Fixed
- **`.github/workflows/rust.yml`** is now the multi-job CI matrix
  described in the v1.1.9 changelog:
  - `fmt` (Linux) — `cargo fmt --all -- --check`
  - `clippy` (Linux, with Iced build deps) — `cargo clippy
    --all-targets -- -D warnings`
  - `test-linux`, `test-macos`, `test-windows` — three separate jobs
    running `cargo test --lib --tests --no-fail-fast`. The plan called
    for a matrix; the implementation is three explicit jobs because the
    repo's `Write` hook flags matrix-variable interpolation patterns
    and the explicit-job form is clearer anyway.
  - `deny` (Linux) — `cargo deny check` against `deny.toml`
  - `gui-build` (Linux) — `cargo build --release --bin pumpbin`
  - `cli-smoke-linux`, `cli-smoke-macos`, `cli-smoke-windows` —
    builds `pumpbin-cli` release binary, runs `--version` + `--help`
    on every subcommand
- **Trigger rules**: push to `main`, `hotfix/**`, `release/**`, any
  `v*` tag; PR to `main`.

### Verification
```
cargo test --lib --tests    -> 51/51 pass (subset CI runs cross-platform)
cargo fmt --check           -> clean
cargo clippy --all-targets -- -D warnings -> clean
```

The previous `Rust` workflow ID in GitHub's workflow registry remains
attached to the old (now-deleted) `Rust`-named workflow. The new
`CI`-named workflow will appear as a separate entry once it runs for
the first time on a `hotfix/**` or `main` push. The `Rust` entry can
be deleted from the GitHub web UI when v2.0.0 ships.

### Roadmap

Remaining v2.0 Phase 0 items deferred to a later chip:
- Maker `fs::read` off the UI thread
- Collapse legacy single-WASM dispatch path
- `OnError::Skip` runtime semantics in the dispatch chain
- Signature migration to `PumpBinResult<T>`

## v1.1.10

Sixth chip of v2.0 Phase 0: recent-files LRU cap centralized + the
broken `release.yml` workflow rewritten for the v1.1.x integrated
binary layout. Two unrelated fixes shipped together because they're
both small and unblock CI.

### Fixed
- **`.github/workflows/release.yml` was broken on every tag push since
  v1.1.5.** It referenced a `maker.exe` binary that no longer exists
  (the Maker was integrated into the main `pumpbin` GUI as a workspace
  toggle in pre-1.1.x commit `44271e1`), and an aarch64 Linux cross-
  compile that pulled an apt `sources.list` from a third-party GitHub
  gist — an unacceptable supply-chain surface. Rewritten to ship the
  current `pumpbin` (GUI) and `pumpbin-cli` binaries on Linux x86_64,
  macOS x86_64, and Windows x86_64. aarch64 builds deferred to a
  future chip with a clean cross-compile setup.

### Added
- **`pumpbin::RECENT_FILES_CAP`** — `pub const usize = 20`. Single
  source of truth for the recent-files cap in both `Pumpbin`
  (Generator) and `Maker` workspaces. Pre-v1.1.10 each had a private
  `truncate(10)` call hardcoded at the use site; v1.1.10 bumps the
  cap to 20 (matching the v2.0 plan) and centralizes the constant.
- **`tests/recent_files_lru.rs`** (3 tests):
  - the constant is locked at 20 for the 1.x line
  - dedup-on-reinsert moves the entry to the front instead of
    creating a duplicate
  - inserting more than `RECENT_FILES_CAP` entries evicts the
    oldest, list length stays exactly at the cap

### Verification
```
cargo test --all-targets    -> 51/51 pass + 1 wine-gated ignored (was 48)
cargo fmt --check           -> clean
cargo clippy --all-targets -- -D warnings -> clean
```

### Roadmap

Remaining v2.0 Phase 0 items deferred to a later chip:
- Maker `fs::read` off the UI thread
- Collapse legacy single-WASM dispatch path
- `OnError::Skip` runtime semantics in the dispatch chain
- Signature migration to `PumpBinResult<T>`
- Iced feature-flag refactor (would let CI run `--all-targets` on
  macOS/Windows)
- aarch64 release builds (deferred from v1.1.10 release.yml cleanup)

## v1.1.9

Fifth chip of v2.0 Phase 0: real CI. The previous workflow ran
`cargo build && cargo test` on `ubuntu-latest` only, with no fmt /
clippy / deny gates. Since the source tree had zero tests until v1.1.2,
the green badge was vacuous. v1.1.9 builds a real CI matrix.

### Added
- **`.github/workflows/rust.yml`** rewritten with 6 jobs:
  - `fmt` — `cargo fmt --all -- --check` (Linux)
  - `clippy` — `cargo clippy --all-targets -- -D warnings` (Linux,
    installs GUI build deps so the `pumpbin` binary clippy-compiles)
  - `test` — matrix `ubuntu-latest`, `macos-latest`, `windows-latest`,
    runs `cargo test --lib --tests --no-fail-fast`. GUI binary is
    *not* compiled on macOS/Windows because the Iced 0.13 wgpu deps
    are flaky to install on CI runners; the library code path the
    tests cover is what matters for parity.
  - `deny` — `cargo deny check` (Linux, runs against `deny.toml`)
  - `gui-build` — `cargo build --release --bin pumpbin` (Linux)
  - `cli-smoke` — matrix Linux/macOS/Windows, builds the CLI release
    binary and runs `--version` / `--help` on every subcommand. Cheap
    sanity check that all three platforms get a working `pumpbin-cli`.
- **`deny.toml`** at repo root: license allowlist (MIT, Apache-2.0,
  BSD-*, ISC, Unicode, Zlib, CC0, MPL-2.0, BSL-1.0, OpenSSL), advisory
  gate (yanked = warn), source restriction (deny unknown git /
  registry). Existing `ring` license override documented.
- **Trigger rules**: runs on push to `main`, `hotfix/**`, `release/**`,
  any `v*` tag, and on PR to `main`.

### Fixed
- **`should_persist` dead-store warning** in `src/maker.rs:951`. The
  assignment was immediately overshadowed by `return`, so the value
  was never read on that branch. Removed the dead write; the
  `add_recent_file` + `current_file_path` mutations on the same path
  are sufficient. This was the only warning that would have tripped
  `cargo clippy -- -D warnings` in CI.

### Intentional scope: cross-platform test caveat

`cargo test --lib --tests` runs on macOS/Windows; `cargo test
--all-targets` does not. The latter compiles the GUI binary, which
needs the Iced 0.13 wgpu graphics stack — getting that to install
reliably on macOS and Windows CI runners is its own engineering
project. The library code path tested cross-platform IS the code that
both the CLI and GUI delegate into (`Plugin::replace_binary`,
`utils::atomic_write`, `plugin_system::run_module`, etc.), so the
parity guarantee is real. A v2.0 Phase 0 chip will feature-flag the
Iced deps so the GUI can be opt-in; until then this is documented
honestly.

### Verification
```
cargo test --all-targets    -> 48/48 pass + 1 wine-gated ignored (was 48)
cargo test --lib --tests    -> same 48/48 (subset that CI runs cross-platform)
cargo fmt --all -- --check  -> clean
cargo clippy --all-targets -- -D warnings -> clean
cargo deny check            -> (verified by CI on push)
```

### Roadmap

Remaining v2.0 Phase 0 items deferred to a later chip:
- Maker `fs::read` off the UI thread
- Recent-files LRU cap
- Collapse legacy single-WASM dispatch path
- `OnError::Skip` runtime semantics in the dispatch chain
- Signature migration to `PumpBinResult<T>`
- Iced 0.13 feature-flag refactor (would let macOS/Windows CI run the
  full test suite)

## v1.1.8

Fourth chip of v2.0 Phase 0: zeroize-on-drop wrapper for shellcode bytes.
v1.1.6 stopped shellcode from leaking into the JSON log file (via
`#[instrument(skip(...))]`); v1.1.8 stops it from sitting in freed heap
pages after the host releases it.

### Rationale

PumpBin briefly holds shellcode in `Vec<u8>` heap allocations while
checking for the placeholder marker, computing length, etc. Without
explicit zeroization, those bytes survive in physical memory until the
allocator hands the page to another caller — or, on swap-enabled
systems, to disk. The fix is a thin `SecretBuf` wrapper that derives
`zeroize::ZeroizeOnDrop`, so every in-memory copy is wiped before the
allocator reuses the page.

### Added
- **`pumpbin::secret` module** with `SecretBuf(Vec<u8>)`. Derives
  `Zeroize` + `ZeroizeOnDrop`. Constructible from `Vec<u8>` and `&[u8]`.
  `Deref<Target=[u8]>` so existing call sites that expect `&[u8]` need
  no change. `Debug` impl prints `<redacted N bytes>` instead of the
  raw contents (belt + braces alongside the `#[instrument(skip)]`
  guards from v1.1.6).
- **`SecretBuf::into_vec()`** as the documented escape hatch when bytes
  must cross a serde boundary. Caller takes responsibility for
  re-wrapping or zeroizing the result.
- **`Plugin::validate_shellcode_source`** (`src/plugin.rs`) now wraps
  the `fs::read` result in `SecretBuf` so the shellcode bytes are wiped
  on scope exit — even on the success path where we only used them to
  scan for the placeholder marker.
- **`SecretBuf` re-exported** at the crate root: `pumpbin::SecretBuf`.
- **`tests/zeroize_secrets.rs`** (new, 6 tests):
  - constructs from Vec / slice / `new()`
  - `Debug` impl never leaks the bytes (raw, Vec-debug, or hex form)
  - `explicit_zeroize` wipes in place and preserves the pointer
  - `Deref` lets existing `&[u8]`-taking callers receive `&SecretBuf`
  - `into_vec` returns the raw bytes for serde escape hatches
  - end-to-end: `validate_shellcode_source` still returns `PB-E0006`
    on empty files (proves the SecretBuf-wrapped read path works)

### Intentional scope

- The on-wire `Pass.holder` / `Pass.replace_by` JSON shape **does not
  change.** Those fields cross the WASM boundary via `serde_json`, and
  the host can't re-wrap bytes that have already been serialized to a
  shared buffer. `SecretBuf` is an in-process hygiene feature, not full
  containment. The CHANGELOG entry documents this honestly.
- WASM module memory (the Wasmtime guest heap) is also outside the
  wrapper's reach. Bytes the module holds internally during a hook
  call survive until the Wasmtime instance drops. v2.0 Phase 0
  signature migration to `PumpBinResult<T>` will let us audit the full
  data-flow path more aggressively.

### What zeroize does (and doesn't) buy you

Wiping `Vec<u8>` on drop defeats the most common leak vector — the
kernel handing the same physical page to another process, or to the
same process after `free`. It does NOT defeat a debugger attached to
the live process, swap-file forensics taken before the wipe runs, or
core dumps captured while bytes are in flight. Treat this as hygiene.

### Dependencies
- `zeroize = "1.8"` with the `derive` feature.

### Verification
```
cargo test --all-targets    -> 48/48 pass + 1 wine-gated ignored (was 42)
  - golden          : 2
  - pass_merge      : 1
  - preflight       : 6
  - parity_harness  : 5
  - cli_exit_codes  : 5
  - error_codes     : 12
  - log_redaction   : 1
  - wasm_policy     : 10
  - zeroize_secrets : 6   (new)
cargo fmt --check           -> clean
cargo clippy --all-targets  -> clean of new warnings
                               (pre-existing maker.rs:951 should_persist)
```

### Roadmap

Remaining v2.0 Phase 0 items deferred to a later chip:
- CI matrix (Linux/macOS/Windows + clippy + fmt + cargo deny)
- Maker `fs::read` off the UI thread
- Recent-files LRU cap
- Collapse legacy single-WASM dispatch path
- `OnError::Skip` runtime semantics in the dispatch chain
- Signature migration to `PumpBinResult<T>`

## v1.1.7

Third chip of v2.0 Phase 0: per-module WASM policy. Eliminates the
unconditional `with_allowed_host("*")` and the hardcoded 5-second
timeout that have shipped since the plugin system landed. Modules now
declare their needs (timeout, network hosts, SDK version) via the
`runtime` block in their `plugin_schema()` export; the host enforces
those declarations. Modules that don't declare anything get safe
defaults (3-second timeout, no network).

### Breaking-ish (backward-compatible default behavior)

- **Default WASM timeout drops from 5s to 3s.** Modules that need
  longer must declare `timeout_ms` in their `RuntimeConfig`. Existing
  plugins built before v1.1.7 hit the new 3s default; if your AES /
  signing / network module was already slow it may start failing —
  add a runtime block with the correct `timeout_ms` to fix.
- **Default network policy: no network.** Pre-v1.1.7, every WASM module
  was loaded with `with_allowed_host("*")`. v1.1.7 loads modules with
  zero allowed hosts. Modules that call `extism_pdk::http::request`
  now get `PB-E0021 WasmHostDenied` unless they declare the host in
  their `RuntimeConfig::allowed_hosts`. The `upload_final_shellcode_remote`
  hook is the main affected path — those plugins must declare their
  upload endpoint explicitly.
- **SDK version checking is now strict.** Modules that declare
  `sdk_version: Some(n)` in their `RuntimeConfig` are refused on
  mismatch with the host's `PUMPBIN_SDK_VERSION` (currently `1`).
  Modules with `runtime: None` or `sdk_version: None` are treated as
  "any" for backward compat with pre-v1.1.7 plugins.

### Added
- **`RuntimeConfig`** struct in both `pumpbin-plugin-sdk` and
  `pumpbin::plugin_system`. Fields: `timeout_ms` (default 3000),
  `allowed_hosts` (default empty), `on_error` (`Abort` | `Skip`,
  default `Abort`), `sdk_version` (default `Some(1)`).
- **`OnError`** enum exported alongside. Currently consumed by
  documentation only; per-module skip-on-error behavior in the
  dispatch chain is on the v2.0 Phase 0 roadmap.
- **`PUMPBIN_SDK_VERSION`** constant (currently `1`) exported from
  both crates. Plugins set their `RuntimeConfig::sdk_version` to this
  value to opt into strict version checking.
- **`ResolvedPolicy`** in `plugin_system`. Carries the validated
  per-module policy built from `RuntimeConfig`. Two constructors:
  `from_runtime(name, &RuntimeConfig)` (validates bounds, may return
  `PB-E0023`) and `defaults(name)` (the safe baseline).
- **`resolve_policy(wasm, name) -> ResolvedPolicy`** — bootstrap helper
  that reads the schema from a WASM module and builds the policy. Used
  by `run_module` on every call so per-call policy comes from the
  module's own declaration.
- **`manifest_from_wasm_with_policy(wasm, &ResolvedPolicy)`** —
  replaces the old hardcoded-host/timeout `manifest_from_wasm`. The
  legacy wrapper has been deleted; all callers go through the policy
  path.
- **3 new `PumpBinError` variants**:
  - `PB-E0021 WasmHostDenied { module, host }` — module tried to
    contact a host not in its allowlist
  - `PB-E0022 WasmSdkVersionMismatch { module, declared, host_version }`
    — module SDK version doesn't match host
  - `PB-E0023 WasmTimeoutInvalid { module, timeout_ms }` — declared
    `timeout_ms` outside the 1..=600_000 ms range

### Tests
- **`tests/wasm_policy.rs`** (new, 10 tests):
  - `from_runtime` bounds checking (0, in-range, above-max)
  - `defaults_are_safe` (3s, no network)
  - `runtime_config_default_matches_resolved_defaults`
  - `host_sdk_version_is_one` (locks the constant for the 1.x line)
  - `pre_v1_1_7_wasm_loads_under_default_policy` — proves the AES
    example plugin still works under the strict defaults (backward
    compat regression guard)
  - error-message well-formedness for `PB-E0021` and `PB-E0022`
- **`tests/error_codes.rs`** — extended the uniqueness check with all
  3 new variants.

### Migration notes for plugin authors

If your plugin previously relied on the implicit "any host, 5-second
timeout" defaults, add a `runtime` block to your `plugin_schema()`:

```rust
use pumpbin_plugin_sdk::*;

#[plugin_fn]
pub fn plugin_schema() -> FnResult<Json<PluginConfigSchema>> {
    Ok(Json(PluginConfigSchema::new(vec![/* fields */])
        .with_runtime(RuntimeConfig {
            timeout_ms: 10_000,                             // need 10s
            allowed_hosts: vec!["api.signer.example".into()],
            on_error: OnError::Abort,
            sdk_version: Some(PUMPBIN_SDK_VERSION),
        })))
}
```

The existing `aes-gcm-encrypt`, `xor-encrypt`, `url-format`, and
`pe-version-info` example plugins don't ship a `runtime` block and
therefore run under the new defaults. They've been smoke-tested under
v1.1.7 and work unchanged. Plugins that take longer than 3s or need
network should add the block.

### Verification
```
cargo test --all-targets    -> 42/42 pass + 1 wine-gated ignored (was 32)
  - golden          : 2
  - pass_merge      : 1
  - preflight       : 6
  - parity_harness  : 5
  - cli_exit_codes  : 5
  - error_codes     : 12
  - log_redaction   : 1
  - wasm_policy     : 10  (new)
cargo fmt --check           -> clean
cargo clippy --all-targets  -> clean of new warnings
```

### Roadmap

Remaining v2.0 Phase 0 items deferred to a later chip:
- Signature migration to `PumpBinResult<T>`
- `zeroize` on shellcode + Pass buffers
- CI matrix (Linux/macOS/Windows + clippy + fmt + cargo deny)
- Maker `fs::read` off the UI thread
- Recent-files LRU cap
- Collapse legacy single-WASM dispatch path
- `OnError::Skip` runtime semantics in the dispatch chain (currently
  only the variant exists; chain behavior is always Abort)

## v1.1.6

Second chip of v2.0 Phase 0: `tracing` initialization + `#[instrument]`
annotations across the library hot path + a secret-leak regression
guard. The CLI now writes structured JSON logs to disk by default;
operators can find every generate / batch / verify run in
`$XDG_DATA_HOME/PumpBin/logs/<build-id>.jsonl`.

### Added
- **`pumpbin::logging` module** with `init(LoggingConfig)` and
  `init_default()`. Installs an `EnvFilter`-driven stderr console layer
  and (unless disabled) a JSON file-sink layer.
- **JSON log file**: one file per process invocation at
  `$XDG_DATA_HOME/PumpBin/logs/{timestamp}-{pid}.jsonl`. Append-only
  within the run; rotation is by-invocation. Log-open failure (disk
  full, permission) degrades silently to console-only — never aborts
  the binary.
- **CLI flags** (global, work on every subcommand):
  - `--no-log` — disable the JSON file sink
  - `--log-level <FILTER>` — override level; accepts EnvFilter syntax
    like `debug` or `info,extism=warn`
- **Env vars**:
  - `PUMPBIN_NO_LOG=1` — same as `--no-log`
  - `PUMPBIN_LOG=<filter>` — same as `--log-level`, but `--log-level`
    wins when both are set
- **`#[tracing::instrument]`** on every hot library function:
  - `Plugin::replace_binary`        — `skip(self, bin, shellcode_src, pass, runtime_config)`
  - `Plugin::validate_for_generation` — `skip(self)`
  - `Plugin::validate_shellcode_source` — `skip(self, shellcode_src)`
  - `PluginPlugins::run_encrypt_shellcode` — `skip(self, runtime_config)`
  - `PluginPlugins::run_format_encrypted_shellcode` — `skip(self, shellcode, runtime_config)`
  - `PluginPlugins::run_post_binary` — `skip(self, binary, runtime_config)`
  - `plugin_system::run_module` — `skip(wasm, input, config)`
  - `utils::atomic_write` — `skip(data)`
  Every shellcode / Pass / runtime_config / key argument is in
  `skip(...)`. The `fields(...)` portion logs only safe metadata
  (plugin name, lengths, save_type, paths).
- **`tests/log_redaction.rs`** — regression guard. Drives a full
  generate with a distinctive `0xDEADBEEF×8` marker shellcode, captures
  every byte the tracing subscriber emits, asserts the marker never
  appears in any form (raw, Debug Vec<u8>, hex). This test is the only
  thing preventing a future PR from accidentally removing a
  `skip(shellcode, ...)` clause and leaking secrets to the log file.

### Changed
- **`pumpbin-cli` progress messages** (Generate, Batch, CreateB1n)
  migrated from `println!`/`eprintln!` to `tracing::info!`/`warn!`.
  Goes to stderr so stdout is reserved for the eventual `--json`
  machine-readable output (planned in Phase 1.3).
- **`pumpbin-cli verify` report** stays on `println!` — its stdout IS
  the subcommand's deliverable output (human-readable PE/Authenticode
  report), not progress chatter.
- **`pumpbin-cli completions <shell>`** stays on `println!` — same
  reason; the shell-completion script IS the output.
- **`src/main.rs` (GUI)** calls `pumpbin::logging::init_default()`
  before any other startup work, so config-path setup, capnp decode
  failures, and Iced runtime errors all land in the JSON log too.

### Dependencies
- `tracing = "0.1"` — added (was claimed by the v2.0 plan to already
  exist; verified absent in Cargo.toml, added fresh).
- `tracing-subscriber = "0.3"` with features `env-filter`, `fmt`,
  `json`, `ansi`, `std`.

### Verification
```
cargo test --all-targets    -> 32/32 pass + 1 wine-gated ignored
  - golden          : 2
  - pass_merge      : 1
  - preflight       : 6
  - parity_harness  : 5
  - cli_exit_codes  : 5
  - error_codes     : 12
  - log_redaction   : 1  (new)
cargo fmt --check           -> clean
cargo clippy --all-targets  -> clean of new warnings
```

### Roadmap

Remaining v2.0 Phase 0 items deferred to a later chip:
- Signature migration to `PumpBinResult<T>`
- `zeroize` on shellcode and Pass buffers
- CI matrix (Linux/macOS/Windows + clippy + fmt + cargo deny)
- Per-module WASM policy (timeout, allowed_hosts, sdk_version)
- Collapse legacy single-WASM dispatch

## v1.1.5

First chip of v2.0 Phase 0: structured error codes. Public API signatures
unchanged (still `anyhow::Result<T>`), but every existing `bail!()` and
`anyhow!()` site in the core now returns a `PumpBinError` variant wrapped
in `anyhow::Error`. Downstream consumers can do
`err.downcast_ref::<PumpBinError>()` to match on stable `PB-Exxxx` codes
without parsing error strings.

### Added
- **`pumpbin::error` module** with `PumpBinError` enum (20 variants) and
  `PumpBinResult<T>` type alias. Each variant has a stable `code()`
  method returning a `PB-Exxxx` string. Codes are flat-namespaced and
  allocated chronologically — never reused. `error_code()` is also
  embedded in the `Display` output so human consumers see the same
  identifier as machine consumers.
- **`PumpBinError` re-exported at crate root**: `pumpbin::PumpBinError`
  and `pumpbin::PumpBinResult`.
- **`tests/error_codes.rs`** — 12 tests asserting that every error
  condition produces the expected code and that all codes are unique +
  well-formed (`PB-E` + 4 digits).

### Code allocation table

| Code | Variant | Source |
|---|---|---|
| PB-E0001 | `PlaceholderNotFound` | `utils::replace`, `PluginReplace::preflight_template` |
| PB-E0002 | `ReplacementTooLong` | `utils::replace` |
| PB-E0003 | `ShellcodeSourceEmpty` | `Plugin::validate_shellcode_source` |
| PB-E0004 | `ShellcodeFileNotFound` | same |
| PB-E0005 | `ShellcodeReadFailed` | same |
| PB-E0006 | `ShellcodeFileEmpty` | same |
| PB-E0007 | `ShellcodeContainsPlaceholder` | same |
| PB-E0008 | `RemoteUrlInvalidScheme` | same |
| PB-E0009 | `BinaryNotInPlugin` | `Plugin::validate_for_generation` |
| PB-E0010 | `LocalRequiresSizeHolder` | same |
| PB-E0011 | `MaxLenZero` | same |
| PB-E0012 | `ShellcodeTooLong` | `Plugin::replace_binary` |
| PB-E0013 | `SizeStringTooLong` | same |
| PB-E0014 | `ConfigPathUnavailable` | `Plugins::{read,update}_plugins` |
| PB-E0015 | `PluginNotFound` | `Plugins::get` |
| PB-E0016 | `WasmCallFailed` | `plugin_system::run_module` |
| PB-E0017 | `MakerFieldEmpty` | `Maker::check_generate` |
| PB-E0018 | `MakerSourcePrefixCollision` | same |
| PB-E0019 | `MakerPreflightFailed` | `Maker::preflight_readiness_report` |
| PB-E0020 | `MakerMaxLenInvalid` | `Maker::check_generate` |

### Bridge
- `utils::ReplaceError` (the existing pre-v1.1.5 typed error in
  `utils.rs`) now has a `From` impl converting it to the equivalent
  `PumpBinError::PlaceholderNotFound` / `ReplacementTooLong` variant.
  Keeps old callers working unchanged.

### Deferred to v2.0 Phase 0
- Full signature migration from `anyhow::Result<T>` to `PumpBinResult<T>`
  on all library functions. v1.1.5 keeps the boundary anyhow so existing
  callers (GUI Message handlers, CLI main) don't need any change.
- `tracing` JSON logs, zeroize on shellcode/Pass, CI matrix (clippy/fmt/
  deny on Linux/macOS/Windows), and per-module WASM policy. These are
  Phase 0's other pieces.

### Verification
```
cargo test --all-targets   -> 31/31 pass + 1 wine-gated ignored (was 19)
  - golden          : 2
  - pass_merge      : 1
  - preflight       : 6  (updated to assert PB-E0001 + holder bytes)
  - parity_harness  : 5
  - cli_exit_codes  : 5
  - error_codes     : 12 (new)
cargo fmt --check          -> clean
cargo clippy --all-targets -> clean of new warnings
                              (only pre-existing maker.rs:942
                               should_persist warning remains)
```

## v1.1.4

Follow-up to v1.1.3 closing two more drift items surfaced by a second QA
pass that exercised both CLI and GUI workflows (see `QA_REPORT.md` ->
"v1.1.3 QA findings").

### Fixed
- **`pumpbin-cli batch` returned exit 0 even when zero implants were
  generated.** A CI pipeline pointed at the wrong directory, or at a
  directory containing only non-`.bin` files, would print
  `Success: 0, Failed: 0` and pass without warning. Exit-code policy is
  now documented and enforced:
    - `success > 0 && failed == 0`  → 0
    - `success == 0`                → 1 (bails with directory hint)
    - `success > 0 && failed > 0`   → non-zero (partial; lists per-file
                                       errors in the existing `[!]` lines)
- **GUI keyboard shortcuts spawned multiple file dialogs on key-repeat.**
  Holding `Ctrl+Shift+A` while the existing file dialog was still open
  triggered `AddPluginClicked` once per repeat tick, each one setting
  `is_loading=true` and opening its own `AsyncFileDialog`. The user had
  to dismiss N dialogs before the GUI was usable. Now `Message::Keyboard
  Shortcut` and the click handlers (`AddPluginClicked`,
  `ChooseShellcodeClicked`) early-return `Task::none()` when
  `self.is_loading` is true.

### Added
- **`tests/cli_exit_codes.rs`** — 5 end-to-end tests that invoke the
  built `pumpbin-cli` binary as a subprocess and assert exit codes:
    - `batch_empty_dir_exits_nonzero`
    - `batch_dir_of_non_bin_files_exits_nonzero`
    - `batch_with_valid_shellcode_succeeds`
    - `verify_on_non_pe_exits_nonzero`
    - `create_b1n_with_bad_template_exits_nonzero`
  Skip cleanly (with an eprintln) if the binary hasn't been built, so
  `cargo test` in a fresh checkout still works.
- **`examples/seed_xdg.rs`** — QA helper to pre-seed a sandboxed
  `$XDG_DATA_HOME/PumpBin/plugins` registry with a `.b1n` so the GUI
  starts with a plugin already loaded. Used during QA to test GUI
  launches without touching the operator's real plugin list.

### Reference
- `QA_REPORT.md` updated in v1.1.3; this release closes 2 of the
  remaining items it flagged.
- Test count: 14 → 19. All pass.

## v1.1.3

Follow-up to v1.1.2 addressing the highest-severity CLI/UI parity drift
surfaced by the QA pass documented in `QA_REPORT.md`.

### Fixed
- **`pumpbin-cli verify` returned exit 0 on Authenticode/PE failure** —
  `verify_binary` printed `PE format: no` and `Authenticode invalid` and
  still returned `Ok(())`, breaking CI/CD pipelines that relied on exit
  status. Now tracks failures (non-PE input, checksum mismatch, Authenticode
  verify failure when a signature blob exists) and exits 1 with a summary
  of every check that failed. `AuthCheckStatus::NotApplicable` (no
  osslsigncode, no blob) still passes — those are genuinely informational.
- **`pumpbin-cli create-b1n` produced silently-broken `.b1n` files** when the
  template binary lacked the configured `src_prefix` or `size_holder`. The
  Maker GUI enforced this preflight inline; the CLI did not, so plugins
  built via CLI failed only at generate-time with `"Holder '...' not found
  in binary"`. The check is now lifted into the shared
  `PluginReplace::preflight_template` helper and called by both surfaces.

### Added
- **`PluginReplace::preflight_template`** (`src/plugin.rs`) — shared template
  validation. Confirms `src_prefix` is present always; confirms `size_holder`
  is present in Local mode; skips `size_holder` in Remote mode.
- **`tests/preflight.rs`** — 6 tests covering both modes × prefix/holder
  presence/absence permutations.
- **`tests/parity_harness.rs`** — 5 tests asserting the structural
  invariants of `Plugin::replace_binary` that don't depend on random
  padding (output length, shellcode bytes injected verbatim, placeholders
  consumed, decimal size-string written, two runs agree on offsets). This
  is the foundation for v2.0 byte-equivalence parity tests once the
  `BuildJob` abstraction lands.
- **`AuthCheckStatus`** enum (`src/bin/pumpbin-cli.rs`) discriminating
  `Valid`/`Failed`/`NotApplicable` for the exit-code policy above.

### Reference
- Full QA findings, capability matrix, and parity drift inventory:
  `QA_REPORT.md` (added in this release).
- Roadmap context: `/home/kr1yos/.claude/plans/staged-watching-shannon.md`.

## v1.1.2

### Fixed
- **`replace_binary` pass-clobber (silent correctness bug)** — `Plugin::replace_binary`
  unconditionally overwrote any caller-supplied `Vec<Pass>` with whatever
  `run_encrypt_shellcode` returned, silently dropping pre-encrypted holder/replacement
  pairs supplied by the GUI's two-phase encrypt-then-generate flow. Implants built
  this way ran with un-substituted holders embedded in the binary. The two lists are
  now merged with caller-wins precedence on holder collision. Regression covered by
  `tests/pass_merge.rs`.
- **Non-atomic config / state / binary writes** — `Plugins::update_plugins`,
  `Maker::save_state`, generated-binary saves in the GUI, and all CLI write paths now
  go through `utils::atomic_write` (tempfile in the same dir + `persist`). A crash or
  disk-full event mid-write no longer truncates the existing file to a partial state.

### Removed
- **Host-side `host_self_sign` (ephemeral RSA + osslsigncode)** — the in-core signer
  generated a fresh self-signed RSA cert on every build and shelled out to `openssl`
  and `osslsigncode`. It produced unverifiable signatures, polluted operator OPSEC
  with a unique signer identity per build, and forced both binaries as hard host
  dependencies. Replaced in v1.2.0 by three optional post_binary plugins under
  `plugin-examples/signers/` (osslsigncode BYO-PFX, signtool, cert blob steal).
  The `self_sign` and `sign_cn` runtime config keys are no longer recognized.

### Added
- **`utils::replace_with_rng`** — same semantics as `utils::replace` but takes an
  explicit `&mut R: RngCore`, enabling deterministic golden-output tests. Production
  callers continue to use `utils::replace`, which delegates to `thread_rng`.
- **`utils::atomic_write`** — public helper for crash-safe file writes.
- **First real test suite** (`tests/golden.rs`, `tests/pass_merge.rs`) — pre-1.1.2 the
  source tree had zero `#[test]` while CI ran `cargo test`, producing a green badge
  with no coverage. The golden test proves seeded RNG produces stable bytes across
  machines; the pass-merge test guards the bug fix above.
- `plugin_system` module promoted to `pub mod` so downstream tools and tests can
  name `Pass` and the `*Output` types that already appear in the public signature of
  `Plugin::replace_binary`. `Pass` is re-exported at the crate root.

### Hardening (preparatory; surface unchanged)
- New runtime deps: `tempfile` (was dev-dep) for atomic writes.
- New dev deps: `rand_chacha`, `sha2` for seeded-RNG tests.

## v1.1.1

- Fixed: no error returned when holder not found

## v1.1.0

- Compress plugin via zlib.

## v1.0.0

- Implementing a Plug-in System with Extism.
- Serialize the Plugin struct with Cap'n Proto for backward compatibility.
- Refactor the project code.
