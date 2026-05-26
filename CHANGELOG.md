# CHANGELOG

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
