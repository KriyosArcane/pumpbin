# CHANGELOG

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
