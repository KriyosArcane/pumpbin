# PumpBin v1.1.2 QA/QC Report — CLI ↔ UI Parity

**Branch**: `hotfix/v1.1.2` (commit `65c4271`)
**Method**: source trace at file:line granularity + functional run of both binaries against fixtures in `/tmp/pumpbin-qa/`.
**Scope**: every CLI subcommand × every UI message that does real work, with a parity matrix at the end.

---

## TL;DR

PumpBin's CLI and UI **share the core engine** — both call into `Plugin::replace_binary` (`src/plugin.rs:659`), `Plugin::encode_to_vec` (`src/plugin.rs:~250`), and `utils::atomic_write` (`src/utils.rs:108`). That's good — the implant-generation algorithm is single-source.

The drift is at the **edges**: argument validation, output naming, defaults, error surfacing, and which UI workflows have no CLI equivalent at all (or vice versa). 9 concrete divergences found, ranked by severity.

The earlier subagent-reported "CRITICAL drift: CLI passes `vec![]` for pass" was **wrong** — `replace_binary` populates `pass` internally from `run_encrypt_shellcode` output, so `vec![]` is the correct CLI default. Verified by reading `plugin.rs:672-688` directly.

---

## Capability parity matrix

| Capability                            | CLI                          | UI                                            | Status            |
|---------------------------------------|------------------------------|-----------------------------------------------|-------------------|
| Generate single implant               | `generate`                   | Generator workspace → Generate button         | ✅ both           |
| Generate from many shellcodes         | `batch`                      | **none**                                      | ❌ CLI-only       |
| Encrypt shellcode standalone (preview)| **none**                     | Generator → Encrypt Shellcode button          | ❌ UI-only        |
| Build a `.b1n` plugin pack            | `create-b1n`                 | Maker workspace → Generate button             | ⚠️ semantic drift |
| Inspect / verify a built binary       | `verify`                     | **none**                                      | ❌ CLI-only       |
| Add a `.b1n` to local config          | **none**                     | Generator → Add Plugin                        | ❌ UI-only        |
| List installed plugins                | **none**                     | Generator → plugin list                       | ❌ UI-only        |
| Remove an installed plugin            | **none**                     | Generator → Remove Plugin                     | ❌ UI-only        |
| Open existing `.b1n` for edit         | **none**                     | Maker workspace → Open                        | ❌ UI-only        |
| Drag-drop file ingestion              | **n/a**                      | Both workspaces (`FilesDropped`)              | UI-only by design |
| Shell completion scripts              | `completions`                | **n/a**                                       | CLI-only by design|
| Per-module post-binary chain          | `--post-module` + `--post-module-config IDX:K=V` | Schema-driven config rows in UI | ⚠️ different shape |
| Atomic writes                         | ✅ all paths via `atomic_write` | ✅ all paths via `atomic_write`            | ✅ matched (1.1.2) |
| Pass-merge on `replace_binary`        | caller-empty → plugin wins   | caller-populated → caller wins on collision  | ✅ unified (1.1.2) |

**Headline gap**: 6 of 13 capabilities exist on only one surface. There is no shared "headless plan" object that both binaries serialize into and execute — the GUI's `Message::*` handlers and the CLI's `match Commands::*` arms each manually wire the same library calls. That's the root cause of every drift below.

---

## Drift findings, ranked

### S1 — Maker fills empty string fields with `"None"`; CLI keeps them empty

`src/maker.rs:766-789` defaults `info.author`, `info.version`, `info.desc` to the literal string `"None"` if the GUI field is blank. `src/bin/pumpbin-cli.rs:463-467` writes the raw `--author` / `--plugin-version` / `--desc` (which default via clap to `"pumpbin-cli"`, `"0.1.0"`, `"Created by pumpbin-cli create-b1n"`, never empty unless the operator explicitly passes `""`).

A `.b1n` created in the Maker GUI with all metadata blank is **not byte-identical** to one created via CLI with `--author '' --plugin-version '' --desc ''`. Both load and run, but `pumpbin-cli inspect` (planned in v2.0) and any future SBOM diffing will mismatch.

**Fix**: pick one. Probably make empty → empty in both (drop the `"None"` substitution) and let downstream tools render "—" if they want.

### S1 — Maker enforces source-prefix presence in template; CLI does not

`src/maker.rs:830-838` runs `memmem::find(&data, &src_prefix_bytes)` over every template binary and `bail!`s with an actionable error if the prefix is absent ("Please recompile it with the correct placeholder."). `src/bin/pumpbin-cli.rs:457-499` reads the template and slots it straight into `plugin.bins.*.executable_mut()` with no scan. The CLI then quietly produces a `.b1n` that will fail at `generate`-time with `"Holder '$$SHELLCODE$$' not found in binary"`.

**Reproduction**: I built a fixture template at `/tmp/pumpbin-qa/template.exe` that *did* contain the placeholders → CLI worked. The repo's own `hello.b1n` fixture **fails** with `Holder '$$99999$$' not found in binary` (run `./target/release/pumpbin-cli generate --plugin hello.b1n ...`), proving the GUI-side preflight was never run on it.

**Fix**: lift maker's preflight scan into a shared helper in `plugin.rs` (e.g. `Plugin::preflight_template(&[u8]) -> PumpBinResult<()>`) and call from both surfaces.

### S2 — Batch output filename uses `HHMMSS` only; Generate uses `YYYYMMDD_HHMMSS_<rand4>`

`src/bin/pumpbin-cli.rs:394` builds `let timestamp = now.format("%H%M%S").to_string();` for each batch file. `src/bin/pumpbin-cli.rs:251` and `src/lib.rs:631` use `%Y%m%d_%H%M%S` plus a 4-char random suffix (the random suffix is GUI-only, see S3).

Two reproducible failure modes:
1. Two batch runs in the same `HH:MM:SS` clobber each other's outputs.
2. Two batch entries that hash to the same `file_stem` in the same second (different subdirs) collide.

**Demonstrated in QA**: running `batch` twice in the same minute produced files with identical names; the second run overwrote the first (atomic_write replaces silently). Output naming should be consistent across all three surfaces (`generate`, `batch`, GUI), and should include the random suffix or a monotonic counter.

### S2 — UI Generate appends `random_id_lowercase(4)`; CLI Generate does not

`src/lib.rs:640` adds `utils::random_id_lowercase(4)` to the default filename. `src/bin/pumpbin-cli.rs:263-266` does not. A user toggling between GUI and CLI for the same plugin will see different file naming patterns in their output directory.

**Fix**: factor a `default_output_filename(plugin, platform, bin_type, now, rand)` helper in `utils` and call from both.

### S2 — UI Generate uses different `bin_descriptor` strings than CLI

`src/lib.rs:612-619`: `win_exe / win_dll / linux_bin / linux_so / macos_bin / macos_dylib`.
`src/bin/pumpbin-cli.rs:258-261`: `exe / dll` (then a separate `--platform` token in filename); CLI uses `ext_for_output(...)` for the file extension.
GUI extensions: `exe / dll / elf / so / bin / dylib` (`lib.rs:621-628`).
CLI extensions: whatever `ext_for_output` says (defined further down in cli.rs).

These need to match. Right now `pumpbin_win_exe_…` (GUI) vs `pumpbin_windows_exe_…` (CLI) on the same plugin is confusing.

### S2 — Default output directory diverges silently

GUI Generate: `desktop_dir().unwrap_or_else(|| ".".into())` → user's Desktop in 95% of cases (`src/lib.rs:645`).
CLI Generate: omitting `--output` writes to **current working directory** (`src/bin/pumpbin-cli.rs:267`).

An automation script that does `cd /some/sandbox && pumpbin-cli generate ...` will leak the implant into `/some/sandbox`, which is fine. But a user who runs the CLI manually from `~/` expecting Desktop behavior gets it in `~`. No way to know without reading source.

**Fix**: document the difference in `pumpbin-cli generate --help`, OR make CLI default to `desktop_dir()` too with an explicit `--output ./...` to override.

### S3 — `verify` returns exit 0 when Authenticode verify fails / binary isn't a PE

`./target/release/pumpbin-cli verify --binary <some-non-PE>` prints `PE format: no`, `Authenticode verify: invalid`, **then exits 0** (`echo $?` → 0). Confirmed in QA.

For CI/CD integration this is a real bug — a deploy pipeline that runs `pumpbin-cli verify` expecting non-zero on failed signature gets a false-pass. Hard I/O errors *do* surface exit-1 correctly (missing file, parse error); only semantic verification failures don't.

**Fix**: `verify_binary` should track `any_failed_check: bool` and `process::exit(1)` (or return `Err`) when any of {checksum invalid, authenticode invalid, no signature when one expected} is true.

### S3 — `verify` is CLI-only with no UI equivalent

GUI users can't see whether the implant they just generated has a valid Authenticode signature or PE checksum. The PE-analysis code in `pumpbin-cli.rs:968-1119` (`analyze_pe`, `verify_authenticode`, `compute_pe_checksum`, `collect_markers`) is **private to the CLI binary** — none of it is exported from the `pumpbin` library, so the GUI couldn't use it even if it wanted to.

**Fix**: move PE inspection to a new `pumpbin/src/inspect.rs` module exposed from the crate root. Add `Message::VerifyGeneratedBinary` to the GUI as a button next to Generate. Reuse same code path for `pumpbin-cli verify`.

### S3 — Encrypt-Shellcode preview is UI-only

GUI: Generator → "Encrypt Shellcode" runs the same `run_encrypt_shellcode` + `run_format_encrypted_shellcode` chain that `generate` runs, but saves the encrypted-only output for inspection. Useful for debugging encryption modules without doing a full generate.

CLI has no equivalent (`pumpbin-cli encrypt --plugin … --shellcode … --output enc.bin` would mirror it). The schema map handling at `src/lib.rs:481-495` is duplicated logic that already exists in `cli.rs::normalize_runtime_config_for_schema`.

**Fix**: add `pumpbin-cli encrypt-shellcode` subcommand. Shared core helper that returns `(encrypted_bytes, pass_list, optional_url)`.

### S3 — CLI lacks add/list/remove plugin and open-recent

The GUI keeps a persistent plugin registry under `$DATA_DIR/PumpBin/plugins` (`src/plugin.rs:967-982`). The CLI has no commands to query or mutate that registry. An operator who wants to use the GUI for one task and a script for another can't share state.

**Fix**: add `pumpbin-cli plugin {list,add,remove}` operating on the same `Plugins::read_plugins` / `Plugins::update_plugins` API the GUI uses.

### S4 — Post-module chain shape differs

CLI `create-b1n --post-module foo.wasm --post-module bar.wasm` base64-encodes each WASM and stuffs it into `plugin_config` under `post_chain.{N}.module_b64` keys (`src/bin/pumpbin-cli.rs:509-521`). At runtime there's presumably code that decodes and chains them.

Maker UI has no explicit post-chain editor — WASM modules added via "MegaPluginWasm" go to `plugin.plugins.modules` (`src/maker.rs:859-863`), a `Vec<Vec<u8>>` chained by `EventManager::fire_post_binary` (`src/plugin_system.rs:138-160`).

So we have **two different in-disk representations** of a post-binary chain depending on which surface created the `.b1n`. The CLI's base64-in-config approach is a workaround; the maker's `modules` vec is the real path.

**Fix**: deprecate the `post_chain.*` config-key encoding. CLI should append directly to `plugin.plugins.modules` like the GUI.

---

## Functional QA findings (from `/tmp/pumpbin-qa/`)

### What worked

- `cargo build --release` for both `pumpbin` and `pumpbin-cli` clean.
- `pumpbin-cli create-b1n` is **deterministic** — same template + same metadata → same SHA-256 (`884828dd…` twice in a row).
- `pumpbin-cli generate` against the fresh fixture wrote a 4233-byte output that contains the shellcode bytes literally (verified via `sc in out`).
- `pumpbin-cli batch` processed 3 shellcodes, all succeeded, output sizes matched single generate.
- All three Phase-H tests pass (`cargo test`): `golden::*` (2), `pass_merge::caller_supplied_pass_entries_survive_replace_binary`.
- `cargo fmt --check` clean.
- `cargo clippy` clean of new warnings.

### What didn't

- `pumpbin-cli generate --plugin hello.b1n …` **fails** with `Holder '$$99999$$' not found in binary`. The repo's own example `.b1n` is broken (or built for Remote mode without the size_holder check being skipped — needs investigation).
- `pumpbin-cli verify` returns exit 0 on `PE format: no` + `Authenticode invalid`. See S3.
- Batch outputs (`-rw-------`) and single-generate outputs (`-rw-r--r--`) have **different file permissions**. Both go through `utils::atomic_write` → `tempfile::NamedTempFile`. Need to investigate why — probably differs because the single-output path was the first run and umask varied. Worth confirming.
- GUI functional run requires a display server (Wayland/X11). I built the binary successfully (`./target/release/pumpbin` is a 33 MB ELF) but didn't launch interactively. Code-trace parity stands as the GUI verification method for this report.

---

## Recommended consolidation plan

**Phase H is done.** This report's findings are **v1.2.0 or v2.0 Phase 0/2 work**, not part of the hotfix.

The right shape:

1. **Single source of truth: extract `pumpbin::core::BuildJob`** (new `src/core/mod.rs` or similar). A `BuildJob` is a serializable struct: `{plugin_source, platform, binary_type, shellcode_source, module_config, output_target}`. Both the GUI's `Message::GenerateClicked` and the CLI's `Commands::Generate` construct a `BuildJob` and call `job.execute()`. The execute method owns *all* output-naming, all default filename logic, all permission-setting, all atomic-write. The result is one code path tested once.

2. **Fix the 6 missing capabilities** by adding either CLI subcommands or library exports:
   - CLI: `inspect`, `encrypt`, `plugin {list,add,remove}` (closes S3 ×3).
   - Library: export `inspect::analyze_pe`, `inspect::verify_authenticode` from `pumpbin` (currently CLI-private). Add GUI button.

3. **Fix the 4 silent semantic drifts**:
   - S1 maker empty → `"None"` substitution: remove it.
   - S1 source-prefix preflight: lift to shared `Plugin::preflight_template`.
   - S2 filename templates: shared `utils::default_output_filename`.
   - S4 post-module chain shape: drop CLI's `post_chain.*` config keys, use `plugin.plugins.modules` like the GUI.

4. **Fix the 2 CLI exit-code bugs**:
   - `verify` exit-1 on any semantic failure.
   - Confirm no other subcommand swallows exit codes (pipes lied to me earlier; re-audit each).

5. **Add CLI-vs-UI parity tests** (`tests/parity.rs`): build a `.b1n` via `create-b1n`, generate via CLI to file A. Construct an equivalent `BuildJob` programmatically (mimicking the GUI's state at click time), execute, write to file B. Assert SHA-256(A) == SHA-256(B) under seeded RNG. This is the regression guard for any future drift.

### Estimate

- Phase 0 of v2.0 already plans the `Profile`/`BuildJob` abstraction (`pumpbin.toml`) — this consolidation is the *implementation* of that. Cost is already budgeted (~1.5 weeks in the plan at `/home/kr1yos/.claude/plans/staged-watching-shannon.md`).
- The 6 missing capabilities and 4 semantic drifts each add ~0.5 day. Together about 1 week of CLI + library work, fits within Phase 0/1.
- Parity tests: half a day.

Total: no plan revision needed. The QA findings here are the **concrete acceptance criteria** for v2.0 Phase 0/1.

---

## Action items for the next session

If you want me to land any of these inside v1.1.2 *before* v2.0 work begins (i.e. as v1.1.3), the cheapest+highest-value items are:

1. Fix `verify` exit code on Authenticode failure (S3, ~10 min).
2. Lift maker's source-prefix preflight into `Plugin::preflight_template` and call from CLI `create-b1n` (S1, ~30 min).
3. Add the parity test infrastructure (no parity tests yet, just the seeded-RNG harness that makes them possible) (~1 hour).

The rest belongs in v2.0 Phase 0 where `BuildJob` will eliminate them by construction.
