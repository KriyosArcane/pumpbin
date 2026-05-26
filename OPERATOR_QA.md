# Operator QA — junior red-teamer drive-through

> Companion to `QA_REPORT.md` (which tracks code-trace / CLI-vs-UI
> parity). This document captures **friction from the operator's
> seat**: every place a brand-new user trips on the tool while trying
> to ship one Windows implant from a stock msfvenom payload.
>
> Method: fresh shell in `/tmp/op-drive-2026-05-26/`, persona "junior
> red-teamer, has used msfvenom, has not touched PumpBin". Worked
> from README + `--help` only. Time-to-first-implant: ~15 minutes,
> with detours.
>
> Journal: `/tmp/op-drive-2026-05-26/journal.md`.

## Severity legend

- **S1** — Blocker. The tool gives wrong output, lies, or breaks
  documented workflows.
- **S2** — Major friction. The tool works but forces the user to
  guess, hunt, or fight.
- **S3** — Polish. Output is technically correct but confusing or
  noisy.

---

## Findings

### S1 — Blockers

**O-2: The README's quick-start `pumpbin.toml` is invalid TOML.**

The very first copy-paste a new user does fails immediately:

```toml
schema = "pumpbin.profile/v1"
[plugin]    source = "/opt/plugins/stealth-aes.b1n"
[target]    platform = "windows"; binary_type = "exe"
```

TOML doesn't allow `[header]` and keys on the same line, and `;`
isn't a key separator. The build aborts with:

```
TOML parse error at line 2, column 13
  | [plugin]    source = "/opt/plugins/stealth-aes.b1n"
  |             ^
  unexpected key or value, expected newline, `#`
```

**Repro:** copy-paste the README's "Quick start" verbatim, save as
`pumpbin.toml`, run `pumpbin-cli build -f pumpbin.toml`.

**Fix:** rewrite the README example using one-table-per-line TOML.

---

**O-6: Every PumpBin output fails its own `verify` with `PE checksum
mismatch`.**

PumpBin patches the placeholder region in the loader (writes the
shellcode + size into `$$SHELLCODE$$` / `$$99999$$`) but never
recomputes the PE `IMAGE_OPTIONAL_HEADER.CheckSum`. Result: every
stamped EXE carries the original template's checksum, which no longer
matches the new bytes.

This is a **real bug**, not just cosmetic:
- `pumpbin-cli verify` fails on every output (the tool lies to its
  own user — "your build is broken" when it's the verifier that's
  outdated about its own pipeline).
- Stock Windows tools (`certutil -hashfile`, `signtool verify`,
  Defender's static heuristics) treat a stale CheckSum as a strong
  tamper signal. This *increases* detection rate on otherwise clean
  builds.

**Confirmed by hand:**
```
$ python3 -c "..."  # extract IMAGE_OPTIONAL_HEADER64.CheckSum
original loader.exe       CheckSum=0x0014904D
stamped qa_win_implant.exe CheckSum=0x0014904D  # unchanged
verify reports:            calculated=0x00142F06  # actual now
```

**Fix:** after `replace_binary` writes the patched buffer, recompute
the PE checksum (sum 16-bit words mod 2^16, add file size; standard
`CheckSumMappedFile` algorithm) and rewrite it at
`e_lfanew + 24 + 64` for PE32+ or `e_lfanew + 24 + 64` for PE32. Only
applies when `binary_type=exe` AND the input has a valid PE header.

**Auto-fix in scope:** yes — pure file-bytes manipulation, well-
defined algorithm, regression test trivial (build → verify → assert
ok).

---

### S2 — Major friction

**O-1: No "getting started with no plugins" affordance.**

The top-level `pumpbin-cli --help` lists 8 subcommands. Every one
that does real work requires a `.b1n` plugin pack. The CLI offers no
hint of where a new user gets one:

- No `pumpbin-cli init` / `pumpbin-cli examples` / `--list-plugins`.
- The README mentions `plugin-examples/` but those are WASM *modules*
  (encryption, format-conversion, etc.) — not `.b1n` plugin packs.
- The repo's only ready-to-use plugins are `hello.b1n` (broken — see
  QA_REPORT N4), `test/signer.b1n` (signer module, not a loader),
  and the new `tests/fixtures/qa/{linux,windows}_loader.b1n`.

A new user has to grep their disk or read CI fixtures to find a
working starter plugin.

**Fix:** ship `examples/starter-plugins/{linux,windows}.b1n` with a
README explaining they're starter loaders for smoke-testing the
pipeline. Add a `Examples:` section to the top-level `--help`.

**Auto-fix in scope:** yes — copy the QA-harness loaders into
`examples/starter-plugins/`, add a `Need a starter plugin? See
examples/starter-plugins/.` line to the top-level help.

---

**O-3: "Failed to read plugin /path" error gives no next step.**

When the operator points at a missing `.b1n`, they get:

```
Error: Failed to read plugin /opt/plugins/stealth-aes.b1n: No such
file or directory (os error 2)
```

True and useless. A junior op now has to figure out where plugins
live. Same root cause as O-1 (no discoverability).

**Fix:** append a one-liner to the "plugin not found" error pointing
at `examples/starter-plugins/` (after O-1 is fixed).

**Auto-fix in scope:** yes — modify `PumpBinError::FailedToReadPlugin`
to include a suggestion.

---

**O-4: `plugin-examples/` is misnamed for the user perspective.**

A junior op sees `plugin-examples/` and reasonably expects
ready-to-use `.b1n` files. Instead it's source code for WASM
*modules* that live *inside* `.b1n` files (encryption, signers, URL
formatters). True name would be `module-examples/` or
`extism-modules/`.

Renaming would be a breaking change for anyone with build scripts;
the cheaper fix is a one-paragraph README inside `plugin-examples/`
clarifying what's in there and where to find actual `.b1n` files.

**Fix:** add `plugin-examples/README.md` (already exists but doesn't
make this distinction clear) called out at the top.

**Auto-fix in scope:** yes — small doc edit.

---

**O-5: Build succeeds with no warning that the output will be
trivially detected.**

End-to-end test: `pumpbin-cli build` with stock
`create_thread_pumpbin` loader + bare msfvenom
`windows/x64/exec CMD=calc.exe`. Build exits 0. SBOM is clean. Then:

```
$ scp out/implant.exe pumpbin-w10:.../op_drive_calc.exe   # OK
$ ssh pumpbin-w10 ... /op_drive_calc.exe
'C:\Users\Public\op_drive_calc.exe' is not recognized as an internal
or external command, operable program or batch file.
$ ssh pumpbin-w10 dir ... /op_drive_calc.exe
File Not Found            # Defender ate it within seconds
```

PumpBin's README is honest ("does not defeat WinVerifyTrust") but
nothing in the build pipeline says *"you just stamped a raw payload
into a stock loader — this will be quarantined by Defender on first
write."*

A red-team-aware build pipeline should at least warn when:
- No encryption module is in the post-chain
- Shellcode entropy is high (likely raw shellcode, not e.g. a
  PE-loaded payload)
- Loader is one of the "well known" templates (this we can detect by
  matching against a hash list of upstream `rust-shellcode` outputs)

The right behavior isn't to refuse — operators legitimately ship
unencrypted builds for testing — but to **inform** ("warning: no
encryption module configured; output is likely to be flagged").

**Auto-fix in scope:** partial. Adding a "no encryption module +
high-entropy shellcode" warning is one-screen of code. The
loader-hash list is bigger scope.

---

**O-7: `pumpbin-cli create-b1n` default `--max-len 4096` is wrong for
~every real loader.**

```rust
// src/bin/pumpbin-cli.rs:226
#[arg(long, default_value_t = 4096)]
max_len: u64,
```

The user runs `create-b1n` against a template they built with
1 MiB of placeholder padding (the standard `rust-shellcode` pattern).
PumpBin records `max_len: 4096` in the `.b1n`. Now every operator
using this plugin gets rejected:

```
Error: [PB-E0012] Shellcode is 50000 bytes; placeholder slot
accepts at most 4096
```

…even though the loader has 1 MiB of room. The operator has no
visibility into "the plugin author guessed 4096 because they didn't
know to pass --max-len".

**Fix:** auto-detect the placeholder region size during preflight.
We already locate `src_prefix` to validate it exists — extend that
pass to measure the contiguous padding byte (typically `\0` or `'0'`)
that follows. Use the detected size as the default; honor explicit
`--max-len` as an override-only (with a warning if the override is
larger than detected).

**Auto-fix in scope:** yes — `preflight_template` already scans the
binary; adding a "measure padding run" step is ~20 lines.

---

### S3 — Polish

**O-9: `verify <elf>` reports `Authenticode verify failed` alongside
"input is not a valid PE binary".**

```
$ pumpbin-cli verify --binary /tmp/qa_linux_implant
Authenticode verify: invalid (osslsigncode verify failed)
Module markers: none
Error: verify reported 2 failure(s):
  - input is not a valid PE binary
  - Authenticode verify failed: invalid (osslsigncode verify failed)
```

The second error is noise — Authenticode doesn't apply to ELF. Should
short-circuit Authenticode/checksum checks when the input is non-PE
and only report `input is not a valid PE binary`.

**Fix:** in `verify`, detect PE up front (e.g. `MZ` magic + valid
`e_lfanew`); if missing, skip PE-specific checks entirely.

**Auto-fix in scope:** yes — small conditional in the verify path.

---

**O-8: SBOM is genuinely good. (Not a finding — a callout.)**

The `pbom.json` includes plugin sha256, shellcode sha256, builder
identity, version, duration. Useful for IR/blue-team handoff and for
proving provenance after the fact. No fix needed; this is what
"robust" looks like.

---

## Cross-reference to existing QA_REPORT.md

- QA_REPORT N4 already noted the repo's `hello.b1n` is broken
  (deferred to v1.2.0). Still broken in v1.4.6.
- QA_REPORT finding 10 (no CLI `plugin {list,add,remove}`) overlaps
  with O-1 and O-3 — same root cause (no plugin discoverability),
  different surfaces (operator confusion vs missing CLI feature).
- No overlap with the other 11 findings — operator-friction findings
  are largely orthogonal to code-trace/parity findings.

## Triage for auto-fix (next step)

Ranked by value-to-effort:

| # | Finding                            | Auto-fix scope | Touches                      |
|---|------------------------------------|----------------|------------------------------|
| 1 | O-2 README quick-start invalid TOML | trivial        | `README.md`                   |
| 2 | O-9 verify-on-ELF noise            | small          | `src/verify.rs`               |
| 3 | O-3 "plugin not found" hint        | small          | `src/error.rs`                |
| 4 | O-1 starter-plugin discoverability | medium         | `examples/starter-plugins/`, top-level help |
| 5 | O-4 plugin-examples README clarify | small          | `plugin-examples/README.md`   |
| 6 | O-7 `--max-len` auto-detect        | medium         | `src/plugin.rs::preflight_template` |
| 7 | O-6 PE CheckSum recompute          | medium         | `src/plugin.rs::replace_binary` + test |
| 8 | O-5 detection-likelihood warning   | needs design   | gate on user input            |

Items 1-7 are clean candidates for the auto-fix pass. Item 8 needs
your call on what the warning should say and when it fires.
