# CHANGELOG

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
