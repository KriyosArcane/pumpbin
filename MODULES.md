# PumpBin modules

PumpBin discovers external (third-party) modules by scanning two
directories at startup. **A new module is one folder with two
files: a manifest and an executable.** No source-code edit. No
recompile. No registration.

This document covers everything you need to write, ship, and run a
module in any language.

---

## Where modules live

PumpBin scans these roots in order at every invocation:

| # | Path | Notes |
|---|------|-------|
| 1 | `<install>/modules/` | Built-ins shipped with PumpBin. Empty by default in v2.0. |
| 2 | `$XDG_CONFIG_HOME/pumpbin/modules/` (Linux) | The user drop-in dir. Default `~/.config/pumpbin/modules/`. |
|   | `~/Library/Application Support/pumpbin/modules/` (macOS) | |
|   | `%APPDATA%\pumpbin\modules\` (Windows) | |
| 3 | `$PUMPBIN_MODULES_PATH` | Colon-separated (`:` unix, `;` windows). Override for testing. |

**First match wins** on duplicate ids — built-ins can't be silently
shadowed by a user drop-in (security: a malicious folder can't
hijack `aes-gcm`). To replace a built-in, give your module a
different id.

A bad manifest **logs a warning to stderr and skips that module**;
the rest keep working. Same shape as NetExec's `module_is_sane`.

---

## Anatomy of a module

Every module is a directory containing **at least two files**:

```
<module-id>/
├── pumpbin-module.toml      # manifest
└── <executable-or-script>   # runnable; manifest's `executable` field
```

### `pumpbin-module.toml`

```toml
name = "strip-timestamps"                    # required, unique id
description = "Zero PE TimeDateStamp fields" # required, one-line
kind = "post-build"                          # required: see "Kinds"
version = "0.1.0"                            # optional, freeform
protocol = 1                                 # optional, defaults to 1
platforms = ["linux", "windows"]             # optional, defaults to ["any"]
executable = "strip-timestamps"              # required, relative to this dir

[[args]]                                     # optional, repeat per arg
key = "deep"
type = "bool"
required = false
default = "false"
description = "Also zero export dir timestamps"
```

| Field | Type | Required | Notes |
|-------|------|----------|-------|
| `name` | string | yes | snake/kebab/camel — any non-empty unique identifier |
| `description` | string | yes | shown in `list-modules` |
| `kind` | string | yes | one of `encrypt`, `format-encrypted`, `format-url`, `upload-remote`, `post-build` |
| `version` | string | no | freeform; convention is SemVer |
| `protocol` | uint  | no | wire protocol version this module speaks. Currently 1 |
| `platforms` | [string] | no | `["any"]` if script; otherwise list of `linux`/`windows`/`darwin` |
| `executable` | string | yes | filename of the runnable, relative to manifest dir |
| `args` | [Arg] | no | optional arg schema (informational only in v2.0) |

The executable is **never run during discovery** — only the TOML is
parsed. Safe to scan untrusted-looking folders.

---

## Wire protocol v1

When the operator references your module, PumpBin spawns the
executable and speaks the same simple framing on both sides:

```
length-prefixed frame  =  [u32 little-endian length] [length bytes of payload]
```

### Invocation

| Stream | Frame 0 | Frame 1 |
|--------|---------|---------|
| stdin  | JSON request header | raw input payload bytes |
| stdout | JSON response header | raw output payload bytes |

stderr is **free-form text** — anything you log there surfaces to
the operator on failure. Use it.

Exit code: `0` = success; non-zero = failure.

### Request header

```json
{
  "protocol": 1,
  "kind": "post-build",
  "id": "strip-timestamps",
  "args": ["deep=true", "keep_export=false"]
}
```

If `args` is set, each entry is a free-form `key=value` string the
operator passed via `--post-arg`. Modules SHOULD treat unknown keys
as errors and missing required keys as errors.

### Response header (success)

```json
{ "protocol": 1 }
```

### Response header (failure)

```json
{ "protocol": 1, "error": "donor PE not found at /tmp/chrome.exe" }
```

The host treats `error.is_some()` as failure even if the exit code
is 0. Conversely a non-zero exit is failure even with `error: null`.
Set `error` AND exit non-zero for clearest signaling.

### Per-kind payload contract

| Kind | Input payload (frame 1 in) | Output payload (frame 1 out) | Response header extras |
|------|---------------------------|------------------------------|------------------------|
| `encrypt` | raw shellcode bytes | encrypted bytes | `pass: [{holder_hex, replace_by_hex}, ...]` |
| `format-encrypted` | encrypted bytes | reshaped bytes | `pass: [...]` (may be empty) |
| `format-url` | URL as UTF-8 | rewritten URL as UTF-8 | `string: "<rewritten URL>"` (also echoed in payload) |
| `upload-remote` | shellcode bytes | URL as UTF-8 | `string: "<upload URL>"` |
| `post-build` | implant binary bytes | mutated implant bytes | (none) |

For `encrypt` and `format-encrypted`: the `pass` array tells PumpBin
to find each `holder_hex` byte sequence in the loader template and
overwrite it with `replace_by_hex`. Hex-encoded for JSON safety
(arbitrary bytes including NUL, which JSON strings can't carry).

---

## Writing a module in any language

### Pseudocode (the whole contract in 6 steps)

```
1. Read 4 bytes from stdin → u32 LE → N
2. Read N bytes from stdin → JSON request header
3. Read 4 bytes from stdin → u32 LE → M
4. Read M bytes from stdin → raw payload
5. Compute your transformation
6. Write [u32 LE length of header JSON][header JSON][u32 LE length of output][output]
   to stdout. Exit 0.
```

That's the whole contract. Any language with stdin/stdout and JSON
support can implement it in ~30 LOC.

### Python (40 LOC)

See [examples/modules/post-build-python/](examples/modules/post-build-python/).

### Rust (~10 LOC of your code + `pumpbin-module-sdk`)

```rust
use pumpbin_module_sdk::{post_build, Result};

fn main() -> Result<()> {
    post_build(|args, implant| {
        // your mutation here
        implant.push(0xAA);
        Ok(())
    })
}
```

See [examples/modules/post-build-rust/](examples/modules/post-build-rust/) for the full template.

The SDK is optional — Rust authors who want zero deps can hand-roll
the framing the same way the Python example does.

### Go, Bash, anything-else

Use the pseudocode contract above. PumpBin doesn't care what
language a module is in; it only cares that the executable runs and
speaks the wire protocol.

---

## Module dev loop

```
# 1. Build your module (skip if it's already a script)
cd my-module && cargo build --release

# 2. Install
mkdir -p ~/.config/pumpbin/modules/my-module
cp target/release/my-module pumpbin-module.toml ~/.config/pumpbin/modules/my-module/

# 3. PumpBin sees it
pumpbin-cli list-modules
#   post_build:
#     my-module (external: ~/.config/pumpbin/modules/my-module/pumpbin-module.toml) - <description>

# 4. See its full arg schema (declared in pumpbin-module.toml `[[args]]`)
pumpbin-cli list-modules --options --id my-module
#   post_build:
#     my-module (external: ...) - ...
#       marker: hex-byte [default: 0xAA]
#           Byte to append to the implant.

# 5. Test in isolation (no implant needed)
echo "hello world" > /tmp/in
pumpbin-cli module-test my-module --input /tmp/in --output /tmp/out
#   module 'my-module' applied. /tmp/out has the result.

# 6. Use in the full pipeline
pumpbin-cli generate -p loader.b1n -s sc.bin --platform linux -t exe \
    -o implant --post my-module --post-arg my-module=key=value
```

## Discovering options

Mirrors NetExec's `--options` flag:

```
pumpbin-cli list-modules                          # ids + descriptions only
pumpbin-cli list-modules --options                # adds per-module arg schema
pumpbin-cli list-modules --options --id <id>      # focus on one module
```

Modules surface their args from two sources:

- **Built-ins**: declared via `Module::args() -> Vec<ArgSpec>` in the
  trait impl. See `pumpbin/src/modules/post_build/pe_version_info.rs`
  for an 8-arg example or `cert_blob_steal.rs` for a single
  required-arg example.
- **External (drop-in)**: declared via `[[args]]` blocks in
  `pumpbin-module.toml`. Each block has `key`, `type`, optional
  `description`, optional `required`, optional `default`. Add as
  many `[[args]]` blocks as your module accepts.

Modules with no `args()` (or no `[[args]]`) print
`(no documented args)` under `--options`.

---

## Trust model — read this

Modules run as **subprocesses with the operator's full OS
privileges**. There is no sandbox. A malicious module can read your
files, hit the network, install persistence — same as any program
you run from `bash`.

PumpBin's guarantees:

- **Never executes** a module during discovery (only the TOML is read).
- **Never auto-installs** modules from the network. The drop-in dir
  is something *you* populate.
- **Never silently shadows** a built-in (first match wins).

Your job:

- **Treat the drop-in dir like `~/.local/bin/`.** Only drop in
  modules you trust the same way you'd trust any script you run.
- **Inspect TOML + source/binary** before installing. The wire
  protocol gives modules arbitrary I/O.

---

## Protocol stability and versioning

`protocol = 1` is the current contract. PumpBin will refuse to
dispatch to a module declaring a higher protocol than it speaks
(forward compat: old hosts don't run new modules).

When the protocol changes (rare):

- Additive changes (new optional fields) don't bump the version.
- Breaking changes bump to `protocol = 2`. Old `protocol = 1`
  modules keep working — pumpbin maintains the dispatch path.
- Eventually-old protocol versions get removed; PumpBin's
  CHANGELOG announces the window.

If your module pins `protocol = 1` and pumpbin v3.0 drops support,
you'll get a clear error at discovery time. No silent breakage.

---

## Sharing your module

There is **no central registry** yet (premature for the ecosystem
size). Today the path is:

1. Push your module's directory to its own git repo.
2. Add `README.md` with install + usage + safety notes.
3. Add `LICENSE`.
4. List it in your own project README; eventually we'll maintain
   a community "modules in the wild" page that links to repos.

Don't ship signed binaries (we don't verify signatures yet — see
trust model). Operators install at their own risk; clear docs
matter more than crypto.
