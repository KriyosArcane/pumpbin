# PumpBin modules

A module is one folder with two files: a manifest and an executable. Drop it into the right directory, and PumpBin picks it up on the next run. No source-code edits. No recompile. No registration.

This document covers everything you need to write, ship, and run a module in any language.

---

## Where modules live

PumpBin scans these roots in order at every invocation:

| # | Path | Notes |
|---|------|-------|
| 1 | `<install>/modules/` | Reserved for shipped built-ins. Empty by default in v2.0. |
| 2 | `$XDG_CONFIG_HOME/pumpbin/modules/` (Linux) | User drop-in dir. Default: `~/.config/pumpbin/modules/`. |
|   | `~/Library/Application Support/pumpbin/modules/` (macOS) | |
|   | `%APPDATA%\pumpbin\modules\` (Windows) | |
| 3 | `$PUMPBIN_MODULES_PATH` | Colon-separated on Unix, semicolon-separated on Windows. Useful for testing. |

First match wins on duplicate ids. A user drop-in with the same id as a built-in does not shadow it. To replace a built-in, give your module a different id.

A bad manifest logs a warning to stderr and skips that module. The rest keep working.

---

## Anatomy of a module

Every module is a directory with at least two files:

```
<module-id>/
+-- pumpbin-module.toml      # manifest
+-- <executable-or-script>   # the runnable; named in the manifest
```

### pumpbin-module.toml

```toml
name = "strip-timestamps"
description = "Zero PE TimeDateStamp fields"
kind = "post-build"
version = "0.1.0"
protocol = 1
platforms = ["linux", "windows"]
executable = "strip-timestamps"

[[args]]
key = "deep"
type = "bool"
required = false
default = "false"
description = "Also zero export dir timestamps"
```

| Field | Type | Required | Notes |
|-------|------|----------|-------|
| `name` | string | yes | Any non-empty unique identifier. |
| `description` | string | yes | Shown in `list-modules`. |
| `kind` | string | yes | One of: `encrypt`, `format-encrypted`, `format-url`, `upload-remote`, `post-build`. |
| `version` | string | no | Freeform. SemVer by convention. |
| `protocol` | uint | no | Wire protocol version. Currently 1. |
| `platforms` | [string] | no | Use `["any"]` for scripts. Otherwise list `linux`, `windows`, `darwin`. |
| `executable` | string | yes | Filename of the runnable, relative to the manifest directory. |
| `args` | [Arg] | no | Optional arg schema shown in `list-modules --options`. |

The executable is never run during discovery. Only the TOML is parsed.

---

## Wire protocol v1

When an operator references your module, PumpBin spawns the executable and communicates over stdin/stdout using length-prefixed frames:

```
frame = [u32 little-endian length][length bytes of payload]
```

### Invocation

| Stream | Frame 0 | Frame 1 |
|--------|---------|---------|
| stdin  | JSON request header | raw input payload bytes |
| stdout | JSON response header | raw output payload bytes |

Stderr is free-form text. Anything written there surfaces to the operator on failure.

Exit code: `0` is success. Non-zero is failure.

### Request header

```json
{
  "protocol": 1,
  "kind": "post-build",
  "id": "strip-timestamps",
  "args": ["deep=true", "keep_export=false"]
}
```

`args` is always a flat array of `"key=value"` strings, not a dict. To consume it in Python:

```python
def parse_args(header):
    args = {}
    for item in header.get("args", []):
        key, sep, val = item.partition("=")
        if sep:
            args[key] = val
    return args
# args["deep"] == "true", args["keep_export"] == "false"
```

Split each string on the first `=`. Values that contain `=` (e.g. base64) are preserved correctly.

Treat unknown keys as errors. Treat missing required keys as errors.

### Response header (success)

```json
{ "protocol": 1 }
```

### Response header (failure)

```json
{ "protocol": 1, "error": "donor PE not found at /tmp/chrome.exe" }
```

Set `error` and exit non-zero for the clearest failure signal.

### Per-kind payload contract

| Kind | Input (frame 1 in) | Output (frame 1 out) | Response extras |
|------|---------------------|----------------------|-----------------|
| `encrypt` | raw shellcode bytes | encrypted bytes | `pass: [{holder_hex, replace_by_hex}, ...]` |
| `format-encrypted` | encrypted bytes | reshaped bytes | `pass: [...]` (may be empty) |
| `format-url` | URL as UTF-8 | rewritten URL as UTF-8 | `string: "<rewritten URL>"` |
| `upload-remote` | shellcode bytes | URL as UTF-8 | `string: "<upload URL>"` |
| `post-build` | implant binary bytes | mutated implant bytes | (none) |

For `encrypt` and `format-encrypted`: the `pass` array tells PumpBin to find each `holder_hex` byte sequence in the loader template and overwrite it with `replace_by_hex`. Both are hex-encoded so they survive JSON safely.

---

## Writing a module

### The contract in six steps

```
1. Read 4 bytes from stdin -> u32 LE -> N
2. Read N bytes from stdin -> JSON request header
3. Read 4 bytes from stdin -> u32 LE -> M
4. Read M bytes from stdin -> raw payload
5. Compute your transformation
6. Write [u32 LE header length][header JSON][u32 LE output length][output] to stdout. Exit 0.
```

Any language with stdin/stdout and JSON support handles this in around 30 lines.

### Python (40 lines)

See [examples/modules/post-build-python/](examples/modules/post-build-python/).

### Rust (10 lines of your code + pumpbin-module-sdk)

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

The SDK is optional. Rust authors who prefer zero dependencies can hand-roll the framing the same way the Python example does.

### Go, Bash, or anything else

Use the six-step contract above. PumpBin does not care what language a module uses.

---

## Module dev loop

```bash
# 1. Build your module (skip for scripts)
cd my-module && cargo build --release

# 2. Install
mkdir -p ~/.config/pumpbin/modules/my-module
cp target/release/my-module pumpbin-module.toml ~/.config/pumpbin/modules/my-module/

# 3. Verify PumpBin sees it
pumpbin-cli list-modules
#   post_build:
#     my-module (external: ...) - <description>

# 4. See its arg schema
pumpbin-cli list-modules --options --id my-module

# 5. Test in isolation
pumpbin-cli module-test my-module --input /tmp/sample.bin --output /tmp/out.bin

# 6. Use in the pipeline

# Short form: id and args in one flag
pumpbin-cli generate -p loader.b1n -s sc.bin --post my-module:key=value

# Long form (useful for complex args)
pumpbin-cli generate -p loader.b1n -s sc.bin \
    --post my-module --post-arg my-module=key=value
```

### Baking a default chain into a .b1n

Add a `[[package.metadata.pumpbin.post]]` block to your loader crate's `Cargo.toml`. `pumpbin-cli pack` reads it and bakes the chain in:

```toml
[package.metadata.pumpbin]
name = "myloader"
platform = "windows"

[[package.metadata.pumpbin.post]]
id = "cert-graft"
config = { donor = "/tmp/mrt.exe" }

[[package.metadata.pumpbin.post]]
id = "pe-version-info"
config = { from_donor = "/tmp/mrt.exe" }
```

After this, `pumpbin-cli generate -p myloader.b1n -s sc.bin` runs the chain automatically. Explicit `--post` args on `generate` append to the baked chain.

For loaders without a scaffold, use `create-b1n --post-module` instead:

```bash
pumpbin-cli create-b1n \
    --template loader.exe --output loader.b1n \
    --name myloader --platform windows --type exe \
    --src-prefix '$$SHELLCODE$$' --size-holder '$$99999$$' \
    --post-module cert-graft \
    --post-module-config 0:donor=/tmp/mrt.exe
```

---

## Discovering options

```bash
pumpbin-cli list-modules                       # ids and descriptions
pumpbin-cli list-modules --options             # adds per-module arg schema
pumpbin-cli list-modules --options --id <id>   # focus on one module
pumpbin-cli list-modules --json                # machine-readable output
```

Built-ins declare their args via `Module::args() -> Vec<ArgSpec>`. External modules declare them via `[[args]]` blocks in the manifest.

---

## Trust model

Modules run as subprocesses with the operator's full OS privileges. There is no sandbox. A malicious module reads your files, hits the network, and installs persistence the same as any program you run.

PumpBin's guarantees:

- Never executes a module during discovery. Only the TOML is read.
- Never auto-installs modules from the network. You populate the drop-in directory.
- Never silently shadows a built-in. First match wins.

Your responsibilities:

- Treat the drop-in directory like `~/.local/bin/`. Only install modules you trust.
- Inspect the TOML and source or binary before installing.

---

## Protocol stability

`protocol = 1` is the current version. PumpBin refuses to dispatch to a module declaring a higher version than it speaks.

Additive changes (new optional fields) do not bump the version. Breaking changes bump to `protocol = 2`. Old `protocol = 1` modules keep working until explicitly removed. The CHANGELOG announces removal windows in advance.

---

## Sharing your module

There is no central registry yet. The current path:

1. Push your module directory to its own git repo.
2. Add `README.md` with install steps, usage, and safety notes.
3. Add a `LICENSE` file.
4. Link to it from your own project documentation.
