# PumpBin Modules

A module is a directory with two files: a manifest and an executable. Drop it into the modules directory and PumpBin picks it up on the next run. No source-code changes. No recompile. No registration.

## Module directory

PumpBin scans these paths at startup:

| Path | Notes |
|------|-------|
| `$XDG_CONFIG_HOME/pumpbin/modules/` (Linux) | Default: `~/.config/pumpbin/modules/` |
| `~/Library/Application Support/pumpbin/modules/` (macOS) | |
| `%APPDATA%\pumpbin\modules\` (Windows) | |
| `$PUMPBIN_MODULES_PATH` | Colon-separated override for testing |

First match wins on duplicate IDs. A drop-in cannot shadow a built-in. A bad manifest logs a warning and skips that module. All other modules continue working.

## Module structure

```
my-module/
+-- pumpbin-module.toml
+-- my-module              (or my-module.py, my-module.exe, etc.)
```

### pumpbin-module.toml

```toml
name        = "my-module"
description = "One-line description shown in list-modules"
kind        = "post-build"
version     = "0.1.0"
protocol    = 1
platforms   = ["linux", "windows", "darwin"]
executable  = "my-module"

[[args]]
key         = "threshold"
type        = "string"
required    = true
description = "Minimum match score"

[[args]]
key         = "mode"
type        = "string"
required    = false
default     = "all"
description = "all or first"
```

**Manifest fields:**

| Field | Required | Notes |
|-------|----------|-------|
| `name` | yes | Unique ID. Used in `--post` and `list-modules`. |
| `description` | yes | One line. Shown in `list-modules`. |
| `kind` | yes | `encrypt`, `format-encrypted`, `format-url`, `upload-remote`, or `post-build`. |
| `version` | no | Freeform string. SemVer by convention. |
| `protocol` | no | Defaults to 1. |
| `platforms` | no | `["any"]` for scripts. Omit to default to `["any"]`. |
| `executable` | yes | Filename relative to the manifest directory. |
| `[[args]]` | no | Repeat for each argument your module accepts. |

The executable is never run during discovery. Only the TOML is read.

## Wire protocol v1

PumpBin spawns the executable and communicates over stdin/stdout using length-prefixed frames:

```
frame = [u32 little-endian byte count][payload bytes]
```

**Invocation:**

```
stdin  frame 0: JSON request header
stdin  frame 1: raw input bytes
stdout frame 0: JSON response header
stdout frame 1: raw output bytes
stderr:         free-form text (surfaced to operator on failure)
exit code:      0 = success, non-zero = failure
```

### Request header

```json
{
  "protocol": 1,
  "kind": "post-build",
  "id": "my-module",
  "args": ["threshold=80", "mode=first"]
}
```

`args` is a flat array of `"key=value"` strings. Parse them by splitting on the first `=`:

```python
def parse_args(header):
    args = {}
    for item in header.get("args", []):
        key, sep, val = item.partition("=")
        if sep:
            args[key] = val
    return args
```

Treat unknown keys as errors. Treat missing required keys as errors.

### Response headers

Success:

```json
{ "protocol": 1 }
```

Failure:

```json
{ "protocol": 1, "error": "donor file not found at /tmp/signed.exe" }
```

Set `error` and exit non-zero. Both signals are checked independently.

### Payload contract by kind

| Kind | Input | Output | Extra response fields |
|------|-------|--------|-----------------------|
| `post-build` | implant bytes | mutated implant bytes | none |
| `encrypt` | raw shellcode bytes | encrypted bytes | `pass: [{holder_hex, replace_by_hex}, ...]` |
| `format-encrypted` | encrypted bytes | reshaped bytes | `pass: [...]` |
| `format-url` | URL as UTF-8 | rewritten URL as UTF-8 | `string: "<url>"` |
| `upload-remote` | shellcode bytes | upload URL as UTF-8 | `string: "<url>"` |

For `encrypt` and `format-encrypted`: the `pass` array tells PumpBin which byte sequences to overwrite in the loader template. Both `holder_hex` and `replace_by_hex` are hex-encoded strings.

## Writing a module

### The full contract

```
1. Read 4 bytes  -> u32 LE -> N
2. Read N bytes  -> JSON request header
3. Read 4 bytes  -> u32 LE -> M
4. Read M bytes  -> raw input payload
5. Do your transformation
6. Write [u32 LE][response JSON][u32 LE][output bytes] to stdout
7. Exit 0
```

Any language with stdin/stdout and JSON handles this in around 30 lines.

### Python

See [examples/modules/post-build-python/](examples/modules/post-build-python/) for a complete working template with `parse_args`, `read_frame`, `write_frame`, and error handling.

### Rust

```rust
use pumpbin_module_sdk::{post_build, Result};

fn main() -> Result<()> {
    post_build(|args, implant| {
        // mutate implant bytes here
        Ok(())
    })
}
```

See [examples/modules/post-build-rust/](examples/modules/post-build-rust/) for the full Cargo template.

The SDK is optional. Hand-roll the framing if you prefer zero dependencies.

## Development loop

```bash
# 1. Install your module
mkdir -p ~/.config/pumpbin/modules/my-module
cp my-module pumpbin-module.toml ~/.config/pumpbin/modules/my-module/

# 2. Verify discovery
pumpbin-cli list-modules

# 3. Check arg schema
pumpbin-cli list-modules --options --id my-module

# 4. Test in isolation
pumpbin-cli module-test my-module --input sample.bin --output out.bin

# 5. Debug the wire frames
pumpbin-cli module-test my-module --input sample.bin --output out.bin --debug

# 6. Use in the pipeline
pumpbin-cli generate -p loader.b1n -s sc.bin --post my-module:key=value
```

## Baking a default chain into a .b1n

**Option A: Cargo.toml metadata block (scaffolded loaders)**

```toml
[package.metadata.pumpbin]
name = "myloader"
platform = "windows"

[[package.metadata.pumpbin.post]]
id = "cert-graft"
config = { donor = "/path/to/signed.exe" }

[[package.metadata.pumpbin.post]]
id = "pe-version-info"
config = { from_donor = "/path/to/signed.exe" }
```

`pumpbin-cli pack` reads this and bakes the chain into the `.b1n`. Operators run `generate` with no `--post` flags.

**Option B: create-b1n flags (any loader)**

```bash
pumpbin-cli create-b1n \
    --template loader.exe \
    --output loader.b1n \
    --name myloader \
    --platform windows \
    --type exe \
    --src-prefix '$$SHELLCODE$$' \
    --size-holder '$$99999$$' \
    --post-module cert-graft \
    --post-module-config 0:donor=/path/to/signed.exe
```

Explicit `--post` args on `generate` append to the baked chain. They do not replace it.

## Discovering installed modules

```bash
pumpbin-cli list-modules                       # IDs and descriptions
pumpbin-cli list-modules --options             # includes arg schema
pumpbin-cli list-modules --options --id <id>   # single module
pumpbin-cli list-modules --json                # machine-readable
```

## Trust model

Modules run as subprocesses with the operator's full OS privileges. There is no sandbox.

PumpBin guarantees:

- Never executes a module during discovery.
- Never auto-installs modules from the network.
- Never silently shadows a built-in.

Treat the drop-in directory the same as `~/.local/bin/`. Inspect source or binaries before installing any module you did not write.

## Protocol versioning

`protocol = 1` is current. PumpBin refuses to dispatch to a module declaring a higher version than it speaks.

Additive changes (new optional fields) do not increment the version. Breaking changes go to `protocol = 2`. Old modules stay working on the old dispatch path until the CHANGELOG announces removal.

## Sharing modules

There is no central registry. Publish your module directory as its own git repo with a `README.md` covering install steps, usage, and a safety note. Link to it from your project documentation.
