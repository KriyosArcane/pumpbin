# PumpBin Module Examples

WASM modules that hook into PumpBin's generation pipeline. Each is an independent
Rust crate compiled to `wasm32-wasip1`.

## Build

```bash
# Add the target once
rustup target add wasm32-wasip1

# Build all examples
cd plugin-examples
cargo build --release --target wasm32-wasip1

# WASM files land here:
#   target/wasm32-wasip1/release/aes_gcm_encrypt.wasm
#   target/wasm32-wasip1/release/xor_encrypt.wasm
#   target/wasm32-wasip1/release/url_format.wasm
```

## Examples

### `aes-gcm-encrypt` — AES-256-GCM encryption

Pairs with the `create_thread_encrypt` loader example. On every generation:

1. Generates a fresh random 32-byte AES key and 12-byte nonce.
2. Encrypts the shellcode with AES-256-GCM.
3. Returns `Pass` entries so PumpBin replaces the key/nonce placeholders in the binary.

**Binary template requirements** — the loader must contain:
- `$$KKKKKKKKKKKKKKKKKKKKKKKKKKKK$$` (32 bytes) — AES key placeholder
- `$$NNNNNNNN$$` (12 bytes) — GCM nonce placeholder

**Config fields** (optional):
| Key | Type | Description |
|-----|------|-------------|
| `aad` | text | Hex-encoded additional authenticated data. Leave empty for none. |

---

### `xor-encrypt` — Single/multi-byte XOR

The simplest encryption module — good starting point for learning the SDK.

**Binary template requirements** — the loader must contain:
- `\x00\x00XOR\x00\x00` (7 bytes) — key placeholder

**Config fields** (optional):
| Key | Type | Description |
|-----|------|-------------|
| `xor_key` | number | Key byte 1–255. Random if empty. |
| `multi_byte` | boolean | Use all 7 placeholder bytes as the key. |

---

### `url-format` — URL transformer (remote mode)

Transforms the operator-supplied shellcode URL before it's embedded in the binary.

**Config fields** (optional):
| Key | Type | Description |
|-----|------|-------------|
| `url_prefix` | text | Prepended to the URL. |
| `url_suffix` | text | Appended to the URL. |
| `encoding` | choice | `none` or `base64` — encodes the final URL string. |

---

## Writing your own module

1. Create a new crate with `crate-type = ["cdylib"]`.
2. Add `pumpbin-plugin-sdk = { path = "../../plugin-sdk" }` as a dependency.
3. Export any hooks you need using `#[plugin_fn]`. Unexported hooks are silently skipped.
4. Read runtime config with `pumpbin_config!("key")`.

```rust
use pumpbin_plugin_sdk::*;

// Declare what config fields your module needs (optional)
#[plugin_fn]
pub fn plugin_schema() -> FnResult<Json<PluginConfigSchema>> {
    Ok(Json(PluginConfigSchema::new(vec![
        PluginConfigField::new("my_key", "text")
            .description("A config value shown in the PumpBin UI")
            .required(),
    ])))
}

// Encrypt the shellcode
#[plugin_fn]
pub fn encrypt_shellcode(
    Json(input): Json<EncryptShellcodeInput>,
) -> FnResult<Json<EncryptShellcodeOutput>> {
    let my_key = pumpbin_config!("my_key").unwrap_or_default();

    // ... your logic here ...

    Ok(Json(EncryptShellcodeOutput {
        encrypted: input.shellcode, // replace with actual encrypted bytes
        pass: vec![],               // add Pass entries for key/nonce placeholders
    }))
}
```

### Available hooks

| Hook | Input | Output | Called when |
|------|-------|--------|-------------|
| `plugin_schema` | *(none)* | `PluginConfigSchema` | UI loads schema |
| `encrypt_shellcode` | `EncryptShellcodeInput` | `EncryptShellcodeOutput` | Local mode, before embedding |
| `format_encrypted_shellcode` | `FormatEncryptedShellcodeInput` | `FormatEncryptedShellcodeOutput` | After encryption, before embed |
| `format_url_remote` | `FormatUrlRemoteInput` | `FormatUrlRemoteOutput` | Remote mode |
| `upload_final_shellcode_remote` | `UploadFinalShellcodeRemoteInput` | `UploadFinalShellcodeRemoteOutput` | Remote mode, uploads shellcode |
| `post_binary` | `PostBinaryInput` | `PostBinaryOutput` | After all replacements (all modules run) |

All hooks are optional — implement only the ones you need.
