# Top 5 Plugin Build Plan

Selected plugins to implement now:

1. `encrypt_shellcode/xor32-random-key`
2. `encrypt_shellcode/rc4-key16`
3. `encrypt_shellcode/chunked-xor-keysalt`
4. `post_binary/patch-build-tag`
5. `post_binary/patch-campaign-id`

## Placeholder Contracts
- `xor32-random-key`:
  - `$$XOR32_KEY_BLOB_32_BYTES_MARKER!$$`
- `rc4-key16`:
  - `$$RC4_KEY_MARKER_16$$`
- `chunked-xor-keysalt`:
  - `$$CKEY16_MARKER____$$`
  - `$$CSALT8$` (8-byte marker for salt)
- `patch-build-tag`:
  - `$$BUILD_TAG$$`
- `patch-campaign-id`:
  - `$$CMPGNID$$`

## Validation
- Build each plugin with `./scripts/build-plugin.sh <type> <name>`.
- Verify wasm output exists in workspace target.
- Keep post-binary output same length.
