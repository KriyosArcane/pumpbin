# Top 5 Selection and Implementation Map (2026 Q2)

This file maps the judged top 5 ideas to new crate names and paths.
All names are new and do not overwrite existing plugin crates.

## Final Top 5 (New Crate Targets)
1. E03 -> xorstream-keyed-pass-v2
   - Stage: encrypt_shellcode
   - Path: /home/kr1yos/Projects/plug-in/encrypt_shellcode/xorstream-keyed-pass-v2
   - Why: strongest value/reliability blend and straightforward marker pass integration.

2. P03 -> marker-patch-metadata-v2
   - Stage: post_binary
   - Path: /home/kr1yos/Projects/plug-in/post_binary/marker-patch-metadata-v2
   - Why: high operator value for campaign/build tracking with fixed-length safe mutation.

3. F02 -> chunked-hex-array-v2
   - Stage: format_encrypted_shellcode
   - Path: /home/kr1yos/Projects/plug-in/format_encrypted_shellcode/chunked-hex-array-v2
   - Why: practical output format used in real loaders with deterministic rendering.

4. R04 -> url-path-campaign-wrap-v2
   - Stage: format_url_remote
   - Path: /home/kr1yos/Projects/plug-in/format_url_remote/url-path-campaign-wrap-v2
   - Why: campaign-aware URL shaping without brittle parser logic.

5. U06 -> base64-data-url-inline-v2
   - Stage: upload_final_shellcode_remote
   - Path: /home/kr1yos/Projects/plug-in/upload_final_shellcode_remote/base64-data-url-inline-v2
   - Why: removes mandatory external infra dependency while preserving remote mode semantics.

## Delivery Requirements
- Real implementation logic (no TODO-only stubs).
- README per plugin with contracts and examples.
- Build target: wasm32-wasip1.
- Function name must match exact PumpBin stage contract.

## Template Coverage
In addition to top 5, one easy template is provided per stage type for fast start.
