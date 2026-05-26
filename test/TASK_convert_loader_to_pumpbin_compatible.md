# Task Playbook: Convert Loader To PumpBin Compatible

## Goal
Convert an existing Rust shellcode loader into a PumpBin-compatible template (`.b1n` generation flow).

## Steps
1. Ensure loader has a shellcode placeholder prefix in compiled binary.
2. For Local type, ensure a numeric size holder placeholder exists.
3. Keep execution logic unchanged; only shellcode source mechanism changes.
4. Compile loader artifacts per platform/type.
5. Create `.b1n` via Maker or CLI `create-b1n`.

## Local Template Checklist
- Prefix marker exists (example: `$$SHELLCODE$$`).
- Size holder exists (example: `$$99999$$`).
- Prefix region has enough max length for expected payload sizes.

## Remote Template Checklist
- URL placeholder exists in template.
- Runtime code correctly handles URL string and fetch flow.
- Max length sized for longest expected URL.

## Validation Commands
- Build loader and confirm marker exists:
  - `rg --text "\$\$SHELLCODE\$\$" <artifact-path>`
- Create plugin with CLI:
  - `pumpbin-cli create-b1n ...`
- Generate output with CLI:
  - `pumpbin-cli generate ...`

## Common Failure Causes
- Marker not present in release binary.
- `size_holder` missing for Local save type.
- Shellcode size exceeds `max_len`.
- Unsupported platform/type selected during generation.
