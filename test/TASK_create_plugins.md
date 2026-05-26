# Task Playbook: Create PumpBin WASM Plugins

## Goal
Create Extism plugins compatible with PumpBin stage contracts.

## Supported Stage Types
- `encrypt_shellcode`
- `format_encrypted_shellcode`
- `format_url_remote`
- `upload_final_shellcode_remote`
- `post_binary`

## Workflow
1. Scaffold plugin:
   - `./scripts/new-plugin.sh <type> <name>`
2. Implement stage function in `src/lib.rs`.
3. Add placeholder expectations and usage notes in `README.md`.
4. Build plugin:
   - `./scripts/build-plugin.sh <type> <name>`
5. Integrate in Maker/CLI and test generation.

## Contract Notes
- Function name must exactly match stage API name.
- Input/output are JSON bytes.
- For `post_binary`, preserve length unless core supports size changes.
- If returning replacement pairs (`pass`) from encryption stage, each placeholder must exist in template binary.

## Quality Checklist
- Clear error messages when input invalid.
- Deterministic output structure.
- Minimal assumptions about template internals.
- README includes required placeholders and build command.
