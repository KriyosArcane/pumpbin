# PumpBin Project Start Here

Read this first at the start of any PumpBin task.

## What This Project Is
- PumpBin is an implant generation platform.
- Researchers create template binaries (`.b1n` plugins).
- Operators inject shellcode/URLs into placeholders to produce final artifacts.

## Core Repositories In This Workspace
- `pumpbin/`: GUI + CLI tooling for generation and plugin handling.
- `plug-in/`: Extism WASM plugin workspace used by PumpBin stages.

## Important PumpBin Concepts
- Save types:
  - `Local`: shellcode bytes embedded in binary.
  - `Remote`: URL embedded, target fetches payload remotely.
- Placeholder model:
  - Source prefix marker, usually `$$SHELLCODE$$`.
  - Size holder marker for Local templates, usually `$$99999$$`.
- Stage model (WASM plugin hooks):
  - `encrypt_shellcode`
  - `format_encrypted_shellcode`
  - `format_url_remote`
  - `upload_final_shellcode_remote`
  - `post_binary`

## Key Files To Know
- `pumpbin/src/plugin.rs`: plugin format, binary replacement, stage execution.
- `pumpbin/src/maker.rs`: Maker workflow for creating `.b1n` plugin files.
- `pumpbin/src/bin/pumpbin-cli.rs`: CLI generation/batch/create-b1n workflows.
- `plug-in/scripts/new-plugin.sh`: plugin scaffolding tool.
- `plug-in/scripts/build-plugin.sh`: plugin build helper.

## Build/Test Quick Commands
- PumpBin CLI check:
  - `cargo check --bin pumpbin-cli`
- PumpBin GUI check:
  - `cargo check --bin pumpbin`
- Create plugin scaffold:
  - `cd /home/kr1yos/Projects/plug-in && ./scripts/new-plugin.sh <type> <name>`
- Build a plugin:
  - `cd /home/kr1yos/Projects/plug-in && ./scripts/build-plugin.sh <type> <name>`

## Working Rules For New Plugins
- Keep exported function name exactly matching stage contract.
- Use deterministic JSON input/output schema per stage contract.
- Keep output binary length unchanged in `post_binary` plugins.
- Document required placeholders in plugin `README.md`.
