# Execute-QA fixtures

Fixtures for `scripts/qa-execute.sh` and `tests/qa_execute.rs`.

## What's here

| File                    | Purpose                                                                                  |
|-------------------------|------------------------------------------------------------------------------------------|
| `linux_sentinel.asm`    | x86_64 Linux shellcode source: opens a path, writes `PB-QA-OK`, exits cleanly.           |
| `linux_sentinel.bin`    | Assembled blob (158 B). Path is a 64-byte `'X'` placeholder patched at runtime.          |
| `linux_loader.b1n`      | Linux loader plugin pack (zlib-wrapped). Copy of `test/linux_loader_basic.b1n`.          |
| `windows_sentinel.asm`  | x86_64 Windows shellcode source: PEB-walks for kernel32, resolves CreateFileA/WriteFile/CloseHandle/ExitProcess by ROR13 hash, drops sentinel. |
| `windows_sentinel.bin`  | Assembled blob (~540 B). Path is a 128-byte `'X'` placeholder.                           |
| `windows_loader.b1n`    | Windows loader plugin pack, built from `rust-shellcode/create_thread_pumpbin`.           |

## Rebuilding the shellcode

```
nasm -f bin linux_sentinel.asm   -o linux_sentinel.bin
nasm -f bin windows_sentinel.asm -o windows_sentinel.bin
```

## Rebuilding the Windows loader

```
cd <path-to>/rust-shellcode/create_thread_pumpbin
cargo build --release --target x86_64-pc-windows-gnu
pumpbin-cli create-b1n \
    --output  tests/fixtures/qa/windows_loader.b1n \
    --name    pumpbin_qa_winloader \
    --author  pumpbin-qa \
    --template target/x86_64-pc-windows-gnu/release/loader.exe \
    --platform windows --type exe
```

## SSH setup (Windows side)

The harness uses an SSH host alias (`pumpbin-w10` by default). Add to
`~/.ssh/config`:

```
Host pumpbin-w10
    HostName <your-win10-ip>
    User <your-admin-user>
    IdentityFile ~/.ssh/<your-key>
    StrictHostKeyChecking accept-new
    ConnectTimeout 10
```

Override with `--ssh-host` or `PUMPBIN_QA_SSH_HOST=...`.

If the alias isn't reachable, `tests/qa_execute.rs::windows_implant_writes_sentinel`
**skips** (does not fail) so the test suite stays green on dev
machines without a VM. The Windows test only becomes mandatory when
invoked from the pre-push hook on a release-tag push.
