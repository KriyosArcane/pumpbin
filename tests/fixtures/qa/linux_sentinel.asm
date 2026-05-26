; PumpBin QA execution-sentinel shellcode (x86_64 Linux).
;
; What it does:
;   1. open(path, O_WRONLY|O_CREAT|O_TRUNC, 0644)
;   2. write(fd, "PB-QA-OK", 8)
;   3. close(fd)
;   4. exit(0)
;
; The path is embedded as a fixed 64-byte placeholder filled with 'X'.
; The orchestrator script overwrites the first N bytes with the
; run-specific sentinel path (NUL-terminated) before stamping the
; loader. 64 bytes is plenty for "/tmp/pumpbin_qa_<16-hex>\0".
;
; PIC: every label is reached via RIP-relative LEA so the blob is
; position-independent. No data section, no relocations.
;
; Assemble with:
;   nasm -f bin linux_sentinel.asm -o linux_sentinel.bin

BITS 64

_start:
    ; --- open(path, O_WRONLY|O_CREAT|O_TRUNC, 0644) ---
    mov     rax, 2              ; SYS_open
    lea     rdi, [rel sentinel_path]
    mov     rsi, 0o1101         ; O_WRONLY | O_CREAT | O_TRUNC
    mov     rdx, 0o644          ; mode
    syscall
    test    rax, rax
    js      .fail
    mov     r12, rax            ; save fd

    ; --- write(fd, "PB-QA-OK", 8) ---
    mov     rax, 1              ; SYS_write
    mov     rdi, r12
    lea     rsi, [rel sentinel_msg]
    mov     rdx, 8
    syscall

    ; --- close(fd) ---
    mov     rax, 3              ; SYS_close
    mov     rdi, r12
    syscall

    ; --- exit(0) ---
    mov     rax, 60             ; SYS_exit
    xor     rdi, rdi
    syscall

.fail:
    ; exit(1) on open() failure
    mov     rax, 60
    mov     rdi, 1
    syscall

sentinel_msg:
    db      "PB-QA-OK"

; Fixed 64-byte placeholder. Orchestrator patches the leading bytes
; with the run-specific path + NUL terminator. Pattern 'X' chosen so
; an unpatched run fails immediately on open("XXXX...") rather than
; silently writing to some path that happens to exist.
sentinel_path:
    times 64 db 'X'
