; PumpBin QA execution-sentinel shellcode (x86_64 Windows).
;
; What it does:
;   1. PEB walk -> kernel32 base
;   2. ROR13-hash resolve: CreateFileA, WriteFile, CloseHandle, ExitProcess
;   3. CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
;                  FILE_ATTRIBUTE_NORMAL, NULL)
;   4. WriteFile(h, "PB-QA-OK", 8, &written, NULL)
;   5. CloseHandle(h)
;   6. ExitProcess(0)
;
; Path is embedded as a 128-byte placeholder of 'X' bytes. The
; orchestrator patches the leading bytes with the run-specific path
; (NUL-terminated) before pumpbin stamps it into the loader.
;
; Windows x64 ABI: RCX, RDX, R8, R9 = first 4 args; caller reserves
; 32 bytes shadow space; stack 16-aligned before each CALL.
;
; Assemble:
;   nasm -f bin windows_sentinel.asm -o windows_sentinel.bin

BITS 64
DEFAULT REL

; ROR13 hashes (name only, terminator excluded — matches resolve() loop).
%define HASH_CreateFileA   0x7C0017A5
%define HASH_WriteFile     0xE80A791F
%define HASH_CloseHandle   0x0FFD97FB
%define HASH_ExitProcess   0x73E2D87E

_start:
    ; Standard prologue: align stack to 16, reserve shadow + 5 spill
    ; slots for our resolved function pointers (5*8 = 40 -> 48 with
    ; alignment). Lay it out as:
    ;   [rsp+0..31]  shadow space for callees
    ;   [rsp+32]     hFile      (returned by CreateFileA)
    ;   [rsp+40]     bytes_written (out param for WriteFile)
    ;   [rsp+48..]   resolved fn pointers stack (we'll use registers)
    push    rbp
    mov     rbp, rsp
    and     rsp, -16
    sub     rsp, 0x60

    ; --- PEB -> kernel32 base via InLoadOrderModuleList + name match ---
    ; LDR_DATA_TABLE_ENTRY layout (x64):
    ;   +0x00 InLoadOrderLinks   (LIST_ENTRY: Flink, Blink)
    ;   +0x30 DllBase
    ;   +0x58 BaseDllName        (UNICODE_STRING: Length, MaxLen, Buffer@+8)
    ;   +0x60 BaseDllName.Buffer
    mov     rax, [gs:0x60]              ; PEB
    mov     rax, [rax + 0x18]           ; PEB_LDR_DATA
    lea     rbx, [rax + 0x10]           ; &InLoadOrderModuleList
    mov     rax, [rbx]                  ; first Flink (self exe entry)
.find_k32:
    mov     rax, [rax]                  ; next Flink
    cmp     rax, rbx
    je      .die                        ; wrapped — kernel32 not found
    ; case-insensitive compare of BaseDllName.Buffer to "KERNEL32"
    mov     rsi, [rax + 0x60]           ; ptr to UTF-16 BaseDllName
    ; check 8 chars: K E R N E L 3 2 (case-insensitive by OR 0x20)
    mov     cl, [rsi + 0x00]
    or      cl, 0x20
    cmp     cl, 'k'
    jne     .find_k32
    mov     cl, [rsi + 0x02]
    or      cl, 0x20
    cmp     cl, 'e'
    jne     .find_k32
    mov     cl, [rsi + 0x04]
    or      cl, 0x20
    cmp     cl, 'r'
    jne     .find_k32
    mov     cl, [rsi + 0x06]
    or      cl, 0x20
    cmp     cl, 'n'
    jne     .find_k32
    mov     cl, [rsi + 0x08]
    or      cl, 0x20
    cmp     cl, 'e'
    jne     .find_k32
    mov     cl, [rsi + 0x0A]
    or      cl, 0x20
    cmp     cl, 'l'
    jne     .find_k32
    mov     cl, [rsi + 0x0C]
    cmp     cl, '3'
    jne     .find_k32
    mov     cl, [rsi + 0x0E]
    cmp     cl, '2'
    jne     .find_k32
    mov     rbx, [rax + 0x30]           ; kernel32.DllBase

    ; --- Resolve each export by ROR13 hash ---
    mov     rcx, rbx
    mov     edx, HASH_CreateFileA
    call    resolve
    mov     r12, rax                    ; r12 = CreateFileA

    mov     rcx, rbx
    mov     edx, HASH_WriteFile
    call    resolve
    mov     r13, rax                    ; r13 = WriteFile

    mov     rcx, rbx
    mov     edx, HASH_CloseHandle
    call    resolve
    mov     r14, rax                    ; r14 = CloseHandle

    mov     rcx, rbx
    mov     edx, HASH_ExitProcess
    call    resolve
    mov     r15, rax                    ; r15 = ExitProcess

    ; --- CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
    ;                FILE_ATTRIBUTE_NORMAL, NULL) ---
    lea     rcx, [rel sentinel_path]
    mov     edx, 0x40000000             ; GENERIC_WRITE
    xor     r8, r8                      ; dwShareMode = 0
    xor     r9, r9                      ; lpSecurityAttributes = NULL
    mov     dword [rsp+0x20], 2         ; CREATE_ALWAYS (5th arg)
    mov     dword [rsp+0x28], 0x80      ; FILE_ATTRIBUTE_NORMAL (6th)
    mov     qword [rsp+0x30], 0         ; hTemplateFile = NULL (7th)
    call    r12
    cmp     rax, -1                     ; INVALID_HANDLE_VALUE
    je      .die
    mov     [rsp+0x38], rax             ; save hFile

    ; --- WriteFile(h, "PB-QA-OK", 8, &written, NULL) ---
    mov     rcx, rax
    lea     rdx, [rel sentinel_msg]
    mov     r8d, 8
    lea     r9, [rsp+0x40]              ; &bytes_written
    mov     qword [rsp+0x20], 0         ; lpOverlapped = NULL
    call    r13

    ; --- CloseHandle(h) ---
    mov     rcx, [rsp+0x38]
    call    r14

.die:
    ; --- ExitProcess(0) ---
    xor     rcx, rcx
    call    r15
    ; unreachable

; -----------------------------------------------------------------
; resolve(module_base in rcx, hash in edx) -> rax = export VA
;   Standard PE EAT walk + ROR13 name hash.
;   Clobbers: rax, rcx, rdx, rsi, rdi, r8, r9, r10, r11
; -----------------------------------------------------------------
resolve:
    mov     r8, rcx                     ; r8  = module base
    mov     eax, [r8 + 0x3C]            ; e_lfanew
    add     rax, r8                     ; -> NT headers
    mov     eax, [rax + 0x88]           ; ExportDirectory RVA
    add     rax, r8                     ; -> ExportDirectory
    mov     r9d, [rax + 0x18]           ; NumberOfNames
    mov     r10d, [rax + 0x20]          ; AddressOfNames RVA
    add     r10, r8                     ; -> name RVA table
    mov     r11d, [rax + 0x24]          ; AddressOfNameOrdinals RVA
    add     r11, r8
    mov     eax, [rax + 0x1C]           ; AddressOfFunctions RVA (save)
    push    rax
    xor     ecx, ecx                    ; index
.loop:
    cmp     ecx, r9d
    jae     .notfound
    mov     esi, [r10 + rcx*4]          ; name RVA
    add     rsi, r8                     ; -> name
    ; compute ror13 hash
    xor     edi, edi
.hash_byte:
    movzx   eax, byte [rsi]
    test    al, al
    jz      .hash_done
    ror     edi, 13
    add     edi, eax
    inc     rsi
    jmp     .hash_byte
.hash_done:
    cmp     edi, edx
    je      .match
    inc     ecx
    jmp     .loop
.match:
    movzx   eax, word [r11 + rcx*2]     ; ordinal
    pop     rcx                         ; AddressOfFunctions RVA
    add     rcx, r8                     ; -> EAT
    mov     eax, [rcx + rax*4]          ; export RVA
    add     rax, r8                     ; -> export VA
    ret
.notfound:
    pop     rax
    xor     rax, rax
    ret

sentinel_msg:
    db      "PB-QA-OK"

; 128-byte placeholder (room for "C:\Users\Public\pumpbin_qa_<runid>.txt\0").
sentinel_path:
    times 128 db 'X'
