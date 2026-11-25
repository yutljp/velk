// The code a packed Windows program starts in: it makes the packed part
// writable, restores it, resolves its imports by name and runs it.
#include <stdint.h>

__declspec(dllimport) void *__stdcall LoadLibraryA(const char *name);
__declspec(dllimport) void *__stdcall GetProcAddress(void *module, const char *name);
__declspec(dllimport) int __stdcall VirtualProtect(void *address, uintptr_t size,
                                                   uint32_t protection, uint32_t *previous);

extern unsigned char payload_start[];
extern unsigned char payload_end[];
extern void *payload_imports[];
int original(void);

// Each library, its functions, an empty name; an empty name ends the list.
static const char imports[] = "user32.dll\0MessageBoxA\0GetDesktopWindow\0\0"
                              "kernel32.dll\0GetTickCount\0\0";

int entry(void) {
    uint32_t previous;
    VirtualProtect(payload_start, (uintptr_t)(payload_end - payload_start), 0x40, &previous);
    for (unsigned char *byte = payload_start; byte != payload_end; byte++) {
        *byte ^= 0x5a;
    }
    const char *name = imports;
    void **slot = payload_imports;
    while (*name) {
        void *module = LoadLibraryA(name);
        while (*name++) {
        }
        while (*name) {
            *slot++ = GetProcAddress(module, name);
            while (*name++) {
            }
        }
        name++;
        slot++;
    }
    return original();
}
