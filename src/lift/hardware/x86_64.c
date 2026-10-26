/* Runs x86-64 instruction sequences for the lifter's differential test.
 *
 * Standard input holds records of a 32-bit code length, the code, sixteen
 * 64-bit registers in encoding order, the flags, xmm0 to xmm7 as sixteen
 * 64-bit halves, low first, and the upper halves of ymm0 to ymm7 the same
 * way. For each record the code runs from
 * those registers and flags (rsp and r15 excepted, which the harness
 * keeps), and standard output receives the same state after it, then a
 * byte: zero, or the signal the code raised.
 *
 * A length with its top bit set adds the contents of the buffer at
 * BUFFER after the state, which the code may read and write, and the
 * output gives them back after the state too. */

#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

typedef struct {
    uint64_t registers[16];
    uint64_t flags;
    uint64_t vectors[16];
    uint64_t upper[16];
} State;

#ifdef __APPLE__
#define ENTER "_velk_enter"
#else
#define ENTER "velk_enter"
#endif

void velk_enter(State *state, void *code);

__asm__(".intel_syntax noprefix\n"
        ".globl " ENTER "\n" ENTER ":\n"
        "push rbx\npush rbp\npush r12\npush r13\npush r14\npush r15\n"
        "mov r15, rdi\n"
        "push rsi\n"
        "push qword ptr [r15 + 128]\npopfq\n"
        "movdqu xmm0, [r15 + 136]\nmovdqu xmm1, [r15 + 152]\n"
        "movdqu xmm2, [r15 + 168]\nmovdqu xmm3, [r15 + 184]\n"
        "movdqu xmm4, [r15 + 200]\nmovdqu xmm5, [r15 + 216]\n"
        "movdqu xmm6, [r15 + 232]\nmovdqu xmm7, [r15 + 248]\n"
        "vinserti128 ymm0, ymm0, [r15 + 264], 1\nvinserti128 ymm1, ymm1, [r15 + 280], 1\n"
        "vinserti128 ymm2, ymm2, [r15 + 296], 1\nvinserti128 ymm3, ymm3, [r15 + 312], 1\n"
        "vinserti128 ymm4, ymm4, [r15 + 328], 1\nvinserti128 ymm5, ymm5, [r15 + 344], 1\n"
        "vinserti128 ymm6, ymm6, [r15 + 360], 1\nvinserti128 ymm7, ymm7, [r15 + 376], 1\n"
        "mov rax, [r15 + 0]\nmov rcx, [r15 + 8]\nmov rdx, [r15 + 16]\n"
        "mov rbx, [r15 + 24]\nmov rbp, [r15 + 40]\nmov rsi, [r15 + 48]\n"
        "mov rdi, [r15 + 56]\nmov r8, [r15 + 64]\nmov r9, [r15 + 72]\n"
        "mov r10, [r15 + 80]\nmov r11, [r15 + 88]\nmov r12, [r15 + 96]\n"
        "mov r13, [r15 + 104]\nmov r14, [r15 + 112]\n"
        "call qword ptr [rsp]\n"
        "mov [r15 + 0], rax\nmov [r15 + 8], rcx\nmov [r15 + 16], rdx\n"
        "mov [r15 + 24], rbx\nmov [r15 + 40], rbp\nmov [r15 + 48], rsi\n"
        "mov [r15 + 56], rdi\nmov [r15 + 64], r8\nmov [r15 + 72], r9\n"
        "mov [r15 + 80], r10\nmov [r15 + 88], r11\nmov [r15 + 96], r12\n"
        "mov [r15 + 104], r13\nmov [r15 + 112], r14\n"
        "pushfq\npop qword ptr [r15 + 128]\n"
        /* The C ABI requires DF clear, even after a sequence ending in std. */
        "cld\n"
        "movdqu [r15 + 136], xmm0\nmovdqu [r15 + 152], xmm1\n"
        "movdqu [r15 + 168], xmm2\nmovdqu [r15 + 184], xmm3\n"
        "movdqu [r15 + 200], xmm4\nmovdqu [r15 + 216], xmm5\n"
        "movdqu [r15 + 232], xmm6\nmovdqu [r15 + 248], xmm7\n"
        "vextracti128 [r15 + 264], ymm0, 1\nvextracti128 [r15 + 280], ymm1, 1\n"
        "vextracti128 [r15 + 296], ymm2, 1\nvextracti128 [r15 + 312], ymm3, 1\n"
        "vextracti128 [r15 + 328], ymm4, 1\nvextracti128 [r15 + 344], ymm5, 1\n"
        "vextracti128 [r15 + 360], ymm6, 1\nvextracti128 [r15 + 376], ymm7, 1\n"
        "add rsp, 8\n"
        "pop r15\npop r14\npop r13\npop r12\npop rbp\npop rbx\n"
        "ret\n"
        ".att_syntax\n");

#define BUFFER ((unsigned char *)0x600000000000)
#define BUFFER_SIZE 8192
#define WITH_MEMORY 0x80000000u

static sigjmp_buf recovery;

static void on_fault(int signal) { siglongjmp(recovery, signal); }

int main(void) {
    const size_t size = 1 << 16;
    unsigned char *page = mmap(NULL, size, PROT_READ | PROT_WRITE | PROT_EXEC,
                               MAP_PRIVATE | MAP_ANON, -1, 0);
    if (page == MAP_FAILED) {
        perror("mmap");
        return 1;
    }
    if (mmap(BUFFER, BUFFER_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON | MAP_FIXED,
             -1, 0) == MAP_FAILED) {
        perror("mmap buffer");
        return 1;
    }
    int faults[] = {SIGILL, SIGFPE, SIGSEGV, SIGBUS, SIGTRAP};
    for (size_t i = 0; i < sizeof faults / sizeof *faults; i++) {
        struct sigaction action;
        memset(&action, 0, sizeof action);
        action.sa_handler = on_fault;
        sigemptyset(&action.sa_mask);
        sigaction(faults[i], &action, NULL);
    }
    uint32_t length;
    while (fread(&length, sizeof length, 1, stdin) == 1) {
        int memory = (length & WITH_MEMORY) != 0;
        length &= ~WITH_MEMORY;
        State state;
        if (length + 1 > size || fread(page, 1, length, stdin) != length ||
            fread(&state, sizeof state, 1, stdin) != 1 ||
            (memory && fread(BUFFER, 1, BUFFER_SIZE, stdin) != BUFFER_SIZE)) {
            return 1;
        }
        page[length] = 0xc3;
        volatile State result = state;
        unsigned char status = (unsigned char)sigsetjmp(recovery, 1);
        if (status == 0) {
            State running = state;
            velk_enter(&running, page);
            result = running;
        }
        State out = result;
        fwrite(&out, sizeof out, 1, stdout);
        if (memory) {
            fwrite(BUFFER, 1, BUFFER_SIZE, stdout);
        }
        fwrite(&status, 1, 1, stdout);
    }
    return 0;
}
