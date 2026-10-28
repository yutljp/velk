unsigned long __stack_chk_guard;

__attribute__((noinline)) int corrupt_guard(void) {
    volatile unsigned char bytes[8];
    bytes[0] = 7;
    __asm__ volatile("" : : "r"(bytes) : "memory");
    __stack_chk_guard ^= 1;
#if defined(__x86_64__)
    __asm__ volatile("xorq $1, %%fs:0x28" ::: "memory", "cc");
#elif defined(__i386__)
    __asm__ volatile("xorl $1, %%gs:0x14" ::: "memory", "cc");
#elif defined(__aarch64__)
    unsigned long *thread;
    __asm__ volatile("mrs %0, tpidr_el0" : "=r"(thread));
    thread[5] ^= 1;
#endif
    return bytes[0];
}
