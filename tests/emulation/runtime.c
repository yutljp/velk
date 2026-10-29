#ifdef NATIVE
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <signal.h>
#include <unistd.h>
#else
typedef __INTPTR_TYPE__ time_t;
extern int rand(void);
extern void srand(unsigned);
extern time_t time(time_t *);
extern void (*signal(int, void (*)(int)))(int);
extern unsigned alarm(unsigned);
#endif

unsigned random_values(unsigned seed, unsigned count) {
    srand(seed);
    unsigned value = 0;
    for (unsigned i = 0; i < count; ++i) value = value * 33u + (unsigned)rand();
    return value;
}
unsigned random_default(void) { return (unsigned)rand(); }
unsigned random_repeat(unsigned seed) {
    srand(seed);
    unsigned value = (unsigned)rand();
    srand(seed);
    return value == (unsigned)rand();
}
unsigned random_branch(unsigned seed) {
    if (seed != 1) return 0;
    srand(seed);
    if (seed & 1) return (unsigned)rand() == 1804289383u;
    return (unsigned)rand() == 1804289383u;
}
unsigned clock_value(void) {
    time_t stored = 0;
    time_t value = time(&stored);
    return value == stored ? (unsigned)value : 0xffffffffu;
}
time_t clock_pointer(time_t *pointer) { return time(pointer); }
unsigned signal_values(void) {
    unsigned value = signal(14, (void (*)(int))1) == 0;
    value += 2u * (signal(14, (void (*)(int))0) == (void (*)(int))1);
    value += 4u * (signal(14, (void (*)(int))0) == 0);
    return value;
}
unsigned signal_number(unsigned number) { signal((int)number, (void (*)(int))0); return 1; }
unsigned signal_error_handler(void) { signal(14, (void (*)(int))-1); return 1; }
unsigned alarm_values(void) {
    unsigned value = alarm(0) == 0;
    value += 2u * (alarm(30) == 0);
    value += 4u * (alarm(0) == 30);
    return value;
}
#ifdef NATIVE
int main(int argc, char **argv) {
    if (argc != 3) return 1;
    unsigned seed = (unsigned)strtoul(argv[1], 0, 0);
    unsigned count = (unsigned)strtoul(argv[2], 0, 0);
    printf("%u", random_values(seed, count));
    return 0;
}
#endif

#ifndef NATIVE
extern int socket(int, int, int);
extern int prctl(int, ...);
extern int ptrace(int, ...);
extern int getppid(void);
extern char *getenv(const char *);
extern int open(const char *, int, ...);
extern int read(int, void *, unsigned long);
extern int close(int);
extern int IsDebuggerPresent(void);
extern int CheckRemoteDebuggerPresent(void *, int *);
extern long syscall(long, ...);
struct timespec { __INTPTR_TYPE__ tv_sec; __INTPTR_TYPE__ tv_nsec; };
extern int clock_gettime(int, struct timespec *);
unsigned network_socket(void) { return (unsigned)socket(2, 1, 0); }
unsigned process_control(void) { return (unsigned)prctl(38, 1, 0, 0, 0); }
unsigned ptrace_once(void) { return (unsigned)(ptrace(0, 0, 0, 0) == 0); }
unsigned ptrace_twice(void) {
    int first = ptrace(0, 0, 0, 0);
    int second = ptrace(0, 0, 0, 0);
    return (unsigned)(first == 0) + 2u * (unsigned)(second == -1);
}
#if defined(__aarch64__)
#define TEST_SYS_PTRACE 117
#elif defined(__i386__)
#define TEST_SYS_PTRACE 26
#else
#define TEST_SYS_PTRACE 101
#endif
unsigned raw_ptrace_twice(void) {
    long first = syscall(TEST_SYS_PTRACE, 0, 0, 0, 0);
    long second = syscall(TEST_SYS_PTRACE, 0, 0, 0, 0);
    return (unsigned)(first == 0) + 2u * (unsigned)(second == -1);
}
unsigned parent_process(void) { return (unsigned)getppid(); }
unsigned preload_unset(void) { return getenv("LD_PRELOAD") == 0; }
unsigned debugger_apis_clear(void) {
    int present = 1;
    return IsDebuggerPresent() == 0 && CheckRemoteDebuggerPresent(0, &present) != 0 && present == 0;
}
unsigned status_tracer_clear(void) {
    int descriptor = open("/proc/self/status", 0);
    if (descriptor < 0) return 0;
    char bytes[1024];
    int count = read(descriptor, bytes, sizeof(bytes));
    close(descriptor);
    for (int i = 0; i + 13 < count; ++i) {
        if (bytes[i] == 'T' && bytes[i + 1] == 'r' && bytes[i + 2] == 'a' &&
            bytes[i + 3] == 'c' && bytes[i + 4] == 'e' && bytes[i + 5] == 'r' &&
            bytes[i + 6] == 'P' && bytes[i + 7] == 'i' && bytes[i + 8] == 'd' &&
            bytes[i + 9] == ':' && bytes[i + 10] == '\t' && bytes[i + 11] == '0' &&
            bytes[i + 12] == '\n') return 1;
    }
    return 0;
}
unsigned clock_advances(void) {
    struct timespec first, second;
    if (clock_gettime(1, &first) != 0 || clock_gettime(1, &second) != 0) return 0;
    return second.tv_sec > first.tv_sec || second.tv_nsec > first.tv_nsec;
}
static volatile unsigned trap_signal;
static void trap_handler(int signal_number) { trap_signal = (unsigned)signal_number; }
unsigned sigtrap_handler(void) {
#if defined(__x86_64__)
    trap_signal = 0;
    signal(5, trap_handler);
    __asm__ volatile("int3");
    return trap_signal == 5;
#else
    return 0;
#endif
}
#endif
