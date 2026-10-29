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
struct rlimit { unsigned long rlim_cur; unsigned long rlim_max; };
extern int getrlimit(int, struct rlimit *);
extern int setrlimit(int, const struct rlimit *);
extern char *setlocale(int, const char *);
extern int strcmp(const char *, const char *);
extern unsigned sleep(unsigned);
extern int usleep(unsigned);
extern int nanosleep(const struct timespec *, struct timespec *);
extern int connect(int, const void *, unsigned);
extern int bind(int, const void *, unsigned);
extern int listen(int, int);
extern int accept(int, void *, unsigned *);
extern int send(int, const void *, unsigned long, int);
extern int recv(int, void *, unsigned long, int);
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
unsigned sleep_clock(void) {
    struct timespec first, second;
    if (clock_gettime(1, &first) != 0 || sleep(2) != 0 || clock_gettime(1, &second) != 0) return 0;
    return second.tv_sec >= first.tv_sec + 2;
}
unsigned usleep_clock(void) {
    struct timespec first, second;
    if (clock_gettime(1, &first) != 0 || usleep(10) != 0 || clock_gettime(1, &second) != 0) return 0;
    return second.tv_sec > first.tv_sec || second.tv_nsec >= first.tv_nsec + 10000;
}
unsigned nanosleep_clock(void) {
    struct timespec first, second, request = { 0, 1234567 };
    if (clock_gettime(1, &first) != 0 || nanosleep(&request, 0) != 0 || clock_gettime(1, &second) != 0) return 0;
    return second.tv_sec > first.tv_sec || second.tv_nsec >= first.tv_nsec + request.tv_nsec;
}
extern int *__errno_location(void);
unsigned invalid_sleep_arguments(void) {
    struct timespec request = { 0, 1000000000 };
    *__errno_location() = 0;
    if (usleep(1000000) != -1 || *__errno_location() != 22) return 0;
    *__errno_location() = 0;
    return nanosleep(&request, 0) == -1 && *__errno_location() == 22;
}
unsigned resource_limit_state(void) {
    struct rlimit limit;
    if (getrlimit(0, &limit) != 0) return 0;
    if (limit.rlim_cur != ~0ul || limit.rlim_max != ~0ul) return 0;
    limit.rlim_cur = 1;
    if (setrlimit(0, &limit) != 0 || getrlimit(0, &limit) != 0) return 0;
    return limit.rlim_cur == 1;
}
unsigned invalid_resource_limit(void) {
    struct rlimit limit;
    *__errno_location() = 0;
    if (getrlimit(16, &limit) != -1 || *__errno_location() != 22) return 0;
    if (getrlimit(0, &limit) != 0) return 0;
    limit.rlim_cur = 1;
    limit.rlim_max = 2;
    if (setrlimit(0, &limit) != 0) return 0;
    limit.rlim_max = 3;
    *__errno_location() = 0;
    return setrlimit(0, &limit) == -1 && *__errno_location() == 1;
}
unsigned locale_c(void) {
    char *name = setlocale(6, "C");
    return name != 0 && strcmp(name, "C") == 0;
}
struct sockaddr_test { unsigned short family; unsigned char bytes[14]; };
unsigned network_client(void) {
    int descriptor = socket(2, 1, 0);
    unsigned short address = 2;
    char request[] = "PING", response[4];
    if (descriptor < 0 || connect(descriptor, &address, sizeof(address)) != 0) return 0;
    if (send(descriptor, request, 4, 0) != 4 || recv(descriptor, response, 4, 0) != 4) return 0;
    close(descriptor);
    return response[0] == 'P' && response[1] == 'O' && response[2] == 'N' && response[3] == 'G';
}
unsigned network_server(void) {
    int descriptor = socket(2, 1, 0);
    unsigned short address = 2;
    char response[4];
    if (descriptor < 0 || bind(descriptor, &address, sizeof(address)) != 0 || listen(descriptor, 1) != 0) return 0;
    struct sockaddr_test peer;
    unsigned peer_length = sizeof(peer);
    int client = accept(descriptor, &peer, &peer_length);
    if (client < 0 || recv(client, response, 4, 0) != 4) return 0;
    close(client);
    close(descriptor);
    return response[0] == 'P' && response[1] == 'O' && response[2] == 'N' && response[3] == 'G' &&
           peer.family == 2 && peer_length == sizeof(peer);
}
unsigned network_after_open(void) {
    int file = open("/input", 0);
    int descriptor = socket(2, 1, 0);
    unsigned short address = 2;
    char response[4];
    if (file < 0 || descriptor < 0 || file == descriptor ||
        connect(descriptor, &address, sizeof(address)) != 0 || recv(descriptor, response, 4, 0) != 4)
        return 0;
    close(file);
    close(descriptor);
    return response[0] == 'P' && response[1] == 'O' && response[2] == 'N' && response[3] == 'G';
}
#endif
