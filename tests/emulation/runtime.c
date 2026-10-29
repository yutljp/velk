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
