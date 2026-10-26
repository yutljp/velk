#include <stdint.h>
#include <ptrauth.h>
extern uint64_t signed_return(uint64_t);
extern uint64_t signed_return_a(uint64_t);
extern uint64_t load_a(void *);
extern uint64_t load_b(void *);
extern uint64_t invoke_a(void *, uintptr_t);
extern uint64_t invoke_b(void *, uintptr_t);
static uint64_t answer(void) { return 42; }
int main(void) {
    uint64_t data[3] = {11, 23, 37};
    if (signed_return(10) != 17 || signed_return_a(10) != 19) return 1;
    void *a = ptrauth_sign_unauthenticated(&data[0], ptrauth_key_asda, 0);
    void *b = ptrauth_sign_unauthenticated(&data[1], ptrauth_key_asdb, 0);
    if (load_a(a) != 23 || load_b(b) != 11) return 2;
    void *fn = ptrauth_strip(&answer, ptrauth_key_function_pointer);
    void *fa = ptrauth_sign_unauthenticated(fn, ptrauth_key_asia, 0);
    void *fb = ptrauth_sign_unauthenticated(fn, ptrauth_key_asib, 0);
    if (invoke_a(fa, 0) != 42 || invoke_b(fb, 0) != 42) return 3;
    return 0;
}
