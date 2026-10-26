// ARM exception entry points needed only for linking metadata fixtures.
void __aeabi_unwind_cpp_pr0(void) { __builtin_trap(); }
void __cxa_end_cleanup(void) { __builtin_trap(); }
