// Imports are declared directly so both 64-bit instruction sets can be tested
// without cross-compiling a standard library.
struct String { unsigned char bytes[32]; };
extern unsigned char gnu_input[] asm("_ZSt3cin");
extern unsigned char gnu_output[] asm("_ZSt4cout");
extern unsigned char llvm_input[] asm("_ZNSt3__13cinE");
extern unsigned char llvm_output[] asm("_ZNSt3__14coutE");
extern unsigned char llvm_ctype_id[] asm("_ZNSt3__15ctypeIcE2idE");
struct Locale {
    void *implementation;
    ~Locale() asm("_ZNSt3__16localeD1Ev");
};
Locale llvm_locale(void *) asm("_ZNKSt3__18ios_base6getlocEv");
extern "C" {
void *llvm_facet(const Locale *, void *) asm("_ZNKSt3__16locale9use_facetERNS0_2idE");
int abi_llvm_locale() {
    Locale locale = llvm_locale(llvm_output);
    void *facet = llvm_facet(&locale, llvm_ctype_id);
    auto table = *static_cast<void ***>(facet);
    auto widen = reinterpret_cast<char (*)(void *, char)>(table[7]);
    auto narrow = reinterpret_cast<char (*)(void *, char, char)>(table[9]);
    for (unsigned int value = 0; value != 256; ++value) {
        char character = static_cast<char>(value);
        if (widen(facet, character) != character || narrow(facet, character, '?') != (value < 128 ? character : '?'))
            return 1;
    }
    return 0;
}
int abi_bad_llvm_facet() {
    Locale locale = llvm_locale(llvm_output);
    llvm_facet(&locale, llvm_ctype_id + 8);
    return 0;
}
void gnu_construct(String *) asm("_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEC1Ev");
void gnu_destroy(String *) asm("_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEED1Ev");
void *gnu_read(void *, String *) asm("_ZStrsIcSt11char_traitsIcESaIcEERSt13basic_istreamIT_T0_ES7_RNSt7__cxx1112basic_stringIS4_S5_T1_EE");
void *gnu_print(void *, const String *) asm("_ZStlsIcSt11char_traitsIcESaIcEERSt13basic_ostreamIT_T0_ES7_RKNSt7__cxx1112basic_stringIS4_S5_T1_EE");
int gnu_compare(const String *, const char *) asm("_ZNKSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE7compareEPKc");
void llvm_construct(String *) asm("_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEC1Ev");
void llvm_destroy(String *) asm("_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEED1Ev");
void *llvm_read(void *, String *) asm("_ZNSt3__1rsIcNS_11char_traitsIcEENS_9allocatorIcEEEERNS_13basic_istreamIT_T0_EES9_RNS_12basic_stringIS6_S7_T1_EE");
void *llvm_line(void *, String *) asm("_ZNSt3__17getlineIcNS_11char_traitsIcEENS_9allocatorIcEEEERNS_13basic_istreamIT_T0_EES9_RNS_12basic_stringIS6_S7_T1_EE");
void *llvm_print(void *, const String *) asm("_ZNSt3__1lsIcNS_11char_traitsIcEENS_9allocatorIcEEEERNS_13basic_ostreamIT_T0_EES9_RKNS_12basic_stringIS6_S7_T1_EE");
int llvm_compare(const String *, const char *) asm("_ZNKSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE7compareEPKc");
int llvm_compare_range(const String *, unsigned long, unsigned long, const char *, unsigned long) asm("_ZNKSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE7compareEmmPKcm");
__attribute__((noinline)) int abi_accepted() { volatile int result = 0; return result; }
int abi_gnu_word() {
    String text;
    gnu_construct(&text);
    gnu_read(gnu_input, &text);
    gnu_print(gnu_output, &text);
    const bool success = gnu_compare(&text, "key") == 0;
    gnu_destroy(&text);
    return success ? abi_accepted() : 1;
}
int abi_llvm_word() {
    String text;
    llvm_construct(&text);
    llvm_read(llvm_input, &text);
    llvm_print(llvm_output, &text);
    const bool success = llvm_compare(&text, "key") == 0;
    llvm_destroy(&text);
    return success ? abi_accepted() : 1;
}
int abi_llvm_line() {
    String text;
    llvm_construct(&text);
    llvm_line(llvm_input, &text);
    llvm_print(llvm_output, &text);
    const bool success = llvm_compare(&text, "a key") == 0;
    llvm_destroy(&text);
    return success ? abi_accepted() : 1;
}
int abi_llvm_compare_range() {
    String text;
    llvm_construct(&text);
    llvm_read(llvm_input, &text);
    int result = llvm_compare_range(&text, 1, 2, "key", 2);
    llvm_destroy(&text);
    return result;
}
}
extern "C" {
int abi_bad_gnu_size() {
    String text{};
    const unsigned long length = ~0UL;
    __builtin_memcpy(text.bytes + 8, &length, sizeof(length));
    gnu_print(gnu_output, &text);
    return 0;
}
int abi_bad_llvm_alternate_size() {
    String text{};
    text.bytes[23] = 23;
    llvm_print(llvm_output, &text);
    return 0;
}
int abi_bad_llvm_size() {
    String text{};
    text.bytes[0] = 46;
    llvm_print(llvm_output, &text);
    return 0;
}
void initialize_ios(void *) asm("_ZNSt8ios_base4InitC1Ev");
void destroy_ios(void *) asm("_ZNSt8ios_base4InitD1Ev");
int register_exit(void (*)(void *), void *, void *) asm("__cxa_atexit");
void cleanup(void *) {}
int abi_startup() {
    unsigned char initialization[8];
    initialize_ios(initialization);
    register_exit(cleanup, nullptr, nullptr);
    destroy_ios(initialization);
    return 0;
}
}
extern "C" {
void *gnu_integer_input(void *, long long *) asm("_ZNSirsERx");
void *gnu_integer_output(void *, long long) asm("_ZNSolsEx");
void *llvm_integer_input(void *, long long *) asm("_ZNSt3__113basic_istreamIcNS_11char_traitsIcEEErsERx");
void *llvm_integer_output(void *, long long) asm("_ZNSt3__113basic_ostreamIcNS_11char_traitsIcEEElsEx");
int abi_gnu_integer() {
    long long value = 0;
    gnu_integer_input(gnu_input, &value);
    gnu_integer_output(gnu_output, value);
    return value == -123 ? abi_accepted() : 1;
}
int abi_llvm_integer() {
    long long value = 0;
    llvm_integer_input(llvm_input, &value);
    llvm_integer_output(llvm_output, value);
    return value == -123 ? abi_accepted() : 1;
}
}
