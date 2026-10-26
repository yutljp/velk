// Symbols supplied by the runtime when linking the ELF metadata fixture.
void *_ZTVN10__cxxabiv117__class_type_infoE[4];
void *_ZTVN10__cxxabiv120__si_class_type_infoE[4];
void *_ZTVN10__cxxabiv121__vmi_class_type_infoE[4];
void *_ZTIi[2];
void __gxx_personality_v0(void) {}
void *__cxa_begin_catch(void *exception) { return exception; }
void __cxa_end_catch(void) {}
void __cxa_call_unexpected(void) { __builtin_trap(); }
void _Unwind_Resume(void) { __builtin_trap(); }
int imported_value(int value) __asm__("_Z14imported_valuei");
int imported_value(int value) { return value; }
