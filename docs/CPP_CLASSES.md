# C++ classes and exception tables

Use `velk --classes app.elf` to list classes described by runtime type information (RTTI).
The result is JSON. In JavaScript, `velk.open("app.elf").classes()` returns the same array.
The MCP tool `velk_classes` takes `path` and an optional Mach-O `arch`.
`velk_run_script` can filter or slice a large class list before returning it.

Each class has a `name`, a hexadecimal `typeInfo` address, `bases` and `vtables`.
Each table has its address point (the first method pointer), its subobject byte offset,
and methods in slot order. Method names missing from the binary are `null`.
Secondary tables retain their adjustment thunks as method addresses. In linked images,
RTTI also adds method entry points missing from symbols and unwind tables to function
discovery, with `rtti` as their source and without inventing method names.

Each base records its name, public access and whether inheritance is virtual.
A fixed byte offset is `offset`; an unknown offset is `null`.
For Itanium virtual inheritance, `vtableOffset` is the signed byte displacement of the
virtual-base offset entry from the address point. When primary tables agree on the
entry, `offset` gives the resulting offset in that object layout.
For MSVC virtual inheritance, `vbtable` records the vbptr offset, the vbtable entry's
byte offset and the fixed member displacement. It does not assert a fixed object offset.
MSVC tables also report `constructionDisplacement`, the displacement of a construction-time
vtordisp field; Itanium tables use `null` for that field.

Class recovery supports little-endian 32-bit and 64-bit ELF and Mach-O Itanium descriptors
(`__class_type_info`, `__si_class_type_info`, `__vmi_class_type_info`) and PE MSVC
absolute x86 or image-relative x64 complete object locators and class hierarchies.
Itanium runtime descriptor kinds must be identified by symbols or relocation/binding
names. Mach-O classic binding streams are read; for 64-bit images, chained pointer
fixups are normalized before class recovery. MSVC simple class and namespace names
are decoded; unsupported decorated names are omitted. Unrecognized or malformed
descriptors do not justify an inferred class layout.

Virtual calls with unambiguous table ownership can use class-named C structure views
for 64-bit pointer loads. The views do not model 32-bit object layouts.
Base members occupy their recorded, nonoverlapping offsets. These byte views describe
only pointer-sized prefixes, not the full C++ object's size or data members. Unknown or
unaligned base locations are omitted from the C view. Table stores use class names and
identify object initialization or destruction; a table store alone cannot distinguish a
constructor from a destructor.

Supported scalar parameter bindings restrict virtual-slot candidates to the
parameter's recovered class and its derived classes, including the recorded
base-subobject offsets.
Adjacent table-pointer loads can print as `object->vtable->method(object, ...)`.
Scalar DWARF method declarations can provide member prototypes when all candidates
agree and their ABI bindings are supported. Object-pointer parameters in these
prototypes use `void *`. A signed 32-bit result is converted to its register bits
when the caller reads the full register. Missing or conflicting prototypes keep an indirect call. A member call can use
an unprototyped pointer when only its slot is known; unknown ownership can retain
the raw call.

For example, the linked ELF fixture prints a typed `Multiple_vtable` member:

```sh
velk -D tests/fixtures/cpp/rtti.debug.elf dispatch_multiple
```

Exception tables print comment blocks such as:

```c
/* try { protected code [0x201c33, 0x201c38) }
   catch (Error) { handler L_201c3f; }
   catch (int) { handler L_201c3f; }
   catch (...) { handler L_201c3f; }
   Exception dispatch is described by unwind metadata. */
```

The ranges are machine-code intervals with exclusive ends. Itanium clauses name the
landing pad that dispatches the selector; multiple clauses can share that pad. Cleanup
actions remain separate from catches. Cleanup-only ranges retain their landing-pad annotations. Nested source tries can share a call-site entry,
so the comments preserve the table's ranges and action order rather than inventing source
scopes. Mach-O compact-unwind LSDA indexes and ELF/Mach-O frame LSDA references are read.
Windows x64 `__CxxFrameHandler3` FuncInfo uses the IP-to-state map to recover protected
ranges and typed handler funclets. Compressed `__CxxFrameHandler4` tables remain undecoded.
These comments preserve C syntax and the existing machine-level handler code; standard C
does not provide C++ exception dispatch.

`tests/cases/cpp/rtti.cpp` covers single, multiple and virtual inheritance and typed,
catch-all, nested and cleanup handlers. `bash tests/make_cpp_fixtures.sh` builds ELF with
clang and `ld.lld`, PE with clang's MSVC target and `lld-link` when available, and Mach-O
on macOS. Debug and stripped copies are checked by `tests/cpp_classes.rs` for names,
offsets, exception comments and compilation of every discovered function.

The layouts follow the [Itanium C++ ABI](https://itanium-cxx-abi.github.io/cxx-abi/abi.html),
[LLVM's MSVC RTTI emission](https://github.com/llvm/llvm-project/blob/main/clang/lib/CodeGen/MicrosoftCXXABI.cpp)
and [LLVM's Windows exception emission](https://github.com/llvm/llvm-project/blob/main/llvm/lib/CodeGen/AsmPrinter/WinException.cpp).
