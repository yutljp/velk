# Windows COM

The Windows header library keeps supported function pointer fields, including their
parameter types, return types, and calling conventions. This includes vtables for
`IUnknown`, `IDispatch`, `IStream`, and other interfaces declared by the included
mingw-w64 headers. Field offsets and widths are specific to x86-32 or x86-64.
Unsupported fields remain padding, including callbacks whose alignment cannot be
represented by a naturally aligned structure.

When an interface type and a supported method signature are available, calls can
print as:

```c
uint32_t com_release(struct IUnknown *object) {
    return object->lpVtbl->Release(object);
}
```

Method printing requires matching arguments and calling conventions, scalar
integer or pointer parameters, and a result whose used bits fit the method's
integer return type of at most 32 bits. A saved vtable is substituted only when
its load immediately precedes the call and has one reader. Other calls retain
their indirect form. Interface types are not inferred from slot numbers alone.
On x86-32, recovery of an otherwise unknown stdcall argument count covers a
single call in a single block with complete integer or pointer debug parameter types.
Other unknown argument counts can prevent decompilation.

Referenced IID and CLSID values are matched against generated header constants.
All sixteen bytes must fit in one file-backed, read-only data section. Results
include every matching name, the GUID text, and the stored bytes. An unrecognized
value gets no GUID annotation. Printed data addresses retain existing names;
otherwise recognized values receive a header name. These names declare byte
arrays with the original address recorded in a comment.

The same data is available through JavaScript, CLI scripts (`velk -r script.js`),
and the MCP `velk_run_script` tool:

```js
const b = velk.open("tests/fixtures/com_x86_64.dll");
({
  vtable: b.libraryType("struct IUnknownVtbl"),
  code: b.getFunction("com_read").decompile(),
  references: b.getFunction("com_unknown_id").references()
});
```

`libraryType()` returns `null` for an unavailable record. A field's `function`
object gives `parameters`, `returnType`, `callingConvention`, and `variadic`.
Each reference has a nullable `guid` object with `names`, `value`, and `bytes`.

Regenerate the fixtures with:

```sh
docker compose run --rm fixtures sh tests/make_com_fixtures.sh
```

The fixtures use `CreateStreamOnHGlobal`, `IUnknown`, `IDispatch`, and `IStream`
for x86-32 and x86-64 PE. Tests compile every discovered function for its Windows
target. Native tests run six method wrappers on 262 inputs at two optimization
levels, with stubs that check arguments, results, and output writes. For those
native runs, 32-bit pointer alignment is adapted to the host's 64-bit layout;
the target compile checks use the exact printed C. GUID tests compare all stored
bytes. These tests do not execute Windows services or Windows PE binaries.

The generator records compiler and header hashes in `windows.json`. Header
license notices are preserved in [windows.LICENSE](../src/analysis/prototypes/windows.LICENSE).
