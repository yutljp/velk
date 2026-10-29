"""Check callback extraction against Clang's target type and layout checks."""

from pathlib import Path
import tempfile
import unittest

import generate_type_library as generator


class FunctionPointerFields(unittest.TestCase):
    def test_windows_targets(self):
        source_text = """
#include <initguid.h>
DEFINE_GUID(IID_TypeTest, 0x81234567, 0xabcd, 0xef01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xff);
typedef long HRESULT;
typedef struct Object Object;
union Position { long long value; };
typedef HRESULT (__attribute__((stdcall)) *Query)(Object *, const int *const, void **);
struct Vtable {
    Query QueryInterface;
    unsigned long (__attribute__((stdcall)) *AddRef)(Object *);
    void *(__attribute__((cdecl)) *Allocate)(unsigned int);
    int (__attribute__((cdecl)) *Visit)(Object *, int (*)(const void *, const void *));
    int (__attribute__((cdecl)) *Format)(const char *, ...);
    Query *Queries;
    HRESULT (__attribute__((stdcall)) *Seek)(Object *, union Position);
    int (*Unspecified)();
};
struct Object { struct Vtable *lpVtbl; };
struct __attribute__((packed)) Packed { char tag; Query method; };
int named_parameters(int count, const void *buffer);
"""
        for target, width in [("i686-w64-mingw32", 4), ("x86_64-w64-mingw32", 8)]:
            with self.subTest(target=target), tempfile.TemporaryDirectory() as temp:
                source = Path(temp) / "source.c"
                source.write_text(source_text)
                for name in ["size_t", "ssize_t", "intptr_t", "uintptr_t", "ptrdiff_t"]:
                    generator.SCALARS[name] = width
                generator.SCALARS["long"] = generator.SCALARS["unsigned long"] = 4
                type_library, _ = generator.extract("clang", None, target, source)
                self.assertEqual(
                    type_library["parameter_names"]["named_parameters"],
                    ["count", "buffer"],
                )
                self.assertEqual(type_library["guids"]["IID_TypeTest"], list(bytes.fromhex("67452381cdab01ef23456789abcdefff")))
                fields = type_library["records"]["struct Vtable"]["fields"]
                self.assertEqual([field[1] for field in fields],
                                 ["QueryInterface", "AddRef", "Allocate", "Visit", "Format", "Queries", "Seek"])
                self.assertEqual([field[0] for field in fields], [i * width for i in range(7)])
                self.assertTrue(all(field[3] == width for field in fields))
                self.assertIn("long", fields[0][2])
                self.assertIn("const int *", fields[0][2])
                self.assertIn("void *", fields[2][2])
                self.assertIn("(*)", fields[3][2])
                self.assertIn("...", fields[4][2])
                self.assertIn("(**)", fields[5][2])
                self.assertIn("union Position", fields[6][2])
                self.assertIn("stdcall" if width == 4 else "ms_abi", fields[0][2])
                packed = type_library["records"]["struct Packed"]
                self.assertEqual(packed["size"], width + 1)
                self.assertEqual(packed["fields"], [[0, "tag", "char", 1]])
                generator.verify_target("clang", target, [str(source)], type_library)


if __name__ == "__main__":
    unittest.main()
