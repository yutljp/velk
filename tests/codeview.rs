mod common;

use std::process::Command;
use velk::service::Binary;

#[test]
fn printed_codeview_names_and_types_compile_and_compute_source_results() {
    let scratch = common::root().join("target/codeview-compile");
    std::fs::create_dir_all(&scratch).expect("scratch directory");
    for extension in ["obj", "dll"] {
        for level in [0, 2] {
            for (source, name, expected, driver) in [
                (
                    "loops",
                    "count_bits",
                    "uint32_t x",
                    "for (unsigned x=0; x<1000; ++x) { unsigned n=0; for(unsigned y=x;y;y>>=1) n+=y&1; if(count_bits(x)!=(int)n) return 1; }",
                ),
                (
                    "loops",
                    "sum_until",
                    "int32_t limit",
                    "for(int n=0;n<100;++n) if(sum_until(n)!=n*(n+1)/2) return 2;",
                ),
                (
                    "l4_memory",
                    "point_dot",
                    "struct point *a",
                    "for(int i=-10;i<10;++i) { struct point a={i,3},b={4,-i}; if(point_dot(&a,&b)!=i) return 3; }",
                ),
                (
                    "l4_memory",
                    "array_sum",
                    "int32_t *a",
                    "int a[]={-3,5,7,-9}; for(int n=0;n<5;++n) {int s=0;for(int i=0;i<n;++i)s+=a[i];if(array_sum(a,n)!=s)return 4;}",
                ),
                (
                    "structs",
                    "rect_area",
                    "struct rect *r",
                    "struct rect r={{-3,2},{7,6}};if(rect_area(&r)!=40)return 5;",
                ),
                (
                    "structs",
                    "point_add",
                    "struct point a",
                    "for(int i=-10;i<10;++i) {struct point a={i,3},b={4,-i};struct point c=point_add(a,b);if(c.x!=i+4||c.y!=3-i)return 6;}",
                ),
                (
                    "loops",
                    "sum_till_neg",
                    "int32_t *p",
                    "int p[]={3,5,-2,7}; if(sum_till_neg(p,4)!=8)return 7;",
                ),
                (
                    "loops",
                    "sum_until_zero",
                    "int32_t *p",
                    "int p[]={3,-2,5,0,7}; if(sum_until_zero(p,5)!=8)return 8;",
                ),
                (
                    "structs",
                    "record_total",
                    "struct record *items",
                    "struct record r[9]={0};for(int i=0;i<9;++i){r[i].value=i-5;r[i].count=i*2-7;}for(int n=0;n<=9;++n){int s=0;for(int i=0;i<n;++i)s+=r[i].value*r[i].count;if(record_total(r,n)!=s)return 9;}",
                ),
                (
                    "structs",
                    "big_make",
                    "big_make(int32_t seed)",
                    "for(int i=-10;i<10;++i){struct big r=big_make(i);if(r.a!=i||r.b!=i+1||r.c!=i*2||r.d!=i*3)return 10;}",
                ),
                (
                    "structs",
                    "big_sum",
                    "struct big value",
                    "for(int i=-10;i<10;++i){struct big r={i,i+1,i*2,i*3};if(big_sum(r)!=i*7+1)return 11;}",
                ),
                (
                    "structs",
                    "flags_set_mode",
                    "void *f",
                    "for(unsigned v=0;v<256;++v)for(unsigned m=0;m<16;++m){unsigned f=v;flags_set_mode(&f,m);if(f!=((v&~14u)|((m&7)<<1)))return 12;}",
                ),
                (
                    "structs",
                    "flags_level",
                    "flags_level(",
                    "for(unsigned f=0;f<256;++f)if(flags_level(f)!=((f&1)?((f>>4)&15):((f>>1)&7)))return 13;",
                ),
                (
                    "structs",
                    "word_low_byte",
                    "word_low_byte(",
                    "for(unsigned w=0;w<1000;++w)if(word_low_byte(w)!=(w&255))return 14;",
                ),
                ("l4_memory", "bump", "bump(", ""),
                ("l4_memory", "banner_first", "banner_first(", ""),
            ] {
                let fixture =
                    common::fixtures_dir().join(format!("codeview/{source}.O{level}.{extension}"));
                let mut binary = Binary::open(&fixture).expect("fixture");
                let addr = binary.find(name).expect("source function").addr;
                let code = binary.decompile(addr, None, None).expect("printed C");
                assert!(code.contains(expected), "{fixture:?}: {code}");
                if name == "sum_until" && level == 0 {
                    assert!(code.contains("for (int32_t i = 1;"), "{code}");
                }
                if name == "point_dot" {
                    assert!(code.contains("a->x") && code.contains("b->y"), "{code}");
                }
                if name == "record_total" {
                    assert!(
                        code.contains("struct record {") && code.contains("int16_t count;"),
                        "{code}"
                    );
                    if level == 0 {
                        assert!(code.contains("items[i].value"), "{code}");
                    }
                }
                if name == "rect_area" {
                    assert!(code.contains("r->max.x"), "{code}");
                }
                let file = scratch.join(format!("{name}.{level}.{extension}.c"));
                let exe = file.with_extension("out");
                std::fs::write(&file, format!("#include <stdint.h>\n#include <stdbool.h>\n#include <string.h>\n{code}\nint main(void){{ {driver} return 0; }}\n")).expect("printed source");
                for optimization in ["-O0", "-O2"] {
                    let output = Command::new("clang")
                        .args([
                            "-std=c11",
                            optimization,
                            "-fwrapv",
                            "-fno-strict-aliasing",
                            "-Werror",
                        ])
                        .arg(&file)
                        .arg("-o")
                        .arg(&exe)
                        .output()
                        .expect("C compiler");
                    assert!(
                        output.status.success(),
                        "{code}\n{}",
                        String::from_utf8_lossy(&output.stderr)
                    );
                    assert!(
                        Command::new(&exe).status().expect("compiled C").success(),
                        "{fixture:?}: {name}"
                    );
                }
            }
        }
    }
}
