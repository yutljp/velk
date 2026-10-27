use super::*;

#[test]
fn constant_stack_loads_keep_signed_branch_and_selection_widths() {
    let scratch = scratch_dir("constant-slot-comparisons");
    let assembly = scratch.join("comparisons.s");
    let object = scratch.join("comparisons.o");
    let mut source = String::from(
        ".text
.globl pure_callee
.type pure_callee,@function
pure_callee:
movl $5, %eax
ret
.size pure_callee, .-pure_callee
",
    );
    let mut names = Vec::new();
    for suffix in ["b", "w", "l"] {
        for value in [0, -28] {
            for selection in [false, true] {
                let name = format!("compare_slot_{}_{suffix}_{}", -value, u8::from(selection));
                let result = if selection {
                    "setge %al\nmovzbl %al, %eax\nmovl %eax, -8(%rbp)".to_owned()
                } else {
                    format!(
                        "jge .Ltrue_{name}\nmovl $99, -8(%rbp)\njmp .Ldone_{name}\n.Ltrue_{name}:\nmovl $7, -8(%rbp)\n.Ldone_{name}:"
                    )
                };
                writeln!(
                    source,
                    ".globl {name}
.type {name},@function
{name}:
pushq %rbp
movq %rsp, %rbp
subq $32, %rsp
movq $1, -16(%rbp)
call pure_callee
mov{suffix} ${value}, -4(%rbp)
cmp{suffix} $-27, -4(%rbp)
{result}
call pure_callee
movl -8(%rbp), %eax
addq $32, %rsp
popq %rbp
ret
.size {name}, .-{name}"
                )
                .unwrap();
                let expected = if selection {
                    i32::from(value >= -27)
                } else if value >= -27 {
                    7
                } else {
                    99
                };
                names.push((name, expected));
            }
        }
    }
    source.push_str(
        ".globl signed_slot_shift
.type signed_slot_shift,@function
signed_slot_shift:
pushq %rbp
movq %rsp, %rbp
subq $32, %rsp
movq $1, -16(%rbp)
call pure_callee
movl $0x80000000, -4(%rbp)
sarl $1, -4(%rbp)
call pure_callee
movl -4(%rbp), %eax
addq $32, %rsp
popq %rbp
ret
.size signed_slot_shift, .-signed_slot_shift
",
    );
    names.push(("signed_slot_shift".to_owned(), -0x40000000));
    common::compiler::compile_x86_64_assembly(&compiler(), &assembly, &object, &source);
    let mut binary = Binary::open(&object).unwrap();
    let address = binary.find("pure_callee").unwrap().addr;
    let mut code = binary.decompile(address, None, None).unwrap();
    let mut assertions = String::new();
    for (name, expected) in names {
        let address = binary.find(&name).unwrap().addr;
        code.push_str(&binary.decompile(address, None, None).unwrap());
        writeln!(assertions, "if ({name}() != {expected}) __builtin_trap();").unwrap();
    }
    syntax::run_printed(&velk::render::combine(&code), "", &assertions);
    std::fs::remove_dir_all(scratch).ok();
}
