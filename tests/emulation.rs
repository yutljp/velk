//! Checks the execution interfaces against compiled C and explicit fault cases.

mod common;
#[path = "emulation/edges.rs"]
mod edges;
#[path = "emulation/io.rs"]
mod io;
#[path = "emulation/matrix.rs"]
mod matrix;

use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::OnceLock;

use serde_json::{Value, json};
use velk::emulation::{self, Options, Report};
use velk::service::Binary;

const SOURCE: &str = r#"
typedef unsigned int u32;
unsigned char data[8] = { 53, 56, 49, 49, 50, 0, 127, 255 };
u32 results[4];
__attribute__((noinline)) u32 decode(unsigned char *p, u32 n, u32 key) {
    u32 sum = 0;
    for (u32 i = 0; i < n; i++) { p[i] ^= key; sum = sum * 33 + p[i]; }
    return sum;
}
__attribute__((noinline)) u32 checksum(const unsigned char *p, u32 n) {
    u32 sum = 0;
    for (u32 i = 0; i < n; i++) { sum = (sum << 3) ^ (sum >> 29) ^ p[i]; }
    return sum;
}
__attribute__((noinline)) u32 sum9(u32 a,u32 b,u32 c,u32 d,u32 e,u32 f,u32 g,u32 h,u32 i) {
    return a + 3*b + 5*c + 7*d + 11*e + 13*f + 17*g + 19*h + 23*i;
}
__attribute__((noinline)) u32 nested(unsigned char *p, u32 n) { return decode(p,n,93) ^ checksum(p,n); }
__attribute__((noinline)) u32 tail(unsigned char *p, u32 n) { return checksum(p,n); }
__attribute__((noinline)) void trap(void) { __builtin_trap(); }
__attribute__((noinline)) u32 fault(const unsigned char *p) { return p[3]; }
__attribute__((noinline)) u32 spin(volatile u32 *p) { while (*p) {} return *p; }
void test_entry(void) {
    results[0] = decode(data, 8, 93);
    results[1] = checksum(data, 8);
    results[2] = sum9(1,2,3,4,5,6,7,8,9);
    results[3] = nested(data, 8);
}
"#;

fn fixture(architecture: &str) -> PathBuf {
    static X64: OnceLock<PathBuf> = OnceLock::new();
    static X32: OnceLock<PathBuf> = OnceLock::new();
    static A64: OnceLock<PathBuf> = OnceLock::new();
    static A32: OnceLock<PathBuf> = OnceLock::new();
    static T32: OnceLock<PathBuf> = OnceLock::new();
    let cache = match architecture {
        "x86_64" => &X64,
        "i386" => &X32,
        "aarch64" => &A64,
        "arm32" => &A32,
        "thumb32" => &T32,
        _ => panic!("unknown architecture"),
    };
    cache.get_or_init(|| build_fixture(architecture)).clone()
}

fn build_fixture(architecture: &str) -> PathBuf {
    let scratch = common::root()
        .join("target/emulation-tests")
        .join(format!("{architecture}-{}", std::process::id()));
    fs::create_dir_all(&scratch).expect("valid compiled fixture state");
    let (target, startup) = match architecture {
        "x86_64" => (
            "x86_64-linux-gnu",
            ".text\n.globl _start\n_start:\ncall test_entry\nmov $1,%eax\nmov $1,%edi\nlea results(%rip),%rsi\nmov $16,%edx\nsyscall\nmov $60,%eax\nxor %edi,%edi\nsyscall\n",
        ),
        "i386" => (
            "i386-linux-gnu",
            ".text\n.globl _start\n_start:\ncall test_entry\nmov $4,%eax\nmov $1,%ebx\nmov $results,%ecx\nmov $16,%edx\nint $0x80\nmov $1,%eax\nxor %ebx,%ebx\nint $0x80\n",
        ),
        "aarch64" => (
            "aarch64-linux-gnu",
            ".text\n.globl _start\n_start:\nbl test_entry\nmov x0,#1\nadrp x1,results\nadd x1,x1,:lo12:results\nmov x2,#16\nmov x8,#64\nsvc #0\nmov x0,#0\nmov x8,#93\nsvc #0\n",
        ),
        "arm32" | "thumb32" => (
            "armv7-linux-gnueabihf",
            ".syntax unified\n.text\n.globl _start\n_start:\nbl test_entry\nmov r0,#1\nmovw r1,:lower16:results\nmovt r1,:upper16:results\nmov r2,#16\nmov r7,#4\nsvc #0\nmov r0,#0\nmov r7,#1\nsvc #0\n",
        ),
        _ => panic!("unknown architecture"),
    };
    fs::write(scratch.join("routines.c"), SOURCE).expect("valid compiled fixture state");
    fs::write(scratch.join("start.S"), startup).expect("valid compiled fixture state");
    let path = scratch.join("routines.elf");
    let mut compiler = Command::new("clang");
    if architecture == "thumb32" {
        compiler.arg("-mthumb");
    }
    let output = common::compiler::run(
        compiler
            .args([
                "-target",
                target,
                if matches!(architecture, "arm32" | "thumb32") {
                    "-O0"
                } else {
                    "-O1"
                },
                "-fno-vectorize",
                "-fno-slp-vectorize",
                "-fno-builtin",
                "-fno-stack-protector",
                "-fno-pie",
                "-nostdlib",
                "-static",
                "-fuse-ld=lld",
                "-Wl,-e,_start",
                "-Wl,--build-id=none",
            ])
            .arg(scratch.join("routines.c"))
            .arg(scratch.join("start.S"))
            .arg("-o")
            .arg(&path),
        None,
    );
    assert!(output.status.success(), "{architecture}: {output:?}");
    path
}

fn native_results() -> &'static [u32; 4] {
    static RESULTS: OnceLock<[u32; 4]> = OnceLock::new();
    RESULTS.get_or_init(|| {
        let scratch = common::root().join(format!("target/emulation-tests/native-{}", std::process::id()));
        fs::create_dir_all(&scratch).expect("creating native reference directory");
        let source = format!("{SOURCE}\n#include <stdio.h>\nint main(void) {{ test_entry(); return fwrite(results, sizeof(results), 1, stdout) == 1 ? 0 : 1; }}\n");
        let path = scratch.join("reference");
        common::compiler::compile_file(
            Command::new("clang").args(["-O1", "-fno-builtin"]).arg(scratch.join("reference.c")).arg("-o").arg(&path),
            &scratch.join("reference.c"),
            &source,
        );
        let output = Command::new(path)
            .output()
            .expect("valid compiled fixture state");
        assert!(output.status.success(), "{output:?}");
        assert_eq!(output.stdout.len(), 16);
        std::array::from_fn(|index| {
            u32::from_le_bytes(
                output.stdout[index * 4..index * 4 + 4]
                    .try_into()
                    .expect("valid compiled fixture state"),
            )
        })
    })
}

fn execute(binary: &Binary, start: &str, value: Value) -> Report {
    let options: Options = serde_json::from_value(value).expect("valid compiled fixture state");
    emulation::run(binary, start, &options, None).expect("valid compiled fixture state")
}

fn assert_returned_value(report: &Report, value: u32) {
    assert_eq!(report.reason, "return", "{report:?}");
    assert_eq!(
        velk::addr::parse(&report.return_value).expect("valid compiled fixture state") as u32,
        value,
        "{report:?}"
    );
}

fn check_imported_hooks(architecture: &str) {
    let scratch = common::root()
        .join("target/emulation-tests")
        .join(format!("imports-{architecture}-{}", std::process::id()));
    fs::create_dir_all(&scratch).expect("creating imported-call fixtures");
    let source = "extern void *memset(void *, int, __SIZE_TYPE__); extern __SIZE_TYPE__ strlen(const char *); unsigned hooked(char *p) { memset(p, 1, 4); p[2] ^= 3; return (unsigned)strlen(p); }";
    let target = match architecture {
        "x86_64" => "x86_64-linux-gnu",
        "i386" => "i386-linux-gnu",
        "aarch64" => "aarch64-linux-gnu",
        "arm32" | "thumb32" => "armv7-linux-gnueabihf",
        _ => panic!("unsupported fixture architecture"),
    };
    fs::write(scratch.join("imports.c"), source).expect("writing imported-call source");
    let mut compiler = Command::new("clang");
    if architecture == "thumb32" {
        compiler.arg("-mthumb");
    }
    let output = common::compiler::run(
        compiler
            .args([
                "-target",
                target,
                "-O1",
                "-fno-builtin",
                "-fPIC",
                "-shared",
                "-nostdlib",
                "-fuse-ld=lld",
            ])
            .arg(scratch.join("imports.c"))
            .arg("-o")
            .arg(scratch.join("imports.elf")),
        None,
    );
    assert!(output.status.success(), "{architecture}: {output:?}");
    let binary = Binary::open(&scratch.join("imports.elf")).expect("loading imported calls");
    let report = execute(&binary, "hooked", json!({"arguments":["0x10000000"]}));
    assert_returned_value(&report, 4);
    let region = report
        .memory
        .iter()
        .find(|region| region.address == "0x10000000")
        .expect("the hook's memory writes");
    assert_eq!(region.bytes, vec![1, 1, 2, 1]);
}

fn check_architecture(architecture: &str) {
    check_imported_hooks(architecture);
    let path = fixture(architecture);
    let binary = Binary::open(&path).expect("valid compiled fixture state");
    let data_address = binary
        .image()
        .data_symbols
        .iter()
        .find(|(_, name)| name.as_str() == "data")
        .map(|(&address, _)| address)
        .expect("valid compiled fixture state");
    let report = execute(
        &binary,
        "decode",
        json!({"arguments":[data_address,8,93],"trace":true}),
    );
    assert_returned_value(&report, native_results()[0]);
    assert!(!report.trace.is_empty());
    if matches!(architecture, "arm32" | "thumb32") {
        let fault = execute(&binary, "fault", json!({"arguments":["0x12345000"]}));
        assert_eq!(fault.reason, "error");
        assert_eq!(fault.registers["pc"], fault.address);
    }

    if matches!(architecture, "x86_64" | "i386") {
        let name = if architecture == "i386" { "esp" } else { "rsp" };
        let width = if architecture == "i386" { 4 } else { 8 };
        assert_eq!(
            velk::addr::parse(&report.registers[name]),
            velk::addr::parse(&report.stack_pointer).map(|stack| stack + width)
        );
    }

    let changed: Vec<u8> = (0..8)
        .map(|offset| {
            let address = data_address + offset;
            for region in &report.memory {
                let start =
                    velk::addr::parse(&region.address).expect("valid compiled fixture state");
                if address >= start
                    && let Some(byte) = region.bytes.get((address - start) as usize)
                {
                    return *byte;
                }
            }
            panic!("missing changed byte at {address:x}: {report:?}")
        })
        .collect();
    let expected: Vec<u8> = [53, 56, 49, 49, 50, 0, 127, 255]
        .map(|byte| byte ^ 93)
        .to_vec();
    assert_eq!(changed, expected);
    let decoded =
        json!({"arguments":["0x10000000",8],"memory":[{"address":"0x10000000","bytes":expected}]});
    assert_returned_value(&execute(&binary, "checksum", decoded), native_results()[1]);
    assert_returned_value(
        &execute(
            &binary,
            "tail",
            json!({"arguments":["0x10000000",8],"memory":[{"address":"0x10000000","bytes":expected}]}),
        ),
        native_results()[1],
    );
    assert_returned_value(
        &execute(&binary, "sum9", json!({"arguments":[1,2,3,4,5,6,7,8,9]})),
        native_results()[2],
    );
    assert_returned_value(
        &execute(&binary, "nested", json!({"arguments":[data_address,8]})),
        native_results()[0] ^ native_results()[1],
    );
    let runner = match architecture {
        "aarch64" => Some("qemu-aarch64"),
        "arm32" | "thumb32" => Some("qemu-arm"),
        "x86_64" if !cfg!(target_os = "linux") => Some("qemu-x86_64"),
        "i386" if !cfg!(target_os = "linux") => Some("qemu-i386"),
        _ => None,
    };
    let output = match runner {
        Some(runner) => Command::new(runner).arg(&path).output(),
        None => Command::new(&path).output(),
    };
    match output {
        Ok(output) => {
            #[cfg(unix)]
            {
                use std::os::unix::process::ExitStatusExt as _;
                if architecture == "i386" && output.status.signal() == Some(31) {
                    eprintln!(
                        "i386: native execution blocked by system-call sandbox; emulation compared with native fixed-width C results"
                    );
                    return;
                }
            }
            assert!(output.status.success(), "{architecture}: {output:?}");
            let values: Vec<u32> = output
                .stdout
                .as_chunks::<4>()
                .0
                .iter()
                .map(|bytes| u32::from_le_bytes(*bytes))
                .collect();
            assert_eq!(values.as_slice(), native_results(), "{architecture}");
            eprintln!("{architecture}: compiled C matches architecture runner and emulation");
        }
        Err(error) if runner.is_some() && error.kind() == std::io::ErrorKind::NotFound => {
            eprintln!(
                "{architecture}: runner unavailable; compiled target compared with native fixed-width C results"
            )
        }
        Err(error) => panic!("{architecture}: {error}"),
    }
}

#[test]
fn x86_64_matches_native_c() {
    check_architecture("x86_64");
}
#[test]
fn i386_matches_compiled_c() {
    check_architecture("i386");
}
#[test]
fn aarch64_matches_compiled_c() {
    check_architecture("aarch64");
}
#[test]
fn arm32_matches_compiled_c() {
    check_architecture("arm32");
    check_architecture("thumb32");
}

#[test]
fn faults_limits_initial_state_and_end_addresses_are_reported() {
    let binary = Binary::open(&fixture("x86_64")).expect("valid compiled fixture state");
    assert_eq!(execute(&binary, "trap", json!({})).reason, "trap");
    let fault = execute(&binary, "fault", json!({"arguments":["0x12345000"]}));
    assert_eq!(fault.reason, "error");
    assert!(
        fault
            .error
            .as_deref()
            .expect("valid compiled fixture state")
            .contains("0x12345003"),
        "{fault:?}"
    );
    assert!(
        fault
            .error
            .as_deref()
            .expect("valid compiled fixture state")
            .contains("instruction 0x")
    );
    let options = json!({"arguments":["0x10000000"],"memory":[{"address":"0x10000000","value":1,"width":4}],"stepLimit":40});
    assert_eq!(execute(&binary, "spin", options).reason, "step limit");
    assert_eq!(
        execute(&binary, "spin", json!({"timeLimitMs":0})).reason,
        "time limit"
    );
    let address = binary
        .find("sum9")
        .expect("valid compiled fixture state")
        .addr;
    let stopped = execute(
        &binary,
        &velk::addr::format(address),
        json!({"end":[address],"registers":{"rax":123}}),
    );
    assert_eq!(stopped.reason, "end address");
    assert_eq!(stopped.return_value, "0x7b");
    assert_eq!(stopped.steps, 0);
    let listing = binary
        .disasm(address, 3)
        .expect("valid compiled fixture state");
    let end = velk::addr::parse(
        listing[1]
            .split_whitespace()
            .next()
            .expect("valid compiled fixture state"),
    )
    .expect("valid compiled fixture state");
    let report = execute(
        &binary,
        &velk::addr::format(address),
        json!({"arguments":[1,2,3,4,5,6,7,8,9],"end":[end],"trace":true}),
    );
    assert_eq!(report.reason, "end address", "{report:?}");
    assert_eq!(report.address, velk::addr::format(end));
    assert_eq!(report.trace, vec![velk::addr::format(address)]);

    let bad: Options = serde_json::from_value(json!({"memory":[{"address":address,"bytes":[0]}]}))
        .expect("valid compiled fixture state");
    assert!(
        emulation::run(&binary, "sum9", &bad, None)
            .unwrap_err()
            .to_string()
            .contains("protected")
    );
    let bad: Options = serde_json::from_value(json!({"registers":{"eax":1}}))
        .expect("valid compiled fixture state");
    assert!(emulation::run(&binary, "sum9", &bad, None).is_err());
    let bad: Options =
        serde_json::from_value(json!({"memory":[{"address":"0xffffffffffffffff","bytes":[1,2]}]}))
            .expect("valid compiled fixture state");
    assert!(emulation::run(&binary, "sum9", &bad, None).is_err());
}

#[test]
fn cli_javascript_and_mcp_share_the_execution_result() {
    let path = fixture("i386");
    let options = json!({"arguments":[1,2,3,4,5,6,7,8,9]});
    let output = Command::new(env!("CARGO_BIN_EXE_velk"))
        .args(["--emulate", "--json"])
        .arg(&path)
        .arg("sum9")
        .arg("--emulation-options")
        .arg(options.to_string())
        .output()
        .expect("valid compiled fixture state");
    assert!(output.status.success(), "{output:?}");
    let cli: Value = serde_json::from_slice(&output.stdout).expect("valid compiled fixture state");
    let engine = velk::script::Engine::new().expect("valid compiled fixture state");
    let script = format!(
        "velk.open({}).getFunction('sum9').emulate({options})",
        json!(path)
    );
    let output = engine.run(&script, None);
    assert!(output.error.is_none(), "{:?}", output.error);
    assert_eq!(
        serde_json::from_str::<Value>(&output.output).expect("valid compiled fixture state"),
        cli
    );
    use std::process::Stdio;
    let child = Command::new(env!("CARGO_BIN_EXE_velk"))
        .arg("--mcp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("valid compiled fixture state");
    let request = json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"velk_emulate","arguments":{"path":path,"start":"sum9","options":options}}});
    let output = common::mcp_request(child, &request);
    let response: Value =
        serde_json::from_slice(&output.stdout).expect("valid compiled fixture state");
    assert_eq!(response["result"]["isError"], false, "{response}");
    assert_eq!(
        serde_json::from_str::<Value>(
            response["result"]["content"][0]["text"]
                .as_str()
                .expect("valid compiled fixture state")
        )
        .expect("valid compiled fixture state"),
        cli
    );
}

#[test]
fn library_hooks_match_native_memory_and_unknown_calls_stop() {
    let scratch = common::root().join(format!(
        "target/emulation-tests/hooks-{}",
        std::process::id()
    ));
    fs::create_dir_all(&scratch).expect("valid compiled fixture state");
    let source = r#"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
__attribute__((noinline)) uint64_t exercise(unsigned char *p, const char *q) {
    memset(p, 0xaa, 8);
    memmove(p + 1, p, 5);
    memcpy(p + 8, q, 6);
    strcpy((char *)p + 16, q);
    char *a = malloc(8);
    char *b = calloc(2, 4);
    if (!a || !b) return 0;
    memset(a, 'z', 7); a[7] = 0;
    uint64_t result = strlen(a) + strlen((char *)p + 16) + b[3];
    result += (strcmp((char *)p + 8, q) == 0) * 10;
    result += (strncmp(a, q, 0) == 0) * 100;
    result += (strcmp(a, q) > 0) * 1000;
    free(a); free(b);
    return result;
}
__attribute__((noinline)) uintptr_t hook_value(unsigned char *p) { return (uintptr_t)memset(p, 7, 1); }
__attribute__((noinline)) uintptr_t read_clobbered(unsigned char *p) {
    memset(p, 7, 1);
    uintptr_t result;
    __asm__ volatile ("movq %%r10, %0" : "=r"(result));
    return result;
}
__attribute__((noinline)) uint32_t byte_registers(unsigned char *p) {
    memset(p, 7, 1);
    uint32_t result;
    __asm__ volatile ("movb $0x5a, %%ch; movzbl %%ch, %%eax" : "=a"(result) : : "rcx");
    return result;
}
__attribute__((noinline)) void no_integer_result(void) { void *p = malloc(1); free(p); }
__attribute__((noinline)) int zero_allocation(volatile unsigned char *p) {
    p[3] = 9;
    unsigned char *q = calloc(1, 8);
    if (!q) return 99;
    int result = q[3];
    free(q);
    return result;
}
__attribute__((noinline)) int redirect_access(const char *s) { (void)s; return 77; }
__attribute__((noinline)) int unknown_call(const char *s) { return access(s, 0); }
__attribute__((noinline)) int bad_copy(char *p) { memcpy(p + 1, p, 5); return 1; }
__attribute__((noinline)) void store(unsigned char *p) { *p = 7; }
int main(void) {
    unsigned char p[32] = {0};
    uint64_t result = exercise(p, "hello");
    fwrite(p, 1, sizeof(p), stdout);
    fwrite(&result, 1, sizeof(result), stdout);
    uint32_t partial = byte_registers(p);
    fwrite(&partial, 1, sizeof(partial), stdout);
    return 0;
}
"#;
    fs::write(scratch.join("hooks.c"), source).expect("valid compiled fixture state");
    let path = scratch.join("hooks.elf");
    let mut compiler = Command::new("clang");
    if cfg!(target_os = "macos") {
        compiler.args(["-arch", "x86_64"]);
    }
    let output = common::compiler::run(
        compiler
            .args([
                "-O1",
                "-fno-builtin",
                "-D_FORTIFY_SOURCE=0",
                "-fno-pie",
                "-no-pie",
            ])
            .arg(scratch.join("hooks.c"))
            .arg("-o")
            .arg(&path),
        None,
    );
    assert!(output.status.success(), "{output:?}");
    let output = Command::new(&path)
        .output()
        .expect("valid compiled fixture state");
    assert!(output.status.success(), "{output:?}");
    assert_eq!(output.stdout.len(), 44);
    let binary = Binary::open(&path).expect("valid compiled fixture state");
    let options = json!({"arguments":["0x10000000","0x10000100"],"memory":[{"address":"0x10000100","bytes":[104,101,108,108,111,0]}]});
    let report = execute(&binary, "exercise", options);
    assert_returned_value(
        &report,
        u64::from_le_bytes(
            output.stdout[32..40]
                .try_into()
                .expect("valid compiled fixture state"),
        ) as u32,
    );
    let mut bytes = [0u8; 32];
    for region in &report.memory {
        let address = velk::addr::parse(&region.address).expect("valid compiled fixture state");
        for (offset, &byte) in region.bytes.iter().enumerate() {
            if let Some(index) = (address + offset as u64)
                .checked_sub(0x1000_0000)
                .filter(|index| *index < 32)
            {
                bytes[index as usize] = byte;
            }
        }
    }
    assert_eq!(bytes, output.stdout[..32]);
    let modeled = execute(
        &binary,
        "hook_value",
        json!({"arguments":["0x10000000"],"registers":{"r10":123,"rbx":123}}),
    );
    assert_returned_value(&modeled, 0x1000_0000);
    assert_eq!(modeled.registers["r10"], "unknown");
    assert_eq!(modeled.registers["rbx"], "0x7b");
    let unknown = execute(
        &binary,
        "read_clobbered",
        json!({"arguments":["0x10000000"],"registers":{"r10":123}}),
    );
    assert_eq!(unknown.reason, "error");
    assert!(
        unknown
            .error
            .expect("undefined register diagnostic")
            .contains("undefined register")
    );
    assert_returned_value(
        &execute(
            &binary,
            "byte_registers",
            json!({"arguments":["0x10000000"]}),
        ),
        u32::from_le_bytes(
            output.stdout[40..44]
                .try_into()
                .expect("native partial register result"),
        ),
    );
    let no_result = execute(&binary, "no_integer_result", json!({}));
    assert_eq!(no_result.reason, "return", "{no_result:?}");
    assert_eq!(no_result.return_value, "unknown");
    assert_returned_value(
        &execute(
            &binary,
            "zero_allocation",
            json!({"arguments":["0x10000000"]}),
        ),
        0,
    );
    let report = execute(&binary, "unknown_call", json!({"arguments":["0x10000000"]}));
    assert_eq!(report.reason, "error", "{report:?}");
    assert!(
        report
            .error
            .expect("valid compiled fixture state")
            .contains("access")
    );
    let (&access_slot, access_name) = binary
        .image()
        .imports
        .iter()
        .find(|(_, name)| name.trim_start_matches('_') == "access")
        .expect("access import slot");
    let mut options = json!({"arguments":["0x10000000"],"callReturns":{}});
    options["callReturns"][access_name] = json!(13);
    assert_returned_value(&execute(&binary, "unknown_call", options), 13);
    assert_returned_value(
        &execute(
            &binary,
            "unknown_call",
            json!({"arguments":["0x10000000"],"skipCalls":true}),
        ),
        0,
    );
    let redirect = binary
        .find("redirect_access")
        .expect("the replacement function")
        .addr;
    assert_returned_value(
        &execute(
            &binary,
            "unknown_call",
            json!({"arguments":["0x10000000"],"memory":[{"address":access_slot,"value":redirect,"width":8}]}),
        ),
        77,
    );
    let report = execute(&binary, "bad_copy", json!({"arguments":["0x10000000"]}));
    assert_eq!(report.reason, "error");
    assert!(
        report
            .error
            .expect("valid compiled fixture state")
            .contains("overlap")
    );
    let address = binary
        .find("store")
        .expect("valid compiled fixture state")
        .addr;
    let report = execute(&binary, "store", json!({"arguments":[address]}));
    assert_eq!(report.reason, "error");
    assert!(
        report
            .error
            .expect("valid compiled fixture state")
            .contains("protected")
    );
}

#[test]
fn dll_image_and_heap_use_separate_address_ranges() {
    let binary = Binary::open(&common::fixtures_dir().join("windows_types.pe32.dll"))
        .expect("the 32-bit DLL fixture loads");
    let address = binary
        .find("windows_error")
        .expect("the exported function")
        .addr;
    let state = execute(&binary, "windows_error", json!({"end":[address]}));
    assert_eq!(state.reason, "end address");
    assert_ne!(state.heap_base, "0x10000000");
    let name = binary
        .image()
        .imports
        .values()
        .find(|name| name.contains("GetLastError"))
        .expect("the imported result function");
    let mut options =
        json!({"memory":[{"address":state.heap_base,"value":4660,"width":2}],"callReturns":{}});
    options["callReturns"][name] = json!(77);
    assert_returned_value(&execute(&binary, "windows_error", options), 77);
}
