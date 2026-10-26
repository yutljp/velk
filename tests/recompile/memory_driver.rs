use super::*;

#[test]
fn arm32_struct_array_memory_comparisons() {
    let scratch = scratch_dir("arm32-struct-arrays");
    for name in [
        "arm32/struct_arrays.arm.O0.elf",
        "arm32/struct_arrays.arm.O2.elf",
        "arm32/struct_arrays.thumb.O0.elf",
        "arm32/struct_arrays.thumb.O2.elf",
    ] {
        let mut fixture = prepare(Path::new(name), Mode::Memory);
        fixture
            .candidates
            .retain(|candidate| candidate.ir.name.as_deref() == Some("cell_set"));
        assert_eq!(fixture.candidates.len(), 1, "{name}");
        let result = check_fixture(&fixture, &scratch, Mode::Memory, &[]);
        assert_comparisons(&result, 1);
    }
    std::fs::remove_dir_all(scratch).unwrap();
}

#[test]
fn memory_execution_budget_excludes_fault_handling_and_waiting() {
    let scratch = scratch_dir("memory-execution-budget");
    let support = r#"
#include <time.h>
#include <unistd.h>
#define REGION_START 0x30000000ULL
#define REGION_BYTES 0x10000ULL
static void velk_fixture_overlay(uintptr_t page, uint64_t size) {
    (void)page; (void)size;
}
static void velk_prepare(int k, uint64_t seed) { (void)k; (void)seed; }
static void velk_canonical(int k, const uint64_t *a, uint64_t *c) {
    (void)k; c[0] = a[0];
}
static uint64_t velk_call(int k, const uint64_t *a) {
    if (k == 1) {
        volatile uint64_t count = 0;
        for (;;) count++;
    }
    if (k == 2) usleep(300000);
    uint64_t value = *(volatile uint64_t *)(uintptr_t)a[0];
    *(volatile uint64_t *)REGION_START = value;
    return value;
}
"#;
    // Both CPU work in the handler and time off CPU exceed the execution budget.
    let driver = MEMORY_DRIVER.replace(
        "    uintptr_t page =",
        "    clock_t start = clock();\n    while (clock() - start < CLOCKS_PER_SEC / 4) {}\n    usleep(300000);\n    uintptr_t page =",
    );
    let source = Program {
        text: format!("{HEADER}{support}{driver}"),
        ranges: Vec::new(),
    };
    let args: &[&str] = if cfg!(target_os = "macos") {
        &["-arch", "x86_64", "-Wl,-pagezero_size,0x1000"]
    } else {
        &[]
    };
    let address = 0x3002_0000 - 4;
    let mut requests = String::new();
    for (function, seed) in [(0, 2), (1, 3), (2, 4), (0, 2)] {
        requests.push_str(&request_run(function, Some(seed), &[address]));
    }
    for level in LEVELS {
        let executable = build(&source, &scratch, level, args);
        let output = run_once(&executable, &requests);
        let rows: Vec<_> = output.lines().collect();
        assert_eq!(rows.len(), 4, "{level}: {output}");
        assert_eq!(rows[1], "timeout", "{level}: {output}");
        for (index, seed) in [(0, 2), (2, 4), (3, 2)] {
            let mut value = 0_u64;
            for byte in 0..8 {
                value |= (eval::hash(seed, address + byte) & 0xff) << (byte * 8);
            }
            let mut checksum = 0xcbf2_9ce4_8422_2325_u64;
            for offset in 0..REGION_SIZE {
                let byte = if offset < 8 {
                    (value >> (offset * 8)) & 0xff
                } else {
                    eval::hash(seed, 0x3000_0000 + offset) & 0xff
                };
                checksum = (checksum ^ byte).wrapping_mul(0x100_0000_01b3);
            }
            assert_eq!(
                rows[index],
                format!("v {value:x} {checksum:x}"),
                "{level}: {output}"
            );
        }
    }
    std::fs::remove_dir_all(scratch).unwrap();
}
