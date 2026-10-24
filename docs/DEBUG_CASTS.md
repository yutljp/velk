# Debug information cast counts

Counts come from `tests/golden/casts.txt`. Vectors list memory pointer, byte pointer, other pointer, address integer, and scalar casts, in that order. Each row pairs `.debug.elf` and `.stripped.elf` metrics fixtures.

| Fixture prefix | Debug before | Debug after | Stripped before | Stripped after |
| --- | --- | --- | --- | --- |
| aggregate_abi.aarch64.O0 | 60/5/0/0/13 | 60/5/0/0/13 | 0/0/1/0/1 | 0/0/1/0/1 |
| aggregate_abi.aarch64.O2 | 60/5/0/0/13 | 60/5/0/0/13 | 3/0/0/0/17 | 3/0/0/0/17 |
| aggregate_abi.x86_64.O0 | 52/10/0/0/22 | 52/10/0/0/22 | 2/2/2/0/0 | 2/2/2/0/0 |
| aggregate_abi.x86_64.O2 | 52/10/0/0/22 | 52/10/0/0/22 | 18/11/0/0/0 | 18/11/0/0/0 |
| alt_names.aarch64.O0 | 0/0/0/0/0 | 0/0/0/0/0 | 0/0/0/0/0 | 0/0/0/0/0 |
| alt_names.aarch64.O2 | 0/0/0/0/1 | 0/0/0/0/1 | 0/0/0/0/1 | 0/0/0/0/1 |
| alt_names.x86_64.O0 | 0/0/0/0/0 | 0/0/0/0/0 | 0/0/0/0/0 | 0/0/0/0/0 |
| alt_names.x86_64.O2 | 0/0/0/0/1 | 0/0/0/0/1 | 0/0/0/0/1 | 0/0/0/0/1 |
| arith_mixed.aarch64.O0 | 0/0/0/0/0 | 0/0/0/0/0 | 0/0/0/0/0 | 0/0/0/0/0 |
| arith_mixed.aarch64.O2 | 0/0/1/0/6 | 0/0/1/0/6 | 0/0/1/0/5 | 0/0/1/0/5 |
| arith_mixed.x86_64.O0 | 0/0/0/0/0 | 0/0/0/0/0 | 0/0/0/0/0 | 0/0/0/0/0 |
| arith_mixed.x86_64.O2 | 4/4/0/0/6 | 4/4/0/0/6 | 4/4/0/0/6 | 4/4/0/0/6 |
| calls.aarch64.O0 | 2/4/4/1/4 | 2/4/4/1/4 | 0/1/4/0/5 | 0/1/4/0/5 |
| calls.aarch64.O2 | 3/3/6/4/3 | 3/3/6/4/3 | 2/0/9/4/3 | 2/0/9/4/3 |
| calls.x86_64.O0 | 0/0/6/1/3 | 0/0/6/1/3 | 0/0/6/1/3 | 0/0/6/1/3 |
| calls.x86_64.O2 | 4/1/13/1/4 | 4/1/13/1/4 | 4/0/13/1/4 | 4/0/13/1/4 |
| control.aarch64.O0 | 0/0/0/0/0 | 0/0/0/0/0 | 0/0/0/0/0 | 0/0/0/0/0 |
| control.aarch64.O2 | 0/0/3/1/15 | 0/0/3/1/15 | 0/0/3/1/13 | 0/0/3/1/13 |
| control.x86_64.O0 | 0/0/0/0/1 | 0/0/0/0/1 | 0/0/0/0/2 | 0/0/0/0/2 |
| control.x86_64.O2 | 4/4/1/0/15 | 4/4/1/0/15 | 4/4/1/0/13 | 4/4/1/0/13 |
| divmod_a64.aarch64.O0 | 0/0/0/0/0 | 0/0/0/0/0 | 0/0/0/0/0 | 0/0/0/0/0 |
| divmod_a64.aarch64.O2 | 0/0/0/0/1 | 0/0/0/0/1 | 0/0/0/0/1 | 0/0/0/0/1 |
| divmod_a64.x86_64.O0 | 0/0/0/0/0 | 0/0/0/0/0 | 0/0/0/0/0 | 0/0/0/0/0 |
| divmod_a64.x86_64.O2 | 0/0/0/0/1 | 0/0/0/0/1 | 0/0/0/0/1 | 0/0/0/0/1 |
| divmod_x64.aarch64.O0 | 0/0/0/0/0 | 0/0/0/0/0 | 0/0/0/0/0 | 0/0/0/0/0 |
| divmod_x64.aarch64.O2 | 0/0/0/0/0 | 0/0/0/0/0 | 0/0/0/0/0 | 0/0/0/0/0 |
| divmod_x64.x86_64.O0 | 0/0/0/0/0 | 0/0/0/0/0 | 0/0/0/0/0 | 0/0/0/0/0 |
| divmod_x64.x86_64.O2 | 0/0/0/0/0 | 0/0/0/0/0 | 0/0/0/0/0 | 0/0/0/0/0 |
| float.aarch64.O0 | 0/0/0/0/3 | 0/0/0/0/3 | 0/0/0/0/3 | 0/0/0/0/3 |
| float.aarch64.O2 | 0/0/0/0/8 | 0/0/0/0/8 | 0/0/0/0/8 | 0/0/0/0/8 |
| float.x86_64.O0 | 0/0/1/0/3 | 0/0/1/0/3 | 0/0/1/0/3 | 0/0/1/0/3 |
| float.x86_64.O2 | 0/0/0/0/4 | 0/0/0/0/4 | 0/0/0/0/4 | 0/0/0/0/4 |
| integers.aarch64.O0 | 0/0/0/0/3 | 0/0/0/0/1 | 0/0/0/0/4 | 0/0/0/0/4 |
| integers.aarch64.O2 | 0/0/0/0/1 | 0/0/0/0/1 | 0/0/0/0/3 | 0/0/0/0/3 |
| integers.x86_64.O0 | 0/0/0/0/4 | 0/0/0/0/2 | 0/0/0/0/5 | 0/0/0/0/5 |
| integers.x86_64.O2 | 0/0/0/0/1 | 0/0/0/0/1 | 0/0/0/0/2 | 0/0/0/0/2 |
| l0_arith.aarch64.O0 | 0/0/0/0/0 | 0/0/0/0/0 | 0/0/0/0/0 | 0/0/0/0/0 |
| l0_arith.aarch64.O2 | 0/0/0/0/1 | 0/0/0/0/1 | 0/0/0/0/1 | 0/0/0/0/1 |
| l0_arith.x86_64.O0 | 0/0/0/0/0 | 0/0/0/0/0 | 0/0/0/0/0 | 0/0/0/0/0 |
| l0_arith.x86_64.O2 | 0/0/0/0/0 | 0/0/0/0/0 | 0/0/0/0/0 | 0/0/0/0/0 |
| l1_branch.aarch64.O0 | 0/0/0/0/0 | 0/0/0/0/0 | 0/0/0/0/0 | 0/0/0/0/0 |
| l1_branch.aarch64.O2 | 0/0/0/0/0 | 0/0/0/0/0 | 0/0/0/0/0 | 0/0/0/0/0 |
| l1_branch.x86_64.O0 | 0/0/0/0/0 | 0/0/0/0/0 | 0/0/0/0/0 | 0/0/0/0/0 |
| l1_branch.x86_64.O2 | 0/0/0/0/0 | 0/0/0/0/0 | 0/0/0/0/0 | 0/0/0/0/0 |
| l2_loop.aarch64.O0 | 0/0/3/0/0 | 0/0/3/0/0 | 0/0/3/0/0 | 0/0/3/0/0 |
| l2_loop.aarch64.O2 | 0/0/3/0/1 | 0/0/3/0/1 | 0/0/3/0/1 | 0/0/3/0/1 |
| l2_loop.x86_64.O0 | 0/0/3/0/0 | 0/0/3/0/0 | 0/0/3/0/0 | 0/0/3/0/0 |
| l2_loop.x86_64.O2 | 0/0/3/0/2 | 0/0/3/0/2 | 0/0/3/0/2 | 0/0/3/0/2 |
| l4_memory.aarch64.O0 | 1/0/2/0/0 | 1/0/2/0/0 | 1/0/2/0/0 | 1/0/2/0/0 |
| l4_memory.aarch64.O2 | 3/0/3/0/5 | 3/0/3/0/5 | 3/0/3/0/4 | 3/0/3/0/4 |
| l4_memory.x86_64.O0 | 1/0/2/0/1 | 1/0/2/0/1 | 1/0/2/0/1 | 1/0/2/0/1 |
| l4_memory.x86_64.O2 | 5/4/2/0/6 | 5/4/2/0/6 | 5/4/2/0/6 | 5/4/2/0/6 |
| l5_switch.aarch64.O0 | 0/0/17/0/0 | 0/0/17/0/0 | 0/0/17/0/0 | 0/0/17/0/0 |
| l5_switch.aarch64.O2 | 0/0/17/0/1 | 0/0/17/0/1 | 0/0/17/0/1 | 0/0/17/0/1 |
| l5_switch.x86_64.O0 | 0/0/17/0/0 | 0/0/17/0/0 | 0/0/17/0/0 | 0/0/17/0/0 |
| l5_switch.x86_64.O2 | 0/0/17/0/0 | 0/0/17/0/0 | 0/0/17/0/0 | 0/0/17/0/0 |
| l6_abi.aarch64.O0 | 0/0/0/0/0 | 0/0/0/0/0 | 0/0/0/0/0 | 0/0/0/0/0 |
| l6_abi.aarch64.O2 | 0/0/0/0/1 | 0/0/0/0/1 | 0/0/0/0/1 | 0/0/0/0/1 |
| l6_abi.x86_64.O0 | 0/0/0/0/0 | 0/0/0/0/0 | 0/0/0/0/0 | 0/0/0/0/0 |
| l6_abi.x86_64.O2 | 0/0/0/0/0 | 0/0/0/0/0 | 0/0/0/0/0 | 0/0/0/0/0 |
| loops.aarch64.O0 | 0/0/0/0/0 | 0/0/0/0/0 | 0/0/0/0/0 | 0/0/0/0/0 |
| loops.aarch64.O2 | 0/0/0/0/3 | 0/0/0/0/3 | 0/0/0/0/3 | 0/0/0/0/3 |
| loops.x86_64.O0 | 0/0/0/0/0 | 0/0/0/0/0 | 0/0/0/0/1 | 0/0/0/0/1 |
| loops.x86_64.O2 | 0/0/0/0/2 | 0/0/0/0/2 | 0/0/0/0/2 | 0/0/0/0/2 |
| memory.aarch64.O0 | 0/0/2/2/4 | 0/0/2/2/3 | 0/0/2/2/2 | 0/0/2/2/2 |
| memory.aarch64.O2 | 0/2/6/4/2 | 0/2/6/4/2 | 0/0/6/6/0 | 0/0/6/6/0 |
| memory.x86_64.O0 | 0/0/2/2/4 | 0/0/2/2/3 | 0/0/2/1/2 | 0/0/2/1/2 |
| memory.x86_64.O2 | 2/0/2/4/1 | 2/0/2/4/1 | 12/14/2/3/0 | 12/14/2/3/0 |
| strings.aarch64.O0 | 1/0/1/0/0 | 1/0/1/0/0 | 1/0/1/0/0 | 1/0/1/0/0 |
| strings.aarch64.O2 | 1/0/1/0/0 | 1/0/1/0/0 | 1/0/1/0/0 | 1/0/1/0/0 |
| strings.x86_64.O0 | 1/0/1/0/1 | 1/0/1/0/1 | 1/0/1/0/1 | 1/0/1/0/1 |
| strings.x86_64.O2 | 1/0/1/0/1 | 1/0/1/0/1 | 1/0/1/0/1 | 1/0/1/0/1 |
| struct_arrays.aarch64.O0 | 0/0/0/0/0 | 0/0/0/0/0 | 0/0/0/0/0 | 0/0/0/0/0 |
| struct_arrays.aarch64.O2 | 2/0/2/0/1 | 2/0/2/0/1 | 2/0/0/0/1 | 2/0/0/0/1 |
| struct_arrays.x86_64.O0 | 2/2/0/0/3 | 2/2/0/0/2 | 0/0/0/1/1 | 0/0/0/1/1 |
| struct_arrays.x86_64.O2 | 10/6/0/0/2 | 10/6/0/0/2 | 6/2/0/0/1 | 6/2/0/0/1 |
| structs.aarch64.O0 | 12/2/0/0/10 | 12/2/0/0/10 | 9/3/1/0/2 | 9/3/1/0/2 |
| structs.aarch64.O2 | 19/3/0/0/7 | 19/3/0/0/7 | 10/0/0/0/4 | 10/0/0/0/4 |
| structs.x86_64.O0 | 11/4/0/0/13 | 11/4/0/0/13 | 6/3/1/0/3 | 6/3/1/0/3 |
| structs.x86_64.O2 | 17/4/0/0/7 | 17/4/0/0/7 | 8/4/0/0/3 | 8/4/0/0/3 |
| switch_jumptable.aarch64.O0 | 0/0/1/0/0 | 0/0/1/0/0 | 0/0/1/0/0 | 0/0/1/0/0 |
| switch_jumptable.aarch64.O2 | 0/0/1/0/0 | 0/0/1/0/0 | 0/0/1/0/0 | 0/0/1/0/0 |
| switch_jumptable.x86_64.O0 | 0/0/1/0/1 | 0/0/1/0/1 | 0/0/1/0/1 | 0/0/1/0/1 |
| switch_jumptable.x86_64.O2 | 0/0/1/0/1 | 0/0/1/0/1 | 0/0/1/0/1 | 0/0/1/0/1 |
| switch_value_table.aarch64.O0 | 0/0/0/0/0 | 0/0/0/0/0 | 0/0/0/0/0 | 0/0/0/0/0 |
| switch_value_table.aarch64.O2 | 0/0/1/0/0 | 0/0/1/0/0 | 0/0/1/0/0 | 0/0/1/0/0 |
| switch_value_table.x86_64.O0 | 0/0/0/0/0 | 0/0/0/0/0 | 0/0/0/0/0 | 0/0/0/0/0 |
| switch_value_table.x86_64.O2 | 0/0/1/0/0 | 0/0/1/0/0 | 0/0/1/0/0 | 0/0/1/0/0 |
| tail_calls.aarch64.O0 | 0/0/0/0/0 | 0/0/0/0/0 | 0/0/0/0/0 | 0/0/0/0/0 |
| tail_calls.aarch64.O2 | 0/0/0/0/1 | 0/0/0/0/1 | 0/0/0/0/1 | 0/0/0/0/1 |
| tail_calls.x86_64.O0 | 0/0/0/0/0 | 0/0/0/0/0 | 0/0/0/0/0 | 0/0/0/0/0 |
| tail_calls.x86_64.O2 | 0/0/0/0/0 | 0/0/0/0/0 | 0/0/0/0/0 | 0/0/0/0/0 |
| tail_indirect.aarch64.O0 | 0/0/0/0/0 | 0/0/0/0/0 | 0/0/0/0/0 | 0/0/0/0/0 |
| tail_indirect.aarch64.O2 | 0/0/0/0/0 | 0/0/0/0/0 | 0/0/0/0/0 | 0/0/0/0/0 |
| tail_indirect.x86_64.O0 | 0/0/0/0/0 | 0/0/0/0/0 | 0/0/0/0/0 | 0/0/0/0/0 |
| tail_indirect.x86_64.O2 | 0/0/0/0/0 | 0/0/0/0/0 | 0/0/0/0/0 | 0/0/0/0/0 |

Total casts: debug 811 → 804; stripped 485 → 485. Only scalar counts change.

## Fixtures with more debug casts

Examples below are retained casts in the rendered C. Aggregate bit copies preserve object representations, signed-to-unsigned conversions preserve access-width bits, and explicit widening prevents narrower C arithmetic. Byte-offset structure accesses remain when an offset is held in a separate integer temporary.

| Fixture prefix | Debug / stripped total before | Debug / stripped total after | Example |
| --- | --- | --- | --- |
| aggregate_abi.aarch64.O0 | 78 / 2 | 78 / 2 | `uint64_t value_bits = *(uint64_t *)__builtin_memcpy((uint64_t[1]){0}, (unsigned char *)&value + 0x0, 8);` |
| aggregate_abi.aarch64.O2 | 78 / 20 | 78 / 20 | `uint64_t value_bits = *(uint64_t *)__builtin_memcpy((uint64_t[1]){0}, (unsigned char *)&value + 0x0, 8);` |
| aggregate_abi.x86_64.O0 | 84 / 6 | 84 / 6 | `uint64_t value_bits = *(uint64_t *)__builtin_memcpy((uint64_t[1]){0}, (unsigned char *)&value + 0x0, 8);` |
| aggregate_abi.x86_64.O2 | 84 / 29 | 84 / 29 | `uint64_t value_bits = *(uint64_t *)__builtin_memcpy((uint64_t[1]){0}, (unsigned char *)&value + 0x0, 8);` |
| arith_mixed.aarch64.O2 | 7 / 6 | 7 / 6 | `v2 = (uint64_t)v1 * ((x - 2) & 0xffffffff);` |
| calls.aarch64.O0 | 15 / 10 | 15 / 10 | `return (uint64_t)x << 1;` |
| calls.aarch64.O2 | 19 / 18 | 19 / 18 | `return (uint64_t)x << 1;` |
| calls.x86_64.O2 | 23 / 22 | 23 / 22 | `uint8_t *const table = (uint8_t *)0x202610ULL;` |
| control.aarch64.O2 | 19 / 17 | 19 / 17 | `for (i = 0; (int64_t)i < (uint32_t)n; i++) {` |
| control.x86_64.O2 | 24 / 22 | 24 / 22 | `if ((uint32_t)n >= 4) {` |
| l4_memory.aarch64.O2 | 11 / 10 | 11 / 10 | `v1 = mul_lanes32(*(uint64_t *)(b), *(uint64_t *)(a));` |
| memory.aarch64.O0 | 8 / 6 | 7 / 6 | `uint32_t *const grid = (uint32_t *)0x220454ULL;` |
| memory.aarch64.O2 | 14 / 12 | 14 / 12 | `v2 = (uint64_t *)(src + 0x10);` |
| memory.x86_64.O0 | 8 / 5 | 7 / 5 | `uint32_t *const grid = (uint32_t *)0x202450ULL;` |
| struct_arrays.aarch64.O2 | 5 / 3 | 5 / 3 | `v3 = (uint32_t)n;` |
| struct_arrays.x86_64.O0 | 7 / 2 | 6 / 2 | `v1 = (uint64_t)i << 4;` |
| struct_arrays.x86_64.O2 | 18 / 9 | 18 / 9 | `v1 = (uint64_t)i << 4;` |
| structs.aarch64.O0 | 24 / 15 | 24 / 15 | `uint64_t a_x = (uint32_t)a.x;` |
| structs.aarch64.O2 | 29 / 14 | 29 / 14 | `v1 = sub_lanes32(*(uint64_t *)((uint8_t *)r + 0x8), *(uint64_t *)(r));` |
| structs.x86_64.O0 | 28 / 13 | 28 / 13 | `v1 = (int64_t)i * 24;` |
| structs.x86_64.O2 | 28 / 15 | 28 / 15 | `v6 = (int16_t)*(uint16_t *)(v5 - 0x18) * *(uint64_t *)(v5 - 0x20) + v3;` |

## Removed casts

- Declared signed byte parameters already promote to signed `int`: `narrow_add` uses `a + b`. The x86 fixture retains its result truncation.
- A declared signed short field already promotes with its sign: `item_weight` uses `items[i].kind * items[i].count`.
- A plain char zero test works with either char signedness: `string_length` uses `s[n] != 0`. Value-producing unsigned byte reads retain their conversion.

The recompile tests `declared_narrow_signed_values_extend_without_casts` and `plain_char_zero_tests_preserve_both_char_signs` assert on printed C and execute signed boundaries and every byte value, respectively. Existing structure-array execution tests cover named fields and wide index arithmetic.

Named `int` parameters already use the same promoted C type as `int32_t`; the signed-extension test includes this spelling. Direct declared-structure indexing already prints `items[i].kind` without a 64-bit index cast. In contrast, `v1 = (int64_t)i * 24` computes an integer byte offset before any pointer operation, so the widening is required to avoid signed 32-bit multiplication overflow. Recovering a field from such a separately stored byte offset remains outside these scalar conversion changes.
