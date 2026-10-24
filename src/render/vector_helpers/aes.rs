use crate::ir::{AesRound, Operation};

pub(super) fn definition(round: AesRound, high: bool) -> String {
    let name = crate::ir::operation_name(Operation::Aes { round, high });
    let decrypt = matches!(round, AesRound::Decrypt | AesRound::DecryptLast);
    let substitute = round != AesRound::MixColumns;
    let mix = !matches!(round, AesRound::EncryptLast | AesRound::DecryptLast);
    let matrix = if decrypt {
        "{14,11,13,9},{9,14,11,13},{13,9,14,11},{11,13,9,14}"
    } else {
        "{2,3,1,1},{1,2,3,1},{1,1,2,3},{3,1,1,2}"
    };
    let substitute_byte = if decrypt {
        "x = (uint8_t)((x << 1 | x >> 7) ^ (x << 3 | x >> 5) ^ (x << 6 | x >> 2) ^ 5);\n            x = velk_aes_inverse(x);"
    } else {
        "x = velk_aes_inverse(x);\n            x = (uint8_t)(x ^ (x << 1 | x >> 7) ^ (x << 2 | x >> 6) ^ (x << 3 | x >> 5) ^ (x << 4 | x >> 4) ^ 99);"
    };
    format!(
        r#"#ifndef VELK_AES_FIELD
#define VELK_AES_FIELD
static inline uint8_t velk_aes_multiply(uint8_t a, uint8_t b) {{
    uint8_t out = 0;
    for (unsigned i = 0; i < 8; ++i) {{
        if (b & 1) out ^= a;
        a = (uint8_t)((a << 1) ^ (a & 128 ? 27 : 0));
        b >>= 1;
    }}
    return out;
}}
static inline uint8_t velk_aes_inverse(uint8_t x) {{
    uint8_t out = 1;
    for (unsigned power = 254; power; power >>= 1) {{
        if (power & 1) out = velk_aes_multiply(out, x);
        x = velk_aes_multiply(x, x);
    }}
    return out;
}}
#endif
#ifndef VELK_{name}
#define VELK_{name}
static inline uint64_t {name}(uint64_t a, uint64_t b, uint64_t c, uint64_t d) {{
    uint8_t bytes[16], shifted[16], result[16];
    const uint8_t matrix[4][4] = {{{matrix}}};
    for (unsigned i = 0; i < 16; ++i) bytes[i] = (uint8_t)((i < 8 ? a : b) >> ((i % 8) * 8));
    for (unsigned column = 0; column < 4; ++column) {{
        for (unsigned row = 0; row < 4; ++row) {{
            unsigned from = {from};
            uint8_t x = bytes[row + 4 * from];
            {substitution}
            shifted[row + 4 * column] = x;
        }}
    }}
    for (unsigned column = 0; column < 4; ++column) {{
        for (unsigned row = 0; row < 4; ++row) {{
            uint8_t x = shifted[row + 4 * column];
            if ({mix}) {{
                x = 0;
                for (unsigned term = 0; term < 4; ++term) x ^= velk_aes_multiply(matrix[row][term], shifted[term + 4 * column]);
            }}
            result[row + 4 * column] = x;
        }}
    }}
    uint64_t out = 0;
    for (unsigned i = 0; i < 8; ++i) out |= (uint64_t)result[{start} + i] << (i * 8);
    return out ^ {key};
}}
#endif

"#,
        from = if !substitute {
            "column"
        } else if decrypt {
            "(column + 4 - row) % 4"
        } else {
            "(column + row) % 4"
        },
        substitution = if substitute { substitute_byte } else { "" },
        mix = u8::from(mix),
        start = if high { 8 } else { 0 },
        key = if high { "d" } else { "c" }
    )
}
