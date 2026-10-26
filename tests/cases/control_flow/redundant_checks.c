#include <stdint.h>

struct effects {
    uint64_t value;
    unsigned calls;
};

static uint64_t call(struct effects *effects, uint64_t result) {
    effects->value = effects->value * 17u + result;
    ++effects->calls;
    return result;
}

/* The call result is unconstrained. No call occurs between the two tests. */
static uint64_t map_check(struct effects *effects, uint64_t input, int simplified) {
    uint64_t v24 = call(effects, input);
    if (v24 != 0) {
        if (!simplified && v24 == 0) {
            call(effects, 19);
        }
        return call(effects, v24 ^ 85u);
    }
    return 0;
}

/* The enclosing tests admit only zero at the removed branch. */
static uint64_t range_check(struct effects *effects, uint8_t input, int simplified) {
    uint8_t v11 = (uint8_t)call(effects, input);
    uint8_t v29 = 1;
    if (v11 <= 1) {
        if (v11 != v29) {
            if (!simplified && v11 != 0) {
                return call(effects, 19);
            }
            effects->value = 0;
            return 0;
        }
        return call(effects, 1);
    }
    return call(effects, 2);
}

/* The incoming paths to the demangler's check retain a length of at least two. */
static uint64_t length_check(struct effects *effects, uint64_t input, int simplified) {
    uint64_t v173 = call(effects, input);
    if (v173 < 2) {
        return 0;
    }
    uint8_t v124 = 2;
    if (v173 <= 2) {
        if (simplified || v173 == v124) {
            return call(effects, 2);
        }
        return call(effects, 19);
    }
    return call(effects, 3);
}

int main(void) {
    uint64_t seed = UINT64_C(0x8f4a7c159e3779b9);
    for (unsigned i = 0; i < 131072; ++i) {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        uint64_t input = i < 65536 ? i : seed;
        if (i < 64) {
            input = i & 1 ? UINT64_MAX - i / 2 : i / 2;
        }
        for (unsigned kind = 0; kind < 3; ++kind) {
            struct effects before = {seed, 0}, after = before;
            uint64_t a, b;
            if (kind == 0) {
                a = map_check(&before, input, 0);
                b = map_check(&after, input, 1);
            } else if (kind == 1) {
                a = range_check(&before, (uint8_t)input, 0);
                b = range_check(&after, (uint8_t)input, 1);
            } else {
                a = length_check(&before, input, 0);
                b = length_check(&after, input, 1);
            }
            if (a != b || before.value != after.value || before.calls != after.calls) {
                return 1;
            }
        }
    }
    return 0;
}
