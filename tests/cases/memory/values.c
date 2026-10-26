#include "constants.inc"

struct sample {
    unsigned char tag;
    signed short value;
    unsigned int words[3];
};
const struct sample record = { 7, -1234, { 0x12345678, 9, 10 } };
unsigned int zero_values[4];
const char greeting[] = "byte search example";
const unsigned short wide_greeting[] = { 'b', 'y', 't', 'e', 0xd83d, 0xde00, 0 };
const unsigned char wildcard_bytes[] = { 0x48, 0x8b, 0x91, 0x24 };
const unsigned long long large_integer = 0xfedcba9876543210ULL;
const float single_value = 1.5f;
const double double_value = -2.5;
const char *const text_pointer = greeting;

unsigned int table_byte(unsigned int index) { return substitution[index & 255]; }
unsigned int read_record(const struct sample *p) { return p->words[0] + p->tag; }
unsigned int mix_delta(unsigned int value) { return value ^ 0x9e3779b9U; }
unsigned int use_tables(unsigned int index) {
    return round_words[index & 63] ^ checksum_words[index & 255]
        ^ alphabet[index % 64] ^ lengths[index % 29];
}
