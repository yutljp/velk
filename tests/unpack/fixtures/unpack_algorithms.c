extern int target(void);

#if defined(__aarch64__)
#define TARGET_LENGTH 16
static const unsigned char lz_bytes[] = {
    4, 0x1f, 0x20, 0x03, 0xd5, 0x84, 4, 8,
    0x40, 0x05, 0x80, 0xd2, 0xc0, 0x03, 0x5f, 0xd6,
};
static const unsigned char two_stage_bytes[] = {
    0x5e, 0x45, 0x7a, 0x59, 0x8f, 0xde, 0x5e, 0x52,
    0x1a, 0x5f, 0xda, 0x88, 0x9a, 0x59, 0x05, 0x8c,
};
#else
#define TARGET_LENGTH 12
static const unsigned char lz_bytes[] = {
    2, 0x90, 0x90, 0x84, 2, 6, 0xb8, 0x2a, 0, 0, 0, 0xc3,
};
static const unsigned char two_stage_bytes[] = {
    0x58, 0xca, 0xca, 0xde, 0x58, 0x5c, 0xe2, 0x70,
    0x5a, 0x5a, 0x5a, 0x99,
};
#endif

static volatile unsigned char *target_data(void) {
  return (volatile unsigned char *)(unsigned long)target;
}

static void decode_rc4(void) {
  unsigned char state[256];
  unsigned int index;
  unsigned int other = 0;
  unsigned int i = 0;
  unsigned int j = 0;
  const unsigned char key[3] = {'k', 'e', 'y'};
  volatile unsigned char *output = target_data();

  for (index = 0; index < 256; index++) {
    state[index] = (unsigned char)index;
  }
  for (index = 0; index < 256; index++) {
    other = (other + state[index] + key[index % 3]) & 255;
    unsigned char temporary = state[index];
    state[index] = state[other];
    state[other] = temporary;
  }
  for (index = 0; index < TARGET_LENGTH; index++) {
    i = (i + 1) & 255;
    j = (j + state[i]) & 255;
    unsigned char temporary = state[i];
    state[i] = state[j];
    state[j] = temporary;
    output[index] ^= state[(state[i] + state[j]) & 255];
  }
}

static void decode_lz(const unsigned char *input, unsigned int input_length) {
  unsigned int input_index = 0;
  unsigned int output_index = 0;
  volatile unsigned char *output = target_data();

  while (input_index < input_length) {
    unsigned int token = input[input_index++];
    if ((token & 0x80) != 0) {
      unsigned int count = token & 0x7f;
      unsigned int distance = input[input_index++];
      while (count-- != 0) {
        output[output_index] = output[output_index - distance];
        output_index++;
      }
    } else {
      unsigned int count = token;
      while (count-- != 0) {
        output[output_index++] = input[input_index++];
      }
    }
  }
}

static void decode_two_stage(void) {
  unsigned char decoded[sizeof(two_stage_bytes)];
  unsigned int index;
  for (index = 0; index < sizeof(two_stage_bytes); index++) {
    decoded[index] = two_stage_bytes[index] ^ 0x5a;
  }
  decode_lz(decoded, sizeof(decoded));
}

void unpack(void) {
#if UNPACK_MODE == 1
  decode_rc4();
#elif UNPACK_MODE == 2
  decode_lz(lz_bytes, sizeof(lz_bytes));
#elif UNPACK_MODE == 3
  decode_two_stage();
#else
#error UNPACK_MODE must be 1, 2, or 3
#endif
  volatile int result = target();
  (void)result;
}

#if defined(__x86_64__) || defined(__i386__)
#if UNPACK_MODE == 1
#define TARGET_BYTES \
  ".byte 0x9b, 0xfc, 0xa4, 0x7d, 0xb4, 0x1f, 0xc3, 0x60, 0x48, 0x4b, 0x08, 0xb8\n"
#else
#define TARGET_BYTES ".zero 12\n"
#endif
__asm__(
    ".text\n"
    ".globl _start\n"
    ".type _start,@function\n"
    "_start:\n"
    "call unpack\n"
    "ud2\n"
    ".size _start,.-_start\n"
    ".balign 16\n"
    ".globl target\n"
    ".type target,@function\n"
    "target:\n"
    TARGET_BYTES
    ".size target,.-target\n");
#elif defined(__aarch64__)
#if UNPACK_MODE == 1
#define TARGET_BYTES \
  ".byte 0x14, 0x4c, 0x37, 0x38, 0x3b, 0xaf, 0x78, 0x9f, " \
  "0x08, 0x4e, 0x88, 0xa9, 0xd6, 0x5e, 0x4d, 0x2b\n"
#else
#define TARGET_BYTES ".zero 16\n"
#endif
__asm__(
    ".text\n"
    ".globl _start\n"
    ".type _start,%function\n"
    "_start:\n"
    "bl unpack\n"
    "brk #0\n"
    ".size _start,.-_start\n"
    ".balign 16\n"
    ".globl target\n"
    ".type target,%function\n"
    "target:\n"
    TARGET_BYTES
    ".size target,.-target\n");
#else
#error Unsupported target architecture
#endif
