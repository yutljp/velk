unsigned char initialized_byte = 0x7b;
unsigned char zero_tail[2048];

unsigned int read_tail(unsigned int index) {
    return initialized_byte + zero_tail[index & 2047];
}

#pragma section(".tail", read)
__declspec(allocate(".tail")) const unsigned char following_bytes[4096] = {0xa5};
