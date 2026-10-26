#include <sodium.h>
#include <string.h>
int main(void) {
    unsigned char hash[64], key[32] = {0}, nonce[24] = {0}, out[128], recovered[64];
    const unsigned char message[] = "signature measurement";
    if (sodium_init() < 0) return 1;
    crypto_hash_sha256(hash, message, sizeof(message));
    crypto_hash_sha512(hash, message, sizeof(message));
    crypto_generichash(hash, 32, message, sizeof(message), key, sizeof(key));
    if (crypto_secretbox_easy(out, message, sizeof(message), nonce, key) != 0) return 2;
    if (crypto_secretbox_open_easy(recovered, out, sizeof(message) + crypto_secretbox_MACBYTES, nonce, key) != 0) return 3;
    return sodium_memcmp(message, recovered, sizeof(message));
}
