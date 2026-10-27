#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <string.h>
int main(void) {
    unsigned char hash[64], key[16] = {0}, input[16] = {0}, encrypted[16], recovered[16];
    AES_KEY encrypt, decrypt;
    SHA256((const unsigned char *)"abc", 3, hash);
    SHA512((const unsigned char *)"abc", 3, hash);
    if (AES_set_encrypt_key(key, 128, &encrypt) || AES_set_decrypt_key(key, 128, &decrypt)) return 1;
    AES_encrypt(input, encrypted, &encrypt); AES_decrypt(encrypted, recovered, &decrypt);
    EVP_MD_CTX *ctx = EVP_MD_CTX_new(); if (!ctx) return 2;
    unsigned int length = 0;
    int digest_succeeded = EVP_DigestInit_ex(ctx, EVP_sha256(), 0) && EVP_DigestUpdate(ctx, "abc", 3) && EVP_DigestFinal_ex(ctx, hash, &length);
    EVP_MD_CTX_free(ctx);
    return !digest_succeeded || length != 32 || hash[0] != 0xba || memcmp(input, recovered, sizeof(input));
}
