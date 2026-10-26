#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>
#include <psa/crypto.h>
int main(void) {
    mbedtls_ssl_context ssl; mbedtls_x509_crt certificate;
    unsigned char hash[64]; size_t length = 0;
    mbedtls_ssl_init(&ssl); mbedtls_x509_crt_init(&certificate);
    if (psa_crypto_init() != PSA_SUCCESS) return 1;
    psa_status_t result = psa_hash_compute(PSA_ALG_SHA_256, (const unsigned char *)"abc", 3, hash, sizeof(hash), &length);
    mbedtls_x509_crt_free(&certificate); mbedtls_ssl_free(&ssl);
    return result != PSA_SUCCESS || length != 32 || hash[0] != 0xba;
}
