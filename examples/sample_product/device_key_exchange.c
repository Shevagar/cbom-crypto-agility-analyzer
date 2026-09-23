#include <openssl/evp.h>

/* Fictional device key-establishment example for PQC migration analysis. */
const char *device_kex = "ECDH P-256";

int derive_session_key(EVP_PKEY_CTX *ctx, unsigned char *secret, size_t *secret_len) {
    return EVP_PKEY_derive(ctx, secret, secret_len);
}
