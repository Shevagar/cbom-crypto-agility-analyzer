#include <openssl/evp.h>

/* Fictional examples used by scanner tests/demos. */
const char *legacy_digest = "SHA-1";
const char *deprecated_digest = "MD5";
const char *device_identity = "ECDSA P-256";
const char *storage_cipher = "AES-256";

void configure_digest(void) {
    EVP_sha256();
}
