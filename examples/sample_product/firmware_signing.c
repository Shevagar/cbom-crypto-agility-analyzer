#include <openssl/evp.h>

/* Fictional firmware-signing example for purpose inference. */
const char *firmware_signing_key = "RSA-3072";

int sign_firmware(EVP_MD_CTX *ctx, EVP_PKEY *key) {
    return EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, key);
}
