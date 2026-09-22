#include <openssl/evp.h>
/* Fictional demonstration code: inventory should identify RSA and AES-256. */
const char *signing_algorithm = "RSA-3072";
const char *data_algorithm = "AES-256";
const char *transport = "TLS1.3";
