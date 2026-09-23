import re
from dataclasses import dataclass
from typing import Optional, Pattern

@dataclass(frozen=True)
class CryptoRule:
    name: str
    category: str
    pattern: Pattern[str]
    quantum_vulnerable: bool = False
    status: str = "review"
    migration_family: Optional[str] = None

RULES = [
    CryptoRule("AES", "symmetric", re.compile(r"\bAES(?:[-_ ]?(?:128|192|256))?\b|EVP_aes_(?:128|192|256)(?:_[a-z0-9]+)?", re.I), status="acceptable"),
    CryptoRule("DES", "symmetric", re.compile(r"\b(?:3DES|Triple[-_ ]?DES|DES)\b", re.I), status="legacy"),
    CryptoRule("RSA", "public-key", re.compile(r"\bRSA(?:[-_ ]?(?:1024|2048|3072|4096))?\b|RSA_(?:new|generate_key_ex|set0_key)|EVP_PKEY_RSA", re.I), True, "migration-review", "ML-DSA or ML-KEM depending on use"),
    CryptoRule("ECC", "public-key", re.compile(r"\b(?:ECC|ECDSA(?:[-_ ]?P[-_ ]?(?:256|384))?|ECDH(?:[-_ ]?P[-_ ]?(?:256|384))?|P[-_ ]?(?:256|384)|secp256r1|prime256v1)\b|EVP_PKEY_EC", re.I), True, "migration-review", "ML-DSA or ML-KEM depending on use"),
    CryptoRule("DSA", "public-key", re.compile(r"\bDSA(?:[-_ ]?(?:1024|2048|3072))?\b", re.I), True, "legacy", "ML-DSA"),
    CryptoRule("MD5", "hash", re.compile(r"\bMD5\b|EVP_md5", re.I), status="deprecated"),
    CryptoRule("SHA-1", "hash", re.compile(r"\bSHA[-_ ]?1\b|EVP_sha1", re.I), status="legacy"),
    CryptoRule("SHA-2", "hash", re.compile(r"\bSHA[-_ ]?(?:224|256|384|512)\b|EVP_sha(?:224|256|384|512)", re.I), status="acceptable"),
    CryptoRule("TLS", "protocol", re.compile(r"\bTLS(?:v?1\.[0-3])?\b|TLS_(?:client|server)_method", re.I)),
    CryptoRule("OpenSSL", "crypto-library", re.compile(r"\bOpenSSL\b|#\s*include\s*[<\"]openssl/", re.I)),
    CryptoRule("mbedTLS", "crypto-library", re.compile(r"\bmbedTLS\b|#\s*include\s*[<\"]mbedtls/", re.I)),
    CryptoRule("wolfSSL", "crypto-library", re.compile(r"\bwolfSSL\b|#\s*include\s*[<\"]wolfssl/", re.I)),
    CryptoRule("libsodium", "crypto-library", re.compile(r"\blibsodium\b|#\s*include\s*[<\"]sodium\.h", re.I)),
]

KEY_SIZE_RE = re.compile(r"(?<!\d)(1024|2048|3072|4096|128|192|256|384|512)(?!\d)")
