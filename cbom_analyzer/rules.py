import re

RULES = [
    ("AES", "symmetric", False, re.compile(r"\\bAES(?:[-_ ]?(?:128|192|256))?\\b", re.I)),
    ("RSA", "public-key", True, re.compile(r"\\bRSA(?:[-_ ]?(?:2048|3072|4096))?\\b", re.I)),
    ("ECC", "public-key", True, re.compile(r"\\b(?:ECC|ECDSA|ECDH|P-256|P-384|secp256r1)\\b", re.I)),
    ("SHA-1", "hash", False, re.compile(r"\\bSHA[-_ ]?1\\b", re.I)),
    ("SHA-2", "hash", False, re.compile(r"\\bSHA[-_ ]?(?:224|256|384|512)\\b", re.I)),
    ("TLS", "protocol", False, re.compile(r"\\bTLS(?:v?1\\.[0-3])?\\b", re.I)),
    ("OpenSSL", "crypto-library", False, re.compile(r"\\bOpenSSL\\b|#\\s*include\\s*[<\"]openssl/", re.I)),
]
