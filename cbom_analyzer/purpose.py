import re
from dataclasses import dataclass
from typing import Optional

@dataclass(frozen=True)
class PurposeMatch:
    purpose: str
    confidence: str
    evidence: str

PURPOSE_RULES = [
    ("digital-signature", "high", re.compile(r"EVP_(?:Digest)?Sign|RSA_sign|ECDSA_sign|verify_signature|firmware_sign", re.I)),
    ("signature-verification", "high", re.compile(r"EVP_(?:Digest)?Verify|RSA_verify|ECDSA_verify|verify_signature|signature_verify", re.I)),
    ("key-establishment", "high", re.compile(r"EVP_PKEY_derive|ECDH_compute_key|key[_ -]?agreement|key[_ -]?exchange", re.I)),
    ("encryption", "high", re.compile(r"EVP_Encrypt|EVP_Seal|RSA_public_encrypt|encrypt(?:ion)?", re.I)),
    ("decryption", "high", re.compile(r"EVP_Decrypt|EVP_Open|RSA_private_decrypt|decrypt(?:ion)?", re.I)),
    ("hashing", "high", re.compile(r"EVP_Digest|SHA(?:1|224|256|384|512)|MD5", re.I)),
    ("transport-security", "high", re.compile(r"TLS_|SSL_|mTLS|TLSv?1\.[0-3]", re.I)),
]

def infer_purpose(context: str) -> Optional[PurposeMatch]:
    for purpose, confidence, pattern in PURPOSE_RULES:
        match=pattern.search(context)
        if match:
            return PurposeMatch(purpose, confidence, match.group(0))
    return None

def pqc_family_for(purpose: Optional[str]) -> Optional[str]:
    if purpose in {"digital-signature", "signature-verification"}:
        return "ML-DSA / SLH-DSA"
    if purpose == "key-establishment":
        return "ML-KEM"
    return None
