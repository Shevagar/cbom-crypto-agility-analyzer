# Hardware-Backed Crypto Discovery

The analyzer can identify source-level evidence of cryptographic backends including TPM2/TSS, PKCS#11 tokens, OP-TEE, Linux keyrings and selected cloud-KMS API patterns.

Each observation records the backend, source location, operation, inferred key-location class, exportability knowledge and confidence.

## Important distinction

Detection of an API is evidence of an integration point, not proof that a particular runtime key is hardware protected. The analyzer therefore uses terms such as hardware-backed or token-backed for the observed backend and leaves exportability unknown unless evidence supports a stronger conclusion.

## Why this matters for crypto agility

Replacing an algorithm is only one part of migration. Hardware and service boundaries may constrain supported algorithms, key formats, provisioning, attestation, certificate enrollment and update strategy. Hardware-backend observations therefore become inputs to later migration-constraint analysis.
