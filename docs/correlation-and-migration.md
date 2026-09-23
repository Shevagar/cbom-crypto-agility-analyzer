# Correlation and Migration Constraints

Detection alone creates a list. Correlation turns that list into an architecture view.

The correlation engine links observations only when evidence supports a relationship. Current rules are intentionally conservative:

- algorithm and hardware-backend observations within a small source-code window: high-confidence `implemented-via`
- algorithm and key material in the same file: medium-confidence `associated-with`
- certificate and key files in the same directory: low-confidence `potential-key-association`

A low-confidence certificate/key relationship is **not** a cryptographic key match. Future adapters can compare certificate public keys with private/public key material safely.

For quantum-vulnerable algorithms, correlated backends produce migration constraints. A TPM-, PKCS#11-, TEE- or KMS-backed asset requires more than an algorithm replacement: provider support, API/mechanism compatibility, provisioning, lifecycle, certificate/profile and deployment impacts may need assessment.

The engine reports unknown backend state rather than assuming software or hardware storage.
