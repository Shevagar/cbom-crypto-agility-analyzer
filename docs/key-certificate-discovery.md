# Key and Certificate Discovery

The analyzer treats keys and certificates as first-class cryptographic assets rather than ordinary text findings.

## Safety principle

Private-key contents are never emitted into reports. Discovery records only metadata such as file location, material type, encryption indication and an algorithm hint available from the PEM header.

## Certificate discovery

PEM certificates in .pem, .crt and .cer files are detected. Where the Python runtime can decode the certificate, the analyzer records subject, issuer, serial number, validity dates and expiry status.

The standard-library decoder does not expose all public-key and signature metadata consistently. Those fields remain explicitly unknown rather than being guessed. A future parser adapter can add richer X.509 metadata.

## Key discovery

PEM public/private-key headers are identified without decoding or copying key material. Private-key presence in a scanned repository is intentionally highlighted because source-tree key material deserves explicit security review.

## Planned adapters

- DER certificate parsing
- PKCS#12 metadata
- OpenSSL command adapter
- TPM object/public-area metadata
- PKCS#11 / secure-element references
- certificate-to-key and component relationships
