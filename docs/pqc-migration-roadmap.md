# PQC Migration Roadmap

The roadmap is not a generic security score. It is an evidence-driven planning view for cryptographic assets already identified as requiring quantum-migration review.

## Dimensions

Each migration assessment records:

- algorithm and cryptographic purpose
- correlated crypto backend
- candidate standardized PQC family
- migration priority inherited from policy
- migration complexity derived from observable dependency factors
- evidence confidence
- concrete migration drivers and engineering actions

## Complexity

Complexity is intentionally separate from severity. A cryptographic primitive may require migration while the engineering effort differs substantially depending on hardware-backed keys, known purpose, parameter/key-size dependencies and protocol or signature constraints.

## Engineering guidance

Signature migrations call out boot-chain, firmware image, certificate, protocol and constrained-storage impacts. Key-establishment migrations call out handshake/message size, latency, memory and endpoint interoperability.

Candidate PQC families are planning inputs, not automatic replacements. Protocol profiles, hardware/provider support, standards requirements, interoperability and product constraints must be evaluated before migration.
