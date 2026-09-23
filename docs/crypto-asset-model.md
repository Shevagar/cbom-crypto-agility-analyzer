# Crypto Asset Model

v0.2 separates observation from security judgment.

## Observation
- `name`: normalized primitive, library, or protocol
- `category`: public-key, symmetric, hash, protocol, or crypto-library
- `file` / `line`: evidence location
- `evidence`: bounded source excerpt
- `key_size`: size visible in the same evidence line
- `confidence`: evidence-strength hint, not a security score

## Assessment
- `status`: initial triage state
- `quantum_vulnerable`: public-key family requires quantum-migration planning
- `pqc_migration_review`: explicit review-queue flag
- `migration_family`: candidate PQC family when purpose permits

## Principle
The scanner must not infer more than evidence supports. Seeing RSA alone does not establish whether it is used for signatures or key establishment, so v0.2 queues it for migration review rather than choosing one replacement.
