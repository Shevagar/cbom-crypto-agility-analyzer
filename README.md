# CBOM & Crypto-Agility Analyzer

A lightweight, explainable tool for discovering cryptographic usage in source/configuration files and producing a machine-readable cryptographic inventory.

## Why this project
Crypto inventories are a prerequisite for crypto-agility and post-quantum migration planning. This project demonstrates how product-security teams can identify where cryptographic algorithms, protocols and key-size indicators appear in a codebase, then triage them for review.

## Capabilities
- Recursively scans source and configuration files
- Detects common cryptographic algorithms and protocols
- Records file, line, category and matched evidence
- Flags quantum-vulnerable public-key primitives for migration review
- Produces JSON and CSV reports
- Uses transparent rules rather than opaque scoring

> **Important:** This is a discovery/triage tool, not a cryptographic verifier, compliance certification tool, or substitute for expert review. Text matching can produce false positives and cannot prove runtime usage.

## Quick start

```bash
python3 -m cbom_analyzer scan examples/sample_product --json report.json --csv report.csv
```

No third-party runtime dependencies are required.

## Example finding

```json
{
  "algorithm": "RSA",
  "category": "public-key",
  "pqc_migration_review": true,
  "file": "examples/sample_product/security.c",
  "line": 4
}
```

## Architecture

```
Repository
   |
File discovery
   |
Rule-based crypto detector
   |
Normalized findings
   +--> JSON inventory
   +--> CSV inventory
   +--> PQC migration review queue
```

## Roadmap
- CycloneDX CBOM-compatible export
- Library/package-aware detection
- Binary inspection adapters
- Confidence/evidence model
- Crypto policy files
- Hybrid/PQC migration recommendations
- CI policy gate

## Security and scope
See [SECURITY.md](SECURITY.md). All examples are fictional and intentionally contain no employer or customer material.

## License
MIT
