# CBOM & Crypto-Agility Analyzer

An explainable product-security tool for discovering cryptographic assets, generating a CycloneDX CBOM, and planning crypto-agility / post-quantum migration.

## What it discovers

- Cryptographic algorithms, protocols and libraries in source/configuration
- Key sizes and source evidence
- Cryptographic purpose such as signing, verification, key establishment, encryption and hashing
- PEM certificates and key-material presence without exporting private-key contents
- Hardware/service crypto integrations including TPM2/TSS, PKCS#11, OP-TEE, Linux keyrings and selected KMS patterns
- Relationships between algorithms, keys, certificates and crypto backends
- Quantum-vulnerable public-key usage and migration constraints

## Outputs

The analyzer can produce:

- JSON crypto inventory with evidence, policy results and relationships
- CSV findings
- CycloneDX 1.7 CBOM JSON
- PQC migration roadmap with priority, complexity, drivers and engineering actions

## Install

Requires Python 3.10 or later and has no third-party runtime dependencies.

```bash
git clone https://github.com/Shevagar/cbom-crypto-agility-analyzer.git
cd cbom-crypto-agility-analyzer
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
```

## Run

```bash
cbom-analyzer scan examples/sample_product \
  --json crypto-inventory.json \
  --csv findings.csv \
  --cyclonedx product.cdx.json \
  --roadmap pqc-roadmap.json
```

You can also run without installation:

```bash
python3 -m cbom_analyzer scan examples/sample_product --json crypto-inventory.json
```

## Architecture

```text
Source / Config / Certificates / Key Material
                    |
              Discovery Engines
       algorithms | certs | keys | backends
                    |
              Crypto Asset Model
                    |
          Purpose + Policy Analysis
                    |
               Correlation
                    |
       +------------+-------------+
       |                          |
 CycloneDX CBOM             PQC Assessment
                                  |
                         Migration Roadmap
```

## PQC migration analysis

The tool does not blindly map every RSA/ECC occurrence to a replacement. It first attempts to establish cryptographic purpose and backend constraints. Signature use can be evaluated against signature-oriented PQC families, while key-establishment use can be evaluated against KEM-oriented migration options.

Migration complexity is separate from security severity. Hardware-backed keys, provider/API support, provisioning, certificates, firmware formats, protocol message sizes, memory and interoperability can all affect engineering effort.

## Evidence and confidence

This project favors explicit uncertainty over unsupported conclusions. For example:

- finding a TPM API is evidence of a TPM integration point, not proof of a runtime key's attributes
- colocated certificate and key files are only a potential association until their public keys are cryptographically matched
- a PQC candidate family is a planning input, not an automatic drop-in replacement

## Test

```bash
python -m unittest discover -s tests -v
```

GitHub Actions tests the project on supported Python versions.

## Documentation

- `docs/crypto-asset-model.md`
- `docs/key-certificate-discovery.md`
- `docs/hardware-backed-crypto.md`
- `docs/correlation-and-migration.md`
- `docs/pqc-migration-roadmap.md`

## Scope

This is a discovery, triage and migration-planning tool. It is not a cryptographic verifier, compliance certification tool, or substitute for expert review. Static evidence can contain false positives and does not prove runtime behavior.

All examples are fictional and contain no employer or customer material. See `SECURITY.md`.

## Roadmap

Next engineering milestones include configurable policy profiles, schema validation, richer X.509/DER/PKCS#12 parsing, cryptographic certificate/key matching, dependency/package detection, binary adapters, CI policy gates and additional TPM/PKCS#11/provider metadata.

## License

MIT
