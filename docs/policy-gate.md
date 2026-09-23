# Configurable Crypto Policy Gate

The policy gate turns discovery results into a CI-friendly pass/fail decision while keeping inventory and migration analysis separate from enforcement.

The default policy fails on explicitly denied legacy algorithms, critical findings and private-key material in the scanned tree. Quantum-vulnerable public-key findings are warnings by default so teams can inventory and plan migration without automatically breaking every existing build.

Use `policy.example.json` as a starting point. Supported keys are intentionally small and validated; unknown keys are rejected rather than silently ignored.

Example:

```bash
cbom-analyzer scan . --policy policy.example.json --gate
echo $?
```

Exit code 0 means no policy failure. Exit code 2 means the crypto policy gate failed. Warnings remain visible in JSON output and terminal output but do not fail the gate unless a future/custom policy explicitly promotes them.
