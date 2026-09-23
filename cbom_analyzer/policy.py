from dataclasses import dataclass
from typing import Optional

@dataclass(frozen=True)
class PolicyResult:
    severity: str
    reason: str
    migration_priority: str

def evaluate(name: str, status: str, key_size: Optional[int], quantum_vulnerable: bool, purpose: Optional[str]) -> PolicyResult:
    if name == "MD5":
        return PolicyResult("high", "Deprecated hash detected.", "immediate")
    if name == "SHA-1":
        return PolicyResult("high", "Legacy hash requires use-case review and migration.", "high")
    if name == "DES":
        return PolicyResult("high", "Legacy symmetric cipher family detected.", "immediate")
    if name == "RSA" and key_size is not None and key_size < 2048:
        return PolicyResult("critical", "RSA key size below 2048 bits detected.", "immediate")
    if quantum_vulnerable:
        detail = f" for {purpose}" if purpose else ""
        return PolicyResult("medium", f"Quantum-vulnerable public-key cryptography detected{detail}.", "planned")
    if status == "acceptable":
        return PolicyResult("info", "No rule-based migration issue identified from available evidence.", "none")
    return PolicyResult("low", "Cryptographic usage requires contextual review.", "review")
