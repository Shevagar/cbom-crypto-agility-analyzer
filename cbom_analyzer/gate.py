import json
from dataclasses import asdict, dataclass
from pathlib import Path

DEFAULT_POLICY={
    "fail_on_severity":["critical"],
    "fail_on_algorithms":["MD5","SHA-1","DES"],
    "fail_on_private_key_material":True,
    "warn_on_quantum_vulnerable":True,
}

@dataclass(frozen=True)
class GateViolation:
    level: str
    rule: str
    asset: str
    reason: str
    def to_dict(self): return asdict(self)

def load_policy(path=None):
    policy=dict(DEFAULT_POLICY)
    if path:
        supplied=json.loads(Path(path).read_text(encoding="utf-8"))
        unknown=set(supplied)-set(DEFAULT_POLICY)
        if unknown: raise ValueError("Unknown policy keys: "+", ".join(sorted(unknown)))
        policy.update(supplied)
    return policy

def evaluate_gate(findings,keys,policy):
    violations=[]
    for f in findings:
        asset=f"{f.name}@{f.file}:{f.line}"
        if f.name in policy["fail_on_algorithms"]:
            violations.append(GateViolation("fail","algorithm",asset,f"{f.name} is denied by policy."))
        elif f.severity in policy["fail_on_severity"]:
            violations.append(GateViolation("fail","severity",asset,f"Severity {f.severity} meets the policy failure threshold."))
        elif policy["warn_on_quantum_vulnerable"] and f.quantum_vulnerable:
            violations.append(GateViolation("warn","quantum-migration",asset,"Quantum-vulnerable public-key cryptography requires migration review."))
    if policy["fail_on_private_key_material"]:
        for k in keys:
            if k.material_type=="private-key":
                violations.append(GateViolation("fail","private-key-material",k.file,"Private-key material was detected in the scanned tree."))
    return violations

def gate_passed(violations):
    return not any(v.level=="fail" for v in violations)
