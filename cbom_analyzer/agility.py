from dataclasses import asdict, dataclass
from typing import Optional

@dataclass(frozen=True)
class MigrationAssessment:
    asset: str
    algorithm: str
    purpose: Optional[str]
    backend: str
    candidate_family: Optional[str]
    migration_priority: str
    complexity: str
    confidence: str
    drivers: tuple
    actions: tuple

    def to_dict(self):
        data=asdict(self)
        data["drivers"]=list(self.drivers)
        data["actions"]=list(self.actions)
        return data

def _backend_for(asset,relationships):
    source=f"{asset.name}@{asset.file}:{asset.line}"
    for r in relationships:
        if r.source==source and r.relationship=="implemented-via":
            return r.target.split("@",1)[0]
    return "unknown"

def _complexity(asset,backend):
    factors=0
    if backend!="unknown": factors+=2
    if asset.purpose is None: factors+=1
    if asset.key_size is not None: factors+=1
    if asset.purpose in {"digital-signature","signature-verification","key-establishment"}: factors+=1
    return "high" if factors>=4 else ("medium" if factors>=2 else "low")

def assess_migration(findings,relationships):
    results=[]
    for asset in findings:
        if not asset.quantum_vulnerable:
            continue
        backend=_backend_for(asset,relationships)
        drivers=["quantum-vulnerable public-key cryptography"]
        actions=[]
        if asset.purpose:
            drivers.append(f"cryptographic purpose: {asset.purpose}")
        else:
            drivers.append("cryptographic purpose not established")
            actions.append("Confirm whether the primitive is used for signatures, key establishment, encryption, or another purpose.")
        if backend!="unknown":
            drivers.append(f"backend dependency: {backend}")
            actions.append(f"Verify {backend} support for the target PQC algorithm/mechanism and required key sizes.")
            actions.append("Review provisioning, storage, rotation, update, recovery and decommissioning impacts.")
        else:
            actions.append("Identify the crypto provider and key-storage boundary before selecting a migration design.")
        if asset.migration_family:
            actions.append(f"Evaluate {asset.migration_family} for this use case; do not treat this as an automatic drop-in replacement.")
        if asset.purpose in {"digital-signature","signature-verification"}:
            actions.append("Assess signature/public-key size impact on firmware images, boot chain, certificates, protocols and constrained storage.")
        if asset.purpose=="key-establishment":
            actions.append("Assess handshake/message-size, latency, memory and interoperability impact across both endpoints.")
        results.append(MigrationAssessment(
            asset=f"{asset.name}@{asset.file}:{asset.line}",algorithm=asset.name,purpose=asset.purpose,
            backend=backend,candidate_family=asset.migration_family,migration_priority=asset.migration_priority,
            complexity=_complexity(asset,backend),confidence=asset.purpose_confidence or asset.confidence,
            drivers=tuple(drivers),actions=tuple(dict.fromkeys(actions))))
    return results

def build_roadmap(assessments):
    order={"immediate":0,"high":1,"planned":2,"review":3,"none":4}
    complexity={"high":0,"medium":1,"low":2}
    return sorted((x.to_dict() for x in assessments),
                  key=lambda x:(order.get(x["migration_priority"],9),complexity.get(x["complexity"],9),x["asset"]))
