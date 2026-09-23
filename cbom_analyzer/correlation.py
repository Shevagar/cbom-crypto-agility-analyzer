from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional

@dataclass(frozen=True)
class CryptoRelationship:
    source_type: str
    source: str
    relationship: str
    target_type: str
    target: str
    confidence: str
    reason: str

    def to_dict(self):
        return asdict(self)

def _same_file(a,b):
    return Path(a).as_posix()==Path(b).as_posix()

def _near(line_a,line_b,distance=8):
    return line_a is not None and line_b is not None and abs(line_a-line_b)<=distance

def correlate(findings,certificates,keys,hardware):
    relationships=[]
    for f in findings:
        for h in hardware:
            if _same_file(f.file,h.file) and _near(f.line,h.line):
                relationships.append(CryptoRelationship(
                    "algorithm",f"{f.name}@{f.file}:{f.line}","implemented-via",
                    "crypto-backend",f"{h.backend}@{h.file}:{h.line}","high",
                    "Algorithm and backend evidence occur in the same local source context."))
        for k in keys:
            if _same_file(f.file,k.file):
                relationships.append(CryptoRelationship(
                    "algorithm",f"{f.name}@{f.file}:{f.line}","associated-with",
                    "key-material",k.file,"medium",
                    "Algorithm evidence and key material share a file; manual confirmation required."))
    for c in certificates:
        for k in keys:
            if Path(c.file).parent==Path(k.file).parent:
                relationships.append(CryptoRelationship(
                    "certificate",c.file,"potential-key-association",
                    "key-material",k.file,"low",
                    "Certificate and key material are colocated; cryptographic matching was not performed."))
    return relationships

def migration_constraints(findings,hardware,relationships):
    constraints=[]
    for f in findings:
        if not f.quantum_vulnerable:
            continue
        related=[r for r in relationships if r.source_type=="algorithm" and r.source==f"{f.name}@{f.file}:{f.line}" and r.target_type=="crypto-backend"]
        if related:
            for r in related:
                backend=r.target.split("@",1)[0]
                constraints.append({
                    "asset":r.source,"backend":backend,"priority":f.migration_priority,
                    "constraint":f"PQC migration must verify {backend} support, key provisioning, API/mechanism compatibility and lifecycle impact.",
                    "candidate_family":f.migration_family,
                })
        else:
            constraints.append({
                "asset":f"{f.name}@{f.file}:{f.line}","backend":"unknown","priority":f.migration_priority,
                "constraint":"Crypto backend is not correlated; identify key storage/provider before migration planning.",
                "candidate_family":f.migration_family,
            })
    return constraints
