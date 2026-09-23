from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable, Optional
from .policy import evaluate
from .purpose import infer_purpose, pqc_family_for
from .rules import KEY_SIZE_RE, RULES

TEXT_EXTENSIONS = {".c",".h",".cc",".cpp",".hpp",".py",".java",".rs",".go",".js",".ts",".json",".yaml",".yml",".xml",".conf",".ini",".toml",".md"}

@dataclass(frozen=True)
class CryptoAsset:
    name: str
    category: str
    file: str
    line: int
    evidence: str
    key_size: Optional[int]
    status: str
    quantum_vulnerable: bool
    pqc_migration_review: bool
    migration_family: Optional[str]
    confidence: str
    purpose: Optional[str]
    purpose_confidence: Optional[str]
    severity: str
    policy_reason: str
    migration_priority: str

    def to_dict(self):
        return asdict(self)

Finding = CryptoAsset

def candidate_files(root: Path) -> Iterable[Path]:
    if root.is_file():
        yield root
        return
    for path in root.rglob("*"):
        if path.is_file() and path.suffix.lower() in TEXT_EXTENSIONS and ".git" not in path.parts:
            yield path

def _key_size(line: str, category: str) -> Optional[int]:
    if category not in {"public-key", "symmetric", "hash"}:
        return None
    match = KEY_SIZE_RE.search(line)
    return int(match.group(1)) if match else None

def _confidence(line: str, category: str) -> str:
    lower=line.lower()
    if category == "crypto-library" or any(token in lower for token in ("evp_", "#include", "ssl_", "rsa_", "ecdsa_", "ecdh_")):
        return "high"
    if "=" in line or '"' in line or "'" in line:
        return "medium"
    return "low"

def _context(lines, index, radius=3):
    start=max(0,index-radius)
    end=min(len(lines),index+radius+1)
    return "\n".join(lines[start:end])

def scan(root: Path):
    findings=[]
    for path in candidate_files(root):
        try:
            lines=path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue
        for index,line in enumerate(lines):
            number=index+1
            context=_context(lines,index)
            purpose_match=infer_purpose(context)
            for rule in RULES:
                if rule.pattern.search(line):
                    key_size=_key_size(line,rule.category)
                    purpose=purpose_match.purpose if purpose_match else None
                    migration=pqc_family_for(purpose) if rule.quantum_vulnerable else None
                    if migration is None:
                        migration=rule.migration_family
                    policy=evaluate(rule.name,rule.status,key_size,rule.quantum_vulnerable,purpose)
                    findings.append(CryptoAsset(
                        name=rule.name, category=rule.category, file=str(path), line=number,
                        evidence=line.strip()[:240], key_size=key_size, status=rule.status,
                        quantum_vulnerable=rule.quantum_vulnerable,
                        pqc_migration_review=rule.quantum_vulnerable,
                        migration_family=migration, confidence=_confidence(line,rule.category),
                        purpose=purpose, purpose_confidence=purpose_match.confidence if purpose_match else None,
                        severity=policy.severity, policy_reason=policy.reason,
                        migration_priority=policy.migration_priority,
                    ))
    return findings
