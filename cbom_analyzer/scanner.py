from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable, Optional
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

def scan(root: Path):
    findings=[]
    for path in candidate_files(root):
        try:
            lines=path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue
        for number,line in enumerate(lines,1):
            for rule in RULES:
                if rule.pattern.search(line):
                    findings.append(CryptoAsset(
                        name=rule.name, category=rule.category, file=str(path), line=number,
                        evidence=line.strip()[:240], key_size=_key_size(line, rule.category),
                        status=rule.status, quantum_vulnerable=rule.quantum_vulnerable,
                        pqc_migration_review=rule.quantum_vulnerable,
                        migration_family=rule.migration_family,
                        confidence=_confidence(line, rule.category),
                    ))
    return findings
