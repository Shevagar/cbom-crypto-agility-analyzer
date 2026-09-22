from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable
from .rules import RULES

TEXT_EXTENSIONS = {".c",".h",".cc",".cpp",".hpp",".py",".java",".rs",".go",".js",".ts",".json",".yaml",".yml",".xml",".conf",".ini",".toml",".md"}

@dataclass(frozen=True)
class Finding:
    algorithm: str
    category: str
    pqc_migration_review: bool
    file: str
    line: int
    evidence: str

    def to_dict(self):
        return asdict(self)

def candidate_files(root: Path) -> Iterable[Path]:
    if root.is_file():
        yield root
        return
    for path in root.rglob("*"):
        if path.is_file() and path.suffix.lower() in TEXT_EXTENSIONS and ".git" not in path.parts:
            yield path

def scan(root: Path):
    findings=[]
    for path in candidate_files(root):
        try:
            lines=path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue
        for number,line in enumerate(lines,1):
            for name,category,pqc,pattern in RULES:
                if pattern.search(line):
                    findings.append(Finding(name,category,pqc,str(path),number,line.strip()[:240]))
    return findings
