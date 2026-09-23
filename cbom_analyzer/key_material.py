import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional

KEY_PATTERNS=[
    ("private-key", re.compile(r"-----BEGIN (?:RSA |EC |ENCRYPTED )?PRIVATE KEY-----")),
    ("public-key", re.compile(r"-----BEGIN PUBLIC KEY-----")),
]

@dataclass(frozen=True)
class KeyMaterialAsset:
    file: str
    material_type: str
    encrypted: bool
    algorithm_hint: Optional[str]
    exposure: str
    confidence: str = "high"

    def to_dict(self):
        return asdict(self)

def scan_key_material(root: Path):
    paths=[root] if root.is_file() else list(root.rglob("*"))
    assets=[]
    for path in paths:
        if not path.is_file() or path.suffix.lower() not in {".pem",".key",".pub"}:
            continue
        try:
            text=path.read_text(encoding="utf-8",errors="ignore")
        except OSError:
            continue
        for material_type,pattern in KEY_PATTERNS:
            match=pattern.search(text)
            if not match:
                continue
            header=match.group(0).upper()
            encrypted="ENCRYPTED" in header
            algorithm="RSA" if "RSA " in header else ("EC" if "EC " in header else None)
            exposure="private-key-material" if material_type=="private-key" else "public-material"
            assets.append(KeyMaterialAsset(str(path),material_type,encrypted,algorithm,exposure))
            break
    return assets
