import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional

@dataclass(frozen=True)
class HardwareCryptoAsset:
    backend: str
    file: str
    line: int
    evidence: str
    operation: Optional[str]
    key_location: str
    exportability: str
    confidence: str

    def to_dict(self):
        return asdict(self)

RULES=[
    ("TPM2", re.compile(r"\b(?:tpm2_|Esys_|Tss2_|TPM2_|Fapi_)",re.I), "hardware-backed", "unknown"),
    ("PKCS#11", re.compile(r"\b(?:C_Initialize|C_OpenSession|C_FindObjects|C_Sign|C_Decrypt|C_GenerateKey|C_GenerateKeyPair|CKM_|PKCS#11)\b",re.I), "token-backed", "unknown"),
    ("OP-TEE", re.compile(r"\b(?:TEEC_|TEE_|OP-TEE|optee)\b",re.I), "trusted-execution-environment", "unknown"),
    ("Linux-keyring", re.compile(r"\b(?:keyctl|add_key|request_key)\b",re.I), "kernel-keyring", "unknown"),
    ("Cloud-KMS", re.compile(r"\b(?:kms:Sign|kms:Decrypt|KeyVault|CryptographyClient|cloudkms|KMSClient)\b",re.I), "remote-kms", "provider-controlled"),
]

OPERATIONS=[
    ("sign",re.compile(r"\b(?:Esys_Sign|Fapi_Sign|C_Sign|kms:Sign|SignAsync)\b",re.I)),
    ("decrypt",re.compile(r"\b(?:Esys_RSA_Decrypt|Fapi_Decrypt|C_Decrypt|kms:Decrypt|DecryptAsync)\b",re.I)),
    ("key-generation",re.compile(r"\b(?:Esys_Create|Fapi_CreateKey|C_GenerateKey|C_GenerateKeyPair|CreateKey)\b",re.I)),
    ("key-load",re.compile(r"\b(?:Esys_Load|Fapi_Load|C_FindObjects|keyctl|request_key)\b",re.I)),
]

def _operation(line):
    for name,pattern in OPERATIONS:
        if pattern.search(line): return name
    return None

def scan_hardware_crypto(root: Path):
    paths=[root] if root.is_file() else list(root.rglob("*"))
    assets=[]
    for path in paths:
        if not path.is_file() or path.suffix.lower() not in {".c",".h",".cc",".cpp",".py",".java",".rs",".go",".js",".ts",".conf",".ini",".yaml",".yml",".json",".md"}:
            continue
        try:
            lines=path.read_text(encoding="utf-8",errors="ignore").splitlines()
        except OSError:
            continue
        for number,line in enumerate(lines,1):
            for backend,pattern,location,exportability in RULES:
                if pattern.search(line):
                    assets.append(HardwareCryptoAsset(backend,str(path),number,line.strip()[:240],_operation(line),location,exportability,"high"))
    return assets
