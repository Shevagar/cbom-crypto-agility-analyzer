import re
import ssl
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

PEM_CERT_RE=re.compile(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",re.S)

@dataclass(frozen=True)
class CertificateAsset:
    file: str
    subject: Optional[str]
    issuer: Optional[str]
    serial_number: Optional[str]
    not_before: Optional[str]
    not_after: Optional[str]
    expired: Optional[bool]
    public_key_algorithm: Optional[str]
    public_key_size: Optional[int]
    signature_algorithm: Optional[str]
    confidence: str = "high"

    def to_dict(self):
        return asdict(self)

def _name(parts):
    values=[]
    for rdn in parts or ():
        for key,value in rdn:
            values.append(f"{key}={value}")
    return ", ".join(values) or None

def _decode_pem(path: Path):
    try:
        return ssl._ssl._test_decode_cert(str(path))
    except (OSError, ssl.SSLError, ValueError):
        return None

def _parse_cert_time(value):
    if not value:
        return None
    try:
        return datetime.strptime(value,"%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    except ValueError:
        return None

def _iso_cert_time(value):
    dt=_parse_cert_time(value)
    return dt.isoformat().replace("+00:00","Z") if dt else None

def _expiry(value):
    dt=_parse_cert_time(value)
    return dt < datetime.now(timezone.utc) if dt else None

def scan_certificates(root: Path):
    paths=[root] if root.is_file() else list(root.rglob("*"))
    assets=[]
    for path in paths:
        if not path.is_file() or path.suffix.lower() not in {".pem",".crt",".cer"}:
            continue
        try:
            text=path.read_text(encoding="utf-8",errors="ignore")
        except OSError:
            continue
        if not PEM_CERT_RE.search(text):
            continue
        decoded=_decode_pem(path)
        if not decoded:
            assets.append(CertificateAsset(str(path),None,None,None,None,None,None,None,None,None,"medium"))
            continue
        raw_before=decoded.get("notBefore"); raw_after=decoded.get("notAfter")
        assets.append(CertificateAsset(
            file=str(path),subject=_name(decoded.get("subject")),issuer=_name(decoded.get("issuer")),
            serial_number=decoded.get("serialNumber"),not_before=_iso_cert_time(raw_before),
            not_after=_iso_cert_time(raw_after),expired=_expiry(raw_after),
            public_key_algorithm=None,public_key_size=None,signature_algorithm=None,
        ))
    return assets
