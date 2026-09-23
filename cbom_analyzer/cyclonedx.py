import uuid
from datetime import datetime, timezone

PRIMITIVES={
    "AES":"block-cipher", "DES":"block-cipher", "RSA":"pke",
    "ECC":"unknown", "DSA":"signature", "MD5":"hash", "SHA-1":"hash", "SHA-2":"hash"
}

def _primitive(asset):
    if asset.purpose in {"digital-signature","signature-verification"}:
        return "signature"
    if asset.purpose == "key-establishment":
        return "key-agree"
    return PRIMITIVES.get(asset.name,"unknown")

def _functions(asset):
    mapping={
        "digital-signature":["sign"], "signature-verification":["verify"],
        "key-establishment":["keyderive"], "encryption":["encrypt"],
        "decryption":["decrypt"], "hashing":["digest"]
    }
    return mapping.get(asset.purpose,[])

def _component(asset,index):
    ref=f"crypto-{index}-{uuid.uuid5(uuid.NAMESPACE_URL, asset.file+':'+str(asset.line)+':'+asset.name)}"
    name=asset.name + (f"-{asset.key_size}" if asset.key_size and str(asset.key_size) not in asset.name else "")
    props={"assetType":"algorithm","algorithmProperties":{
        "primitive":_primitive(asset),
        "algorithmFamily":asset.name,
    }}
    if asset.key_size:
        props["algorithmProperties"]["parameterSetIdentifier"]=str(asset.key_size)
    funcs=_functions(asset)
    if funcs:
        props["algorithmProperties"]["cryptoFunctions"]=funcs
    return {
        "type":"cryptographic-asset","bom-ref":ref,"name":name,
        "cryptoProperties":props,
        "properties":[
            {"name":"cbom-analyzer:source:file","value":asset.file},
            {"name":"cbom-analyzer:source:line","value":str(asset.line)},
            {"name":"cbom-analyzer:confidence","value":asset.confidence},
            {"name":"cbom-analyzer:policy:severity","value":asset.severity},
            {"name":"cbom-analyzer:pqc:migration-priority","value":asset.migration_priority},
        ],
    }

def build_cyclonedx(findings,target_name="scanned-product"):
    crypto=[x for x in findings if x.category not in {"crypto-library","protocol"}]
    return {
        "bomFormat":"CycloneDX",
        "specVersion":"1.7",
        "serialNumber":f"urn:uuid:{uuid.uuid4()}",
        "version":1,
        "metadata":{
            "timestamp":datetime.now(timezone.utc).isoformat().replace("+00:00","Z"),
            "component":{"type":"application","bom-ref":"target","name":target_name,"version":"unknown"},
        },
        "components":[_component(asset,i) for i,asset in enumerate(crypto,1)],
    }
