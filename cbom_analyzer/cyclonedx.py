import uuid
from datetime import datetime, timezone

PRIMITIVES={"AES":"block-cipher","DES":"block-cipher","RSA":"pke","ECC":"unknown","DSA":"signature","MD5":"hash","SHA-1":"hash","SHA-2":"hash"}

def _primitive(asset):
    if asset.purpose in {"digital-signature","signature-verification"}: return "signature"
    if asset.purpose=="key-establishment": return "key-agree"
    return PRIMITIVES.get(asset.name,"unknown")

def _functions(asset):
    return {"digital-signature":["sign"],"signature-verification":["verify"],"key-establishment":["keyderive"],"encryption":["encrypt"],"decryption":["decrypt"],"hashing":["digest"]}.get(asset.purpose,[])

def _algorithm_component(asset,index):
    ref=f"crypto-{index}-{uuid.uuid5(uuid.NAMESPACE_URL,asset.file+':'+str(asset.line)+':'+asset.name)}"
    props={"assetType":"algorithm","algorithmProperties":{"primitive":_primitive(asset),"algorithmFamily":asset.name}}
    if asset.key_size: props["algorithmProperties"]["parameterSetIdentifier"]=str(asset.key_size)
    funcs=_functions(asset)
    if funcs: props["algorithmProperties"]["cryptoFunctions"]=funcs
    return {"type":"cryptographic-asset","bom-ref":ref,"name":asset.name,"cryptoProperties":props,"properties":[
        {"name":"cbom-analyzer:source:file","value":asset.file},{"name":"cbom-analyzer:source:line","value":str(asset.line)},
        {"name":"cbom-analyzer:confidence","value":asset.confidence},{"name":"cbom-analyzer:policy:severity","value":asset.severity},
        {"name":"cbom-analyzer:pqc:migration-priority","value":asset.migration_priority}]}

def _certificate_component(cert,index):
    ref=f"certificate-{index}-{uuid.uuid5(uuid.NAMESPACE_URL,cert.file)}"
    certificate={"subjectName":cert.subject or "unknown","issuerName":cert.issuer or "unknown"}
    if cert.serial_number: certificate["serialNumber"]=cert.serial_number
    if cert.not_before: certificate["notValidBefore"]=cert.not_before
    if cert.not_after: certificate["notValidAfter"]=cert.not_after
    return {"type":"cryptographic-asset","bom-ref":ref,"name":cert.subject or cert.file,
        "cryptoProperties":{"assetType":"certificate","certificateProperties":certificate},
        "properties":[{"name":"cbom-analyzer:source:file","value":cert.file},
                      {"name":"cbom-analyzer:certificate:expired","value":str(cert.expired).lower() if cert.expired is not None else "unknown"}]}

def _key_component(key,index):
    ref=f"key-{index}-{uuid.uuid5(uuid.NAMESPACE_URL,key.file+':'+key.material_type)}"
    return {"type":"cryptographic-asset","bom-ref":ref,"name":key.material_type,
        "cryptoProperties":{"assetType":"related-crypto-material","relatedCryptoMaterialProperties":{
            "type":"private-key" if key.material_type=="private-key" else "public-key"}},
        "properties":[{"name":"cbom-analyzer:source:file","value":key.file},
                      {"name":"cbom-analyzer:key:encrypted","value":str(key.encrypted).lower()},
                      {"name":"cbom-analyzer:key:exposure","value":key.exposure}]}

def build_cyclonedx(findings,target_name="scanned-product",certificates=None,keys=None):
    crypto=[x for x in findings if x.category not in {"crypto-library","protocol"}]
    components=[_algorithm_component(a,i) for i,a in enumerate(crypto,1)]
    components += [_certificate_component(c,i) for i,c in enumerate(certificates or [],1)]
    components += [_key_component(k,i) for i,k in enumerate(keys or [],1)]
    return {"bomFormat":"CycloneDX","specVersion":"1.7","serialNumber":f"urn:uuid:{uuid.uuid4()}","version":1,
        "metadata":{"timestamp":datetime.now(timezone.utc).isoformat().replace("+00:00","Z"),
                    "component":{"type":"application","bom-ref":"target","name":target_name,"version":"unknown"}},
        "components":components}
