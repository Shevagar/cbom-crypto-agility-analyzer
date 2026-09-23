import uuid
from datetime import datetime, timezone

PRIMITIVES={"AES":"block-cipher","DES":"block-cipher","RSA":"pke","ECC":"unknown","DSA":"signature","MD5":"hash","SHA-1":"hash","SHA-2":"hash"}
def _primitive(a):
    if a.purpose in {"digital-signature","signature-verification"}: return "signature"
    if a.purpose=="key-establishment": return "key-agree"
    return PRIMITIVES.get(a.name,"unknown")
def _functions(a):
    return {"digital-signature":["sign"],"signature-verification":["verify"],"key-establishment":["keyderive"],"encryption":["encrypt"],"decryption":["decrypt"],"hashing":["digest"]}.get(a.purpose,[])
def _algorithm_component(a,i):
    ref=f"crypto-{i}-{uuid.uuid5(uuid.NAMESPACE_URL,a.file+':'+str(a.line)+':'+a.name)}"
    props={"assetType":"algorithm","algorithmProperties":{"primitive":_primitive(a),"algorithmFamily":a.name}}
    if a.key_size: props["algorithmProperties"]["parameterSetIdentifier"]=str(a.key_size)
    funcs=_functions(a)
    if funcs: props["algorithmProperties"]["cryptoFunctions"]=funcs
    return {"type":"cryptographic-asset","bom-ref":ref,"name":a.name,"cryptoProperties":props,"properties":[{"name":"cbom-analyzer:source:file","value":a.file},{"name":"cbom-analyzer:source:line","value":str(a.line)},{"name":"cbom-analyzer:confidence","value":a.confidence},{"name":"cbom-analyzer:policy:severity","value":a.severity},{"name":"cbom-analyzer:pqc:migration-priority","value":a.migration_priority}]}
def _certificate_component(c,i):
    cert={"subjectName":c.subject or "unknown","issuerName":c.issuer or "unknown"}
    if c.serial_number: cert["serialNumber"]=c.serial_number
    if c.not_before: cert["notValidBefore"]=c.not_before
    if c.not_after: cert["notValidAfter"]=c.not_after
    return {"type":"cryptographic-asset","bom-ref":f"certificate-{i}-{uuid.uuid5(uuid.NAMESPACE_URL,c.file)}","name":c.subject or c.file,"cryptoProperties":{"assetType":"certificate","certificateProperties":cert},"properties":[{"name":"cbom-analyzer:source:file","value":c.file}]}
def _key_component(k,i):
    return {"type":"cryptographic-asset","bom-ref":f"key-{i}-{uuid.uuid5(uuid.NAMESPACE_URL,k.file+':'+k.material_type)}","name":k.material_type,"cryptoProperties":{"assetType":"related-crypto-material","relatedCryptoMaterialProperties":{"type":"private-key" if k.material_type=="private-key" else "public-key"}},"properties":[{"name":"cbom-analyzer:source:file","value":k.file},{"name":"cbom-analyzer:key:encrypted","value":str(k.encrypted).lower()}]}
def _hardware_component(h,i):
    ref=f"backend-{i}-{uuid.uuid5(uuid.NAMESPACE_URL,h.file+':'+str(h.line)+':'+h.backend)}"
    return {"type":"library","bom-ref":ref,"name":h.backend,"version":"unknown","properties":[{"name":"cbom-analyzer:source:file","value":h.file},{"name":"cbom-analyzer:source:line","value":str(h.line)},{"name":"cbom-analyzer:crypto-backend:key-location","value":h.key_location},{"name":"cbom-analyzer:crypto-backend:operation","value":h.operation or "unknown"},{"name":"cbom-analyzer:crypto-backend:exportability","value":h.exportability}]}
def build_cyclonedx(findings,target_name="scanned-product",certificates=None,keys=None,hardware=None):
    crypto=[x for x in findings if x.category not in {"crypto-library","protocol"}]
    components=[_algorithm_component(a,i) for i,a in enumerate(crypto,1)]
    components += [_certificate_component(c,i) for i,c in enumerate(certificates or [],1)]
    components += [_key_component(k,i) for i,k in enumerate(keys or [],1)]
    components += [_hardware_component(h,i) for i,h in enumerate(hardware or [],1)]
    return {"bomFormat":"CycloneDX","specVersion":"1.7","serialNumber":f"urn:uuid:{uuid.uuid4()}","version":1,"metadata":{"timestamp":datetime.now(timezone.utc).isoformat().replace("+00:00","Z"),"component":{"type":"application","bom-ref":"target","name":target_name,"version":"unknown"}},"components":components}
