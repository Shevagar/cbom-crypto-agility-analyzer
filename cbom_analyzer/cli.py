import argparse
import csv
import json
from pathlib import Path
from .agility import assess_migration, build_roadmap
from .certificates import scan_certificates
from .correlation import correlate, migration_constraints
from .cyclonedx import build_cyclonedx
from .hardware import scan_hardware_crypto
from .key_material import scan_key_material
from .scanner import scan

FIELDS=["name","category","file","line","evidence","key_size","status","quantum_vulnerable","pqc_migration_review","migration_family","confidence","purpose","purpose_confidence","severity","policy_reason","migration_priority"]

def main():
    p=argparse.ArgumentParser(description="Discover cryptographic assets and create a crypto-agility inventory.")
    sub=p.add_subparsers(dest="command",required=True)
    s=sub.add_parser("scan",help="scan crypto assets, backends and migration constraints")
    s.add_argument("path",type=Path); s.add_argument("--json",dest="json_path",type=Path); s.add_argument("--csv",dest="csv_path",type=Path)
    s.add_argument("--cyclonedx",dest="cyclonedx_path",type=Path,help="write CycloneDX 1.7 CBOM JSON")
    s.add_argument("--roadmap",dest="roadmap_path",type=Path,help="write PQC migration roadmap JSON")
    args=p.parse_args()
    findings=scan(args.path); certificates=scan_certificates(args.path); keys=scan_key_material(args.path); hardware=scan_hardware_crypto(args.path)
    relationships=correlate(findings,certificates,keys,hardware); constraints=migration_constraints(findings,hardware,relationships)
    assessments=assess_migration(findings,relationships); roadmap=build_roadmap(assessments)
    data=[f.to_dict() for f in findings]
    inventory={"schema":"cbom-analyzer/v0.6","summary":{
        "findings":len(data),"certificates":len(certificates),"key_material":len(keys),"hardware_crypto":len(hardware),
        "relationships":len(relationships),"migration_constraints":len(constraints),"pqc_migration_assets":len(roadmap),
        "high_complexity_migrations":sum(x["complexity"]=="high" for x in roadmap),
        "private_keys":sum(x.material_type=="private-key" for x in keys),"quantum_vulnerable":sum(x["quantum_vulnerable"] for x in data),
        "legacy_or_deprecated":sum(x["status"] in {"legacy","deprecated"} for x in data),
        "high_or_critical":sum(x["severity"] in {"high","critical"} for x in data),"purpose_inferred":sum(x["purpose"] is not None for x in data),
    },"findings":data,"certificates":[x.to_dict() for x in certificates],"key_material":[x.to_dict() for x in keys],
      "hardware_crypto":[x.to_dict() for x in hardware],"relationships":[x.to_dict() for x in relationships],
      "migration_constraints":constraints,"pqc_migration_roadmap":roadmap}
    if args.json_path: args.json_path.write_text(json.dumps(inventory,indent=2)+"\n",encoding="utf-8")
    if args.csv_path:
        with args.csv_path.open("w",newline="",encoding="utf-8") as fh:
            w=csv.DictWriter(fh,fieldnames=FIELDS); w.writeheader(); w.writerows(data)
    if args.cyclonedx_path:
        bom=build_cyclonedx(findings,args.path.name or "scanned-product",certificates,keys,hardware)
        args.cyclonedx_path.write_text(json.dumps(bom,indent=2)+"\n",encoding="utf-8")
    if args.roadmap_path:
        args.roadmap_path.write_text(json.dumps({"schema":"cbom-analyzer/pqc-roadmap/v1","assets":roadmap},indent=2)+"\n",encoding="utf-8")
    print(json.dumps(inventory["summary"],indent=2)); return 0
