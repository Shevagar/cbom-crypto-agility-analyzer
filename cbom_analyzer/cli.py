import argparse
import csv
import json
from pathlib import Path
from .scanner import scan

FIELDS=["name","category","file","line","evidence","key_size","status","quantum_vulnerable","pqc_migration_review","migration_family","confidence"]

def main():
    p=argparse.ArgumentParser(description="Discover cryptographic assets and create a crypto-agility inventory.")
    sub=p.add_subparsers(dest="command", required=True)
    s=sub.add_parser("scan", help="scan source/configuration files")
    s.add_argument("path", type=Path)
    s.add_argument("--json", dest="json_path", type=Path)
    s.add_argument("--csv", dest="csv_path", type=Path)
    args=p.parse_args()
    findings=scan(args.path)
    data=[f.to_dict() for f in findings]
    inventory={"schema":"cbom-analyzer/v0.2","summary":{
        "findings":len(data),
        "quantum_vulnerable":sum(x["quantum_vulnerable"] for x in data),
        "legacy_or_deprecated":sum(x["status"] in {"legacy","deprecated"} for x in data),
    },"findings":data}
    if args.json_path:
        args.json_path.write_text(json.dumps(inventory,indent=2)+"\n",encoding="utf-8")
    if args.csv_path:
        with args.csv_path.open("w",newline="",encoding="utf-8") as fh:
            w=csv.DictWriter(fh,fieldnames=FIELDS); w.writeheader(); w.writerows(data)
    print(json.dumps(inventory["summary"],indent=2))
    return 0
