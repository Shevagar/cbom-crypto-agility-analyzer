import argparse, csv, json
from pathlib import Path
from .scanner import scan

def main():
    p=argparse.ArgumentParser(description="Discover cryptographic usage and create a crypto inventory.")
    sub=p.add_subparsers(dest="command", required=True)
    s=sub.add_parser("scan")
    s.add_argument("path", type=Path)
    s.add_argument("--json", dest="json_path", type=Path)
    s.add_argument("--csv", dest="csv_path", type=Path)
    args=p.parse_args()
    findings=scan(args.path)
    data=[f.to_dict() for f in findings]
    if args.json_path:
        args.json_path.write_text(json.dumps({"schema":"cbom-analyzer/v0.1","findings":data},indent=2)+"\n")
    if args.csv_path:
        with args.csv_path.open("w",newline="",encoding="utf-8") as fh:
            fields=["algorithm","category","pqc_migration_review","file","line","evidence"]
            w=csv.DictWriter(fh,fieldnames=fields); w.writeheader(); w.writerows(data)
    print(json.dumps({"findings":len(data),"pqc_migration_review":sum(x["pqc_migration_review"] for x in data)},indent=2))
    return 0
