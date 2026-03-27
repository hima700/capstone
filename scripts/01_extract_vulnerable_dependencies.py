#!/usr/bin/env python3
import json
import argparse
from pathlib import Path
from collections import defaultdict

SEV_ORDER = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Unknown": 0, None: 0}

def load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))

def best_severity(vuln_obj):
    # CycloneDX: vulnerability.ratings[].severity (may be multiple)
    ratings = vuln_obj.get("ratings") or []
    best = None
    best_score = -1
    for r in ratings:
        sev = r.get("severity")
        score = SEV_ORDER.get(sev, 0)
        if score > best_score:
            best, best_score = sev, score
    return best or "Unknown"

def infer_ecosystem_from_purl(purl: str):
    if not purl:
        return "unknown"
    if purl.startswith("pkg:npm/"):
        return "npm"
    if purl.startswith("pkg:deb/"):
        return "deb"
    if purl.startswith("pkg:pypi/"):
        return "pypi"
    if purl.startswith("pkg:golang/"):
        return "golang"
    if purl.startswith("pkg:maven/"):
        return "maven"
    return "other"

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--merged", required=True, help="Merged CycloneDX SBOM JSON")
    ap.add_argument("--outdir", required=True, help="Output directory, e.g. runs/.../hcdp-api/inventory")
    args = ap.parse_args()

    merged_path = Path(args.merged)
    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    sbom = load_json(merged_path)

    # components indexed by bom-ref
    components = sbom.get("components") or []
    comp_by_bomref = {}
    for c in components:
        bomref = c.get("bom-ref")
        if bomref:
            comp_by_bomref[bomref] = c

    vulns = sbom.get("vulnerabilities") or []
    if not isinstance(vulns, list):
        raise SystemExit("ERROR: merged SBOM has no vulnerabilities[] list")

    # instance rows: one vuln affecting one bom-ref
    instance_rows = []
    # per component aggregation
    comp_vulns = defaultdict(list)

    for v in vulns:
        vid = v.get("id") or ""
        sev = best_severity(v)
        affects = v.get("affects") or []
        for a in affects:
            ref = a.get("ref")
            if not ref:
                continue
            c = comp_by_bomref.get(ref, {})
            name = c.get("name") or ""
            version = c.get("version") or ""
            purl = c.get("purl") or ""
            ctype = c.get("type") or ""
            eco = infer_ecosystem_from_purl(purl)
            instance_rows.append((vid, sev, ref, eco, name, version, purl, ctype))
            comp_vulns[ref].append((vid, sev, eco, name, version, purl, ctype))

    # write vuln_to_component instances TSV
    inst_path = outdir / "vuln_instances.tsv"
    with inst_path.open("w", encoding="utf-8") as f:
        f.write("vuln_id\tseverity\tbom_ref\tecosystem\tname\tversion\tpurl\ttype\n")
        for row in instance_rows:
            f.write("\t".join(x if x is not None else "" for x in row) + "\n")

    # write unique vulnerable components TSV
    comp_path = outdir / "vulnerable_components.tsv"
    with comp_path.open("w", encoding="utf-8") as f:
        f.write("bom_ref\tecosystem\tname\tversion\tpurl\ttype\tvuln_count\tmax_severity\tvuln_ids\n")
        for ref, items in comp_vulns.items():
            # items: (vid, sev, eco, name, version, purl, type)
            vids = sorted({i[0] for i in items if i[0]})
            max_sev = "Unknown"
            max_score = -1
            for i in items:
                score = SEV_ORDER.get(i[1], 0)
                if score > max_score:
                    max_score = score
                    max_sev = i[1]
            eco = items[0][2]
            name = items[0][3]
            version = items[0][4]
            purl = items[0][5]
            ctype = items[0][6]
            f.write(f"{ref}\t{eco}\t{name}\t{version}\t{purl}\t{ctype}\t{len(items)}\t{max_sev}\t{','.join(vids)}\n")

    # summary JSON
    summary = {
        "merged": str(merged_path),
        "total_vulnerability_objects": len(vulns),
        "total_vuln_instances": len(instance_rows),
        "unique_vulnerable_components": len(comp_vulns),
        "ecosystem_breakdown": {}
    }
    eco_counts = defaultdict(int)
    for ref, items in comp_vulns.items():
        eco_counts[items[0][2]] += 1
    summary["ecosystem_breakdown"] = dict(sorted(eco_counts.items(), key=lambda x: (-x[1], x[0])))

    (outdir / "inventory_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")

    print("[OK] wrote:")
    print(f"  {inst_path}")
    print(f"  {comp_path}")
    print(f"  {outdir / 'inventory_summary.json'}")
    print(f"[INFO] unique vulnerable components: {summary['unique_vulnerable_components']}")
    print(f"[INFO] breakdown: {summary['ecosystem_breakdown']}")

if __name__ == "__main__":
    main()
