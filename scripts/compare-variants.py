#!/usr/bin/env python3
"""
Variant Comparison Report Generator

Compares baseline SBOM scan against remediated variants and generates
a comprehensive before/after report with Debian urgency classification.

Usage (from capstone-sbom root):
    python3 scripts/compare-variants.py \\
      --run-dir runs/2026-02-09 \\
      --baseline sage3 \\
      --variants sage3-patched-slim sage3-alpine
"""

import argparse
import glob
import json
import os
from datetime import datetime
from collections import defaultdict


def load_grype(filepath):
    """Load and parse a Grype CycloneDX JSON file."""
    with open(filepath) as f:
        data = json.load(f)
    vulns = data.get("vulnerabilities", [])

    # Build unique CVE map
    cve_map = {}
    for v in vulns:
        cve_id = v.get("id", "unknown")
        if cve_id not in cve_map:
            severity = "unknown"
            ratings = v.get("ratings", [])
            if ratings:
                severity = ratings[0].get("severity", "unknown")

            affected_refs = [a.get("ref", "") for a in v.get("affects", []) if a.get("ref")]

            cve_map[cve_id] = {
                "severity": severity,
                "source_url": v.get("source", {}).get("url", ""),
                "affected_refs": affected_refs
            }

    return cve_map


def load_sbom(filepath):
    """Load SBOM and return component info."""
    with open(filepath) as f:
        data = json.load(f)

    components = data.get("components", [])
    dependencies = data.get("dependencies", [])

    # Build component lookup
    comp_lookup = {}
    type_counts = defaultdict(int)
    for c in components:
        bom_ref = c.get("bom-ref", "")
        purl = c.get("purl", "")
        comp_lookup[bom_ref] = {
            "name": c.get("name", "unknown"),
            "version": c.get("version", "unknown"),
            "type": c.get("type", "unknown"),
            "purl": purl
        }
        if purl:
            comp_lookup[purl] = comp_lookup[bom_ref]
        type_counts[c.get("type", "unknown")] += 1

    return {
        "component_count": len(components),
        "dependency_count": len(dependencies),
        "type_counts": dict(type_counts),
        "lookup": comp_lookup
    }


def classify_cve_ecosystem(cve_info, comp_lookup):
    """Determine if a CVE affects a Debian or npm package."""
    for ref in cve_info.get("affected_refs", []):
        if ref in comp_lookup:
            purl = comp_lookup[ref].get("purl", "")
            if "pkg:deb/" in purl:
                return "debian", comp_lookup[ref]
            elif "pkg:npm/" in purl:
                return "npm", comp_lookup[ref]
            elif "pkg:apk/" in purl:
                return "alpine", comp_lookup[ref]
    return "unknown", {}


def load_debian_urgency(migration_json_path):
    """Load Debian urgency data from migration analysis."""
    if not os.path.exists(migration_json_path):
        return {}

    with open(migration_json_path) as f:
        data = json.load(f)

    urgency_map = {}
    for pkg in data:
        for cve in pkg.get("cve_analysis", []):
            urgency_map[cve["cve_id"]] = {
                "urgency": cve.get("urgency", "unknown"),
                "status": cve.get("details", "unknown"),
                "fixed_in_latest": cve.get("fixed_in_latest", None)
            }

    return urgency_map


def find_cdx_file(directory):
    """Find the first .cdx.json file in a directory."""
    pattern = os.path.join(directory, "*.cdx.json")
    matches = sorted(glob.glob(pattern))
    if matches:
        return matches[0]
    return None


def discover_variant(run_dir, project_name, label=None):
    """Auto-discover sbom and grype files for a project directory."""
    base = os.path.join(run_dir, project_name)
    if not os.path.isdir(base):
        return None

    sbom_dir = os.path.join(base, "sbom")
    grype_dir = os.path.join(base, "grype")

    sbom_file = find_cdx_file(sbom_dir) if os.path.isdir(sbom_dir) else None
    grype_file = find_cdx_file(grype_dir) if os.path.isdir(grype_dir) else None

    if not label:
        label = project_name

    return {
        "label": label,
        "sbom": sbom_file,
        "grype": grype_file,
    }


def main():
    parser = argparse.ArgumentParser(description="Variant Comparison Report")
    parser.add_argument("--run-dir", required=True,
                        help="Path to the run directory (e.g. runs/2026-02-09)")
    parser.add_argument("--baseline", required=True,
                        help="Baseline project directory name (e.g. sage3)")
    parser.add_argument("--variants", required=True, nargs="+",
                        help="One or more variant project directory names "
                             "(e.g. sage3-patched-slim sage3-alpine)")
    # Keep --project as a hidden alias for backwards compatibility
    parser.add_argument("--project", required=False, help=argparse.SUPPRESS)
    args = parser.parse_args()

    # Backwards compat: if --project given but not --baseline, use project as baseline
    if args.project and not args.baseline:
        args.baseline = args.project

    base_dir = os.path.join(args.run_dir, args.baseline)

    # Discover baseline
    baseline_info = discover_variant(args.run_dir, args.baseline, label=f"Baseline ({args.baseline})")
    if not baseline_info or not baseline_info["grype"]:
        print(f"[x] Baseline project '{args.baseline}' not found or missing grype data in {args.run_dir}")
        return

    variants = {"baseline": baseline_info}

    # Discover each variant
    for vname in args.variants:
        vinfo = discover_variant(args.run_dir, vname, label=vname)
        if not vinfo or not vinfo["grype"]:
            print(f"[!] Variant '{vname}' not found or missing grype data -- skipping")
            continue
        variants[vname] = vinfo

    if len(variants) < 2:
        print("[x] Need at least baseline + one variant to compare.")
        return

    print("=" * 70)
    print(f"  Variant Comparison Report -- {args.baseline.upper()}")
    print("=" * 70)
    print()
    print(f"  Baseline:  {args.baseline}")
    for vname in args.variants:
        if vname in variants:
            print(f"  Variant:   {vname}")
    print()

    # Load all variants
    loaded = {}
    for name, paths in variants.items():
        if not os.path.exists(paths["grype"]):
            print(f"[!] Skipping {name} -- files not found")
            continue
        sbom_data = load_sbom(paths["sbom"])
        cve_data = load_grype(paths["grype"])
        loaded[name] = {
            "label": paths["label"],
            "sbom": sbom_data,
            "cves": cve_data,
            "cve_set": set(cve_data.keys())
        }
        print(f"[OK] Loaded {name}: {sbom_data['component_count']} components, {len(cve_data)} unique CVEs")

    if "baseline" not in loaded:
        print("[x] Baseline not found, cannot compare.")
        return

    # Load Debian urgency data from migration analysis (try common naming patterns)
    migration_path = None
    for pattern_name in [f"{args.baseline}-migration-analysis.json",
                         f"{args.baseline}-migration-v2.json",
                         f"{args.baseline}-migration.json"]:
        candidate = os.path.join(base_dir, pattern_name)
        if os.path.exists(candidate):
            migration_path = candidate
            break
    urgency_map = load_debian_urgency(migration_path) if migration_path else {}
    if urgency_map:
        print(f"[OK] Loaded Debian urgency data for {len(urgency_map)} CVEs")

    baseline = loaded["baseline"]
    baseline_lookup = baseline["sbom"]["lookup"]

    # -------------------------------------------------------------------------
    # Build comprehensive comparison
    # -------------------------------------------------------------------------
    report_data = {
        "project": args.baseline,
        "generated": datetime.now().isoformat(),
        "variants": {},
        "comparison": {}
    }

    for name, data in loaded.items():
        # Classify CVEs by ecosystem and severity
        ecosystem_counts = defaultdict(int)
        severity_counts = defaultdict(int)
        urgency_counts = defaultdict(int)

        for cve_id, cve_info in data["cves"].items():
            eco, _ = classify_cve_ecosystem(cve_info, data["sbom"]["lookup"])
            ecosystem_counts[eco] += 1
            severity_counts[cve_info["severity"]] += 1

            # Add urgency classification
            if cve_id in urgency_map:
                urgency_counts[urgency_map[cve_id]["urgency"]] += 1
            else:
                urgency_counts["not_classified"] += 1

        report_data["variants"][name] = {
            "label": data["label"],
            "components": data["sbom"]["component_count"],
            "dependencies": data["sbom"]["dependency_count"],
            "component_types": data["sbom"]["type_counts"],
            "total_unique_cves": len(data["cves"]),
            "severity": dict(severity_counts),
            "ecosystem": dict(ecosystem_counts),
            "debian_urgency": dict(urgency_counts)
        }

    # Compute diffs
    for name, data in loaded.items():
        if name == "baseline":
            continue

        removed = baseline["cve_set"] - data["cve_set"]
        added = data["cve_set"] - baseline["cve_set"]
        remaining = baseline["cve_set"] & data["cve_set"]

        # Classify removed CVEs
        removed_by_eco = defaultdict(list)
        removed_by_severity = defaultdict(int)
        removed_by_urgency = defaultdict(int)
        for cve_id in removed:
            cve_info = baseline["cves"][cve_id]
            eco, pkg_info = classify_cve_ecosystem(cve_info, baseline_lookup)
            removed_by_eco[eco].append({
                "cve_id": cve_id,
                "severity": cve_info["severity"],
                "package": pkg_info.get("name", "unknown"),
                "version": pkg_info.get("version", "unknown")
            })
            removed_by_severity[cve_info["severity"]] += 1
            if cve_id in urgency_map:
                removed_by_urgency[urgency_map[cve_id]["urgency"]] += 1

        # Classify added CVEs
        added_details = []
        for cve_id in added:
            cve_info = data["cves"][cve_id]
            eco, pkg_info = classify_cve_ecosystem(cve_info, data["sbom"]["lookup"])
            added_details.append({
                "cve_id": cve_id,
                "severity": cve_info["severity"],
                "ecosystem": eco,
                "package": pkg_info.get("name", "unknown"),
                "version": pkg_info.get("version", "unknown")
            })

        report_data["comparison"][name] = {
            "cves_removed": len(removed),
            "cves_added": len(added),
            "cves_remaining": len(remaining),
            "net_reduction": len(removed) - len(added),
            "reduction_pct": round((len(removed) - len(added)) / len(baseline["cves"]) * 100, 1) if baseline["cves"] else 0,
            "removed_by_ecosystem": {k: len(v) for k, v in removed_by_eco.items()},
            "removed_by_severity": dict(removed_by_severity),
            "removed_by_urgency": dict(removed_by_urgency),
            "removed_details": {k: v for k, v in removed_by_eco.items()},
            "added_details": added_details
        }

    # -------------------------------------------------------------------------
    # Write JSON report
    # -------------------------------------------------------------------------
    json_path = os.path.join(base_dir, f"{args.baseline}-comparison-report.json")
    with open(json_path, "w") as f:
        json.dump(report_data, f, indent=2, default=str)
    print(f"\n[OK] JSON: {json_path}")

    # -------------------------------------------------------------------------
    # Write human-readable report
    # -------------------------------------------------------------------------
    txt_path = os.path.join(base_dir, f"{args.baseline}-comparison-report.txt")
    with open(txt_path, "w") as f:
        f.write("=" * 80 + "\n")
        f.write(f"  SBOM Remediation Comparison Report -- {args.baseline.upper()}\n")
        f.write(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 80 + "\n\n")

        # Summary table
        f.write("VARIANT COMPARISON\n")
        f.write("-" * 80 + "\n")
        f.write(f"{'Metric':<30} ", )
        for name in loaded:
            label = name[:15]
            f.write(f"{label:>15} ")
        f.write("\n")
        f.write("-" * 80 + "\n")

        f.write(f"{'Components':<30} ")
        for name in loaded:
            f.write(f"{loaded[name]['sbom']['component_count']:>15} ")
        f.write("\n")

        f.write(f"{'Dependencies':<30} ")
        for name in loaded:
            f.write(f"{loaded[name]['sbom']['dependency_count']:>15} ")
        f.write("\n")

        f.write(f"{'Unique CVEs':<30} ")
        for name in loaded:
            f.write(f"{len(loaded[name]['cves']):>15} ")
        f.write("\n")

        f.write("-" * 80 + "\n")

        for sev in ["critical", "high", "medium", "low", "none"]:
            f.write(f"{'  ' + sev:<30} ")
            for name in loaded:
                count = report_data["variants"][name]["severity"].get(sev, 0)
                f.write(f"{count:>15} ")
            f.write("\n")

        f.write("-" * 80 + "\n")

        for eco in ["debian", "npm", "alpine", "unknown"]:
            count_exists = any(report_data["variants"][n]["ecosystem"].get(eco, 0) > 0 for n in loaded)
            if count_exists:
                f.write(f"{'  ' + eco:<30} ")
                for name in loaded:
                    count = report_data["variants"][name]["ecosystem"].get(eco, 0)
                    f.write(f"{count:>15} ")
                f.write("\n")

        f.write("\n\n")

        # Debian urgency breakdown for baseline
        f.write("DEBIAN CVE URGENCY CLASSIFICATION (Baseline)\n")
        f.write("-" * 60 + "\n")
        f.write("  Source: Debian Security Tracker (security-tracker.debian.org)\n\n")
        baseline_urgency = report_data["variants"]["baseline"].get("debian_urgency", {})
        for urg in ["unimportant", "low", "not yet assigned", "unknown", "not_classified"]:
            count = baseline_urgency.get(urg, 0)
            if count > 0:
                meaning = {
                    "unimportant": "Negligible risk, Debian wont fix",
                    "low": "Low priority, may get fixed eventually",
                    "not yet assigned": "Not yet triaged by Debian security",
                    "unknown": "No urgency data available",
                    "not_classified": "Not in Debian tracker (may be npm)"
                }.get(urg, "")
                f.write(f"  {urg:25s}: {count:4d}  ({meaning})\n")
        f.write("\n\n")

        # Per-variant comparison details
        for name, comp in report_data.get("comparison", {}).items():
            variant_label = loaded[name]["label"]
            f.write(f"REMEDIATION: {variant_label}\n")
            f.write("-" * 60 + "\n")
            f.write(f"  CVEs removed:     {comp['cves_removed']}\n")
            f.write(f"  CVEs added (new): {comp['cves_added']}\n")
            f.write(f"  CVEs remaining:   {comp['cves_remaining']}\n")
            f.write(f"  Net reduction:    {comp['net_reduction']} ({comp['reduction_pct']}%)\n\n")

            # Removed by ecosystem
            f.write("  Removed by ecosystem:\n")
            for eco, count in sorted(comp.get("removed_by_ecosystem", {}).items()):
                f.write(f"    {eco}: {count}\n")

            # Removed by severity
            f.write("\n  Removed by severity:\n")
            for sev in ["critical", "high", "medium", "low", "none"]:
                count = comp.get("removed_by_severity", {}).get(sev, 0)
                if count > 0:
                    f.write(f"    {sev}: {count}\n")

            # Removed by Debian urgency
            if comp.get("removed_by_urgency"):
                f.write("\n  Removed by Debian urgency:\n")
                for urg, count in sorted(comp.get("removed_by_urgency", {}).items()):
                    if count > 0:
                        f.write(f"    {urg}: {count}\n")

            # Newly introduced CVEs
            if comp.get("added_details"):
                f.write("\n  [!] NEWLY INTRODUCED CVEs:\n")
                for added in comp["added_details"]:
                    f.write(f"    {added['cve_id']} -- {added['package']}@{added['version']} "
                            f"({added['severity']}, {added['ecosystem']})\n")
            else:
                f.write("\n  [OK] No new CVEs introduced by this remediation\n")

            # List top removed CVEs
            f.write("\n  Top CVEs removed:\n")
            all_removed = []
            for eco, cves in comp.get("removed_details", {}).items():
                all_removed.extend(cves)
            # Sort by severity
            sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "none": 4, "unknown": 5}
            all_removed.sort(key=lambda x: sev_order.get(x["severity"], 5))
            for r in all_removed[:25]:
                f.write(f"    [+] {r['cve_id']} -- {r['package']}@{r['version']} ({r['severity']})\n")
            if len(all_removed) > 25:
                f.write(f"    ... and {len(all_removed) - 25} more\n")

            f.write("\n\n")

        # Recommendations
        f.write("RECOMMENDATIONS\n")
        f.write("-" * 60 + "\n")
        f.write("  Based on this analysis:\n\n")

        # Find best variant
        best_name = min(report_data["comparison"].keys(),
                        key=lambda n: len(loaded[n]["cves"]))
        best_count = len(loaded[best_name]["cves"])
        baseline_count = len(baseline["cves"])

        f.write(f"  1. BEST VARIANT: {best_name}\n")
        f.write(f"     Reduces CVEs from {baseline_count} to {best_count} "
                f"(-{baseline_count - best_count}, "
                f"{((baseline_count - best_count) / baseline_count * 100):.1f}% reduction)\n\n")

        f.write("  2. npm DEPENDENCIES:\n")
        f.write("     - Upgrade nodemailer 6.10.1 -> latest (direct dependency, 2 CVEs)\n")
        f.write("     - Run npm audit fix for transitive vulnerabilities\n\n")

        f.write("  3. DOCKER BASE IMAGE:\n")
        f.write("     - Switch to node:22-alpine OR regularly rebuild with latest node:22-slim\n")
        f.write("     - Alpine eliminates most Debian CVEs by using musl/apk instead\n\n")

        f.write("  4. DEBIAN CVEs (if staying on Debian-based image):\n")
        baseline_urg = report_data["variants"]["baseline"].get("debian_urgency", {})
        unimportant = baseline_urg.get("unimportant", 0)
        f.write(f"     - {unimportant} CVEs are 'unimportant' per Debian Security -- accept risk\n")
        f.write("     - Remaining: monitor via periodic apt-get upgrade in image rebuilds\n\n")

        f.write("  5. ONGOING MAINTENANCE:\n")
        f.write("     - Pin base image digest for reproducibility\n")
        f.write("     - Re-scan monthly with Syft + Grype\n")
        f.write("     - Integrate SBOM generation into CI/CD pipeline\n")

        f.write("\n" + "=" * 80 + "\n")
        f.write("  END OF COMPARISON REPORT\n")
        f.write("=" * 80 + "\n")

    print(f"[OK] Text: {txt_path}")

    # -------------------------------------------------------------------------
    # Write CSV summary
    # -------------------------------------------------------------------------
    csv_path = os.path.join(base_dir, f"{args.baseline}-comparison-summary.csv")
    with open(csv_path, "w") as f:
        f.write("Variant,Components,Dependencies,Unique_CVEs,Critical,High,Medium,Low,None,"
                "Debian_CVEs,npm_CVEs,CVEs_Removed,CVEs_Added,Net_Reduction,Reduction_Pct\n")
        for name in loaded:
            v = report_data["variants"][name]
            comp = report_data.get("comparison", {}).get(name, {})
            f.write(f"{name},"
                    f"{v['components']},"
                    f"{v['dependencies']},"
                    f"{v['total_unique_cves']},"
                    f"{v['severity'].get('critical', 0)},"
                    f"{v['severity'].get('high', 0)},"
                    f"{v['severity'].get('medium', 0)},"
                    f"{v['severity'].get('low', 0)},"
                    f"{v['severity'].get('none', 0)},"
                    f"{v['ecosystem'].get('debian', 0)},"
                    f"{v['ecosystem'].get('npm', 0) + v['ecosystem'].get('alpine', 0)},"
                    f"{comp.get('cves_removed', 0)},"
                    f"{comp.get('cves_added', 0)},"
                    f"{comp.get('net_reduction', 0)},"
                    f"{comp.get('reduction_pct', 0)}\n")
    print(f"[OK] CSV:  {csv_path}")

    # Print summary to console
    print()
    print("=" * 60)
    print(f"  COMPARISON SUMMARY -- {args.baseline.upper()}")
    print("=" * 60)
    for name in loaded:
        cve_count = len(loaded[name]["cves"])
        comp = report_data.get("comparison", {}).get(name, {})
        reduction = comp.get("net_reduction", 0)
        pct = comp.get("reduction_pct", 0)
        label = report_data["variants"][name]["label"]
        if name == "baseline":
            print(f"  {label}: {cve_count} CVEs")
        else:
            print(f"  {label}: {cve_count} CVEs (net -{reduction}, {pct}%)")
    print()


if __name__ == "__main__":
    main()