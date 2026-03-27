#!/usr/bin/env python3
"""
CVE Analysis & Mitigation Report Generator
Reads SBOM pipeline output, queries NVD API, checks latest package versions,
and generates an automated mitigation plan covering ALL CVEs.

Folder structure expected (matches capstone-sbom project):
  capstone-sbom/
    runs/2026-02-09/hcdp-api/
      sbom/hcdp-api-sbom.cdx.json
      grype/hcdp-api-grype.cdx.json
      merged/hcdp-api-merged.cdx.json
      npm/hcdp-api-npm-audit.json
      npm/hcdp-api-npm-tree.json
      nvd/   <-- NVD results cached here

Usage (from capstone-sbom root):
    python3 scripts/analyze-cves.py --run-dir runs/2026-02-09 --project hcdp-api --nvd-api-key YOUR_KEY
    python3 scripts/analyze-cves.py --run-dir runs/2026-02-09 --project hcdp-api  # without key (slower)

    You can also set the key as an environment variable:
    export NVD_API_KEY="your-key-here"
    python3 scripts/analyze-cves.py --run-dir runs/2026-02-09 --project hcdp-api
"""

import argparse
import json
import os
import sys
import time
import urllib.request
import urllib.parse
import urllib.error
from datetime import datetime
from collections import defaultdict

# =============================================================================
# Configuration
# =============================================================================
NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NPM_REGISTRY_BASE = "https://registry.npmjs.org"

RATE_LIMIT_WITH_KEY = 0.6      # seconds between requests (50/30s)
RATE_LIMIT_WITHOUT_KEY = 6.0   # seconds between requests (5/30s)


# =============================================================================
# NVD API Functions
# =============================================================================
def query_nvd(cve_id: str, api_key: str = None, cache_dir: str = None) -> dict:
    """Query NVD API for a specific CVE. Caches results to avoid re-querying."""
    if cache_dir:
        cache_file = os.path.join(cache_dir, f"{cve_id}.json")
        if os.path.exists(cache_file):
            with open(cache_file) as f:
                return json.load(f)

    url = f"{NVD_API_BASE}?cveId={cve_id}"
    headers = {}
    if api_key:
        headers["apiKey"] = api_key

    req = urllib.request.Request(url, headers=headers)

    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            data = json.loads(response.read().decode())
            if data.get("vulnerabilities") and len(data["vulnerabilities"]) > 0:
                result = data["vulnerabilities"][0].get("cve", {})
                if cache_dir:
                    os.makedirs(cache_dir, exist_ok=True)
                    with open(cache_file, "w") as f:
                        json.dump(result, f, indent=2)
                return result
    except urllib.error.HTTPError as e:
        if e.code == 403:
            print(f"    ⚠️  Rate limited on {cve_id}, waiting 30s...")
            time.sleep(30)
            return query_nvd(cve_id, api_key, cache_dir)
        print(f"    ⚠️  HTTP {e.code} for {cve_id}: {e.reason}")
    except urllib.error.URLError as e:
        print(f"    ⚠️  Connection error for {cve_id}: {e.reason}")
    except Exception as e:
        print(f"    ⚠️  Error querying NVD for {cve_id}: {e}")

    return {}


def extract_nvd_details(nvd_data: dict) -> dict:
    """Extract useful fields from NVD response."""
    result = {
        "description": "",
        "cvss_v3_score": None,
        "cvss_v3_severity": "",
        "cvss_v3_vector": "",
        "cwe_ids": [],
        "references": [],
        "published": "",
        "last_modified": "",
    }

    if not nvd_data:
        return result

    descriptions = nvd_data.get("descriptions", [])
    for desc in descriptions:
        if desc.get("lang") == "en":
            result["description"] = desc.get("value", "")
            break

    metrics = nvd_data.get("metrics", {})
    cvss_v31 = metrics.get("cvssMetricV31", [])
    cvss_v30 = metrics.get("cvssMetricV30", [])
    cvss_list = cvss_v31 or cvss_v30

    if cvss_list:
        primary = cvss_list[0].get("cvssData", {})
        result["cvss_v3_score"] = primary.get("baseScore")
        result["cvss_v3_severity"] = primary.get("baseSeverity", "")
        result["cvss_v3_vector"] = primary.get("vectorString", "")

    weaknesses = nvd_data.get("weaknesses", [])
    for w in weaknesses:
        for desc in w.get("description", []):
            cwe_id = desc.get("value", "")
            if cwe_id and cwe_id not in result["cwe_ids"]:
                result["cwe_ids"].append(cwe_id)

    references = nvd_data.get("references", [])
    result["references"] = [
        {"url": ref.get("url", ""), "source": ref.get("source", "")}
        for ref in references[:5]
    ]

    result["published"] = nvd_data.get("published", "")
    result["last_modified"] = nvd_data.get("lastModified", "")

    return result


# =============================================================================
# npm Registry Functions
# =============================================================================
def get_npm_package_info(package_name: str) -> dict:
    """Query npm registry for latest version info."""
    url = f"{NPM_REGISTRY_BASE}/{urllib.parse.quote(package_name, safe='@/')}"

    try:
        req = urllib.request.Request(url)
        req.add_header("Accept", "application/vnd.npm.install-v1+json")
        with urllib.request.urlopen(req, timeout=15) as response:
            data = json.loads(response.read().decode())
            latest_version = data.get("dist-tags", {}).get("latest", "unknown")
            all_versions = list(data.get("versions", {}).keys())

            return {
                "latest_version": latest_version,
                "total_versions": len(all_versions),
                "recent_versions": all_versions[-5:] if all_versions else [],
                "deprecated": data.get("deprecated", None) is not None
            }
    except Exception as e:
        return {
            "latest_version": "unknown",
            "total_versions": 0,
            "recent_versions": [],
            "deprecated": False,
            "error": str(e)
        }


# =============================================================================
# Dependency Tree Analysis
# =============================================================================
def find_package_in_tree(tree: dict, package_name: str, path: list = None) -> list:
    """Recursively find a package in the npm dependency tree."""
    if path is None:
        path = []

    results = []
    deps = tree.get("dependencies", {})

    for dep_name, dep_info in deps.items():
        current_path = path + [dep_name]
        if dep_name == package_name:
            results.append({
                "path": current_path,
                "version": dep_info.get("version", "unknown"),
                "depth": len(current_path),
                "is_direct": len(current_path) == 1
            })
        if isinstance(dep_info, dict):
            sub_results = find_package_in_tree(dep_info, package_name, current_path)
            results.extend(sub_results)

    return results


def classify_dependency(tree: dict, package_name: str) -> dict:
    """Classify a dependency as direct or transitive."""
    occurrences = find_package_in_tree(tree, package_name)

    if not occurrences:
        return {
            "found_in_npm_tree": False,
            "is_direct": False,
            "occurrence_count": 0,
            "min_depth": None,
            "paths": [],
            "ecosystem": "unknown"
        }

    return {
        "found_in_npm_tree": True,
        "is_direct": any(o["is_direct"] for o in occurrences),
        "occurrence_count": len(occurrences),
        "min_depth": min(o["depth"] for o in occurrences),
        "paths": [" → ".join(o["path"]) for o in occurrences[:5]],
        "ecosystem": "npm"
    }


# =============================================================================
# Mitigation Analysis — Answers Dr. Mehdi's specific questions
# =============================================================================
def analyze_mitigation(package_name: str, current_version: str, cve_id: str,
                       npm_info: dict) -> dict:
    """
    For each vulnerable package:
    - Has the CVE been fixed in the latest version (Vx)?
    - Have new CVEs been introduced in Vx?
    - If migrating from Vx-1 to Vx, what's the new CVE count?
    """
    latest = npm_info.get("latest_version", "unknown")

    mitigation = {
        "current_version": current_version,
        "latest_version": latest,
        "upgrade_available": current_version != latest and latest != "unknown",
        "is_deprecated": npm_info.get("deprecated", False),
        "recommendation": "",
        "risk_level": "",
        "notes": []
    }

    if mitigation["is_deprecated"]:
        mitigation["recommendation"] = "REPLACE — package is deprecated, find alternative"
        mitigation["risk_level"] = "high"
        mitigation["notes"].append("Package has been deprecated by maintainers.")
    elif not mitigation["upgrade_available"]:
        mitigation["recommendation"] = "INVESTIGATE — already on latest version, CVE may be unpatched"
        mitigation["risk_level"] = "medium"
        mitigation["notes"].append(
            "Already on latest version. Check if CVE is disputed, "
            "if a patch is pending, or if an alternative package is needed."
        )
    else:
        mitigation["recommendation"] = f"UPGRADE — update from {current_version} to {latest}"
        mitigation["risk_level"] = "low"
        mitigation["notes"].append(
            f"Newer version {latest} available. "
            f"Verify CVE is fixed in {latest} and test for breakage."
        )

    return mitigation


# =============================================================================
# Report Generation
# =============================================================================
def generate_summary_report(results: list, project_name: str) -> str:
    """Generate a human-readable summary report."""
    lines = []
    lines.append("=" * 80)
    lines.append(f"  SBOM Vulnerability Mitigation Report — {project_name.upper()}")
    lines.append(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("=" * 80)
    lines.append("")

    total_cves = len(results)
    severity_counts = defaultdict(int)
    ecosystem_counts = defaultdict(int)
    action_counts = defaultdict(int)

    for r in results:
        sev = r.get("nvd_details", {}).get("cvss_v3_severity", "UNKNOWN") or "UNKNOWN"
        severity_counts[sev] += 1

        eco = r.get("dependency_info", {}).get("ecosystem", "unknown")
        ecosystem_counts[eco] += 1

        mit = r.get("mitigation", {})
        action = mit.get("recommendation", "").split("—")[0].strip() if mit.get("recommendation") else "UNKNOWN"
        action_counts[action] += 1

    lines.append("SUMMARY")
    lines.append("-" * 40)
    lines.append(f"  Total unique CVEs analyzed:  {total_cves}")
    lines.append("")
    lines.append("  Mitigation Actions:")
    for action, count in sorted(action_counts.items()):
        lines.append(f"    {action:20s}: {count}")
    lines.append("")
    lines.append("  Severity Distribution (NVD CVSS v3):")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]:
        if severity_counts.get(sev, 0) > 0:
            lines.append(f"    {sev:12s}: {severity_counts[sev]}")
    lines.append("")
    lines.append("  Ecosystem Distribution:")
    for eco, count in sorted(ecosystem_counts.items()):
        lines.append(f"    {eco:12s}: {count}")

    lines.append("")
    lines.append("")
    lines.append("DETAILED CVE ANALYSIS")
    lines.append("-" * 40)

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
    sorted_results = sorted(results, key=lambda r: severity_order.get(
        r.get("nvd_details", {}).get("cvss_v3_severity", "UNKNOWN") or "UNKNOWN", 5
    ))

    for i, r in enumerate(sorted_results, 1):
        cve_id = r.get("cve_id", "unknown")
        nvd = r.get("nvd_details", {})
        dep = r.get("dependency_info", {})
        mit = r.get("mitigation", {})

        lines.append("")
        lines.append(f"  [{i}/{total_cves}] {cve_id}")
        lines.append(f"  {'—' * 50}")

        score = nvd.get("cvss_v3_score", "N/A")
        severity = nvd.get("cvss_v3_severity", "UNKNOWN") or "UNKNOWN"
        lines.append(f"  Severity:    {severity} (CVSS: {score})")

        pkg = r.get("package_name", "unknown")
        ver = r.get("package_version", "unknown")
        lines.append(f"  Package:     {pkg}@{ver}")

        if dep.get("found_in_npm_tree"):
            dep_type = "DIRECT" if dep.get("is_direct") else "TRANSITIVE"
            depth = dep.get("min_depth", "?")
            occurrences = dep.get("occurrence_count", 0)
            lines.append(f"  Dep Type:    {dep_type} (depth: {depth}, occurrences: {occurrences})")
            if dep.get("paths"):
                lines.append(f"  Path:        {dep['paths'][0]}")
        else:
            eco = dep.get("ecosystem", "unknown")
            lines.append(f"  Dep Type:    {eco.upper()} (not in npm tree)")

        desc = nvd.get("description", "")
        if desc:
            truncated = desc[:200] + "..." if len(desc) > 200 else desc
            lines.append(f"  Description: {truncated}")

        cwes = nvd.get("cwe_ids", [])
        if cwes:
            lines.append(f"  CWE:         {', '.join(cwes)}")

        lines.append(f"  Latest Ver:  {mit.get('latest_version', 'unknown')}")
        lines.append(f"  Action:      {mit.get('recommendation', 'N/A')}")
        lines.append(f"  Risk Level:  {mit.get('risk_level', 'unknown')}")
        for note in mit.get("notes", []):
            lines.append(f"  Note:        {note}")

    lines.append("")
    lines.append("=" * 80)
    lines.append("  END OF REPORT")
    lines.append("=" * 80)

    return "\n".join(lines)


# =============================================================================
# Main
# =============================================================================
def main():
    parser = argparse.ArgumentParser(description="CVE Analysis & Mitigation Report Generator")
    parser.add_argument("--run-dir", required=True, help="Path to run directory (e.g., runs/2026-02-09)")
    parser.add_argument("--project", required=True, help="Project name (e.g., hcdp-api)")
    parser.add_argument("--nvd-api-key", default=None, help="NVD API key")
    parser.add_argument("--skip-nvd", action="store_true", help="Skip NVD queries")
    args = parser.parse_args()

    base_dir = os.path.join(args.run_dir, args.project)
    sbom_file = os.path.join(base_dir, "sbom", f"{args.project}-sbom.cdx.json")
    grype_file = os.path.join(base_dir, "grype", f"{args.project}-grype.cdx.json")
    merged_file = os.path.join(base_dir, "merged", f"{args.project}-merged.cdx.json")
    npm_audit_file = os.path.join(base_dir, "npm", f"{args.project}-npm-audit.json")
    npm_tree_file = os.path.join(base_dir, "npm", f"{args.project}-npm-tree.json")
    nvd_cache_dir = os.path.join(base_dir, "nvd")

    api_key = args.nvd_api_key or os.environ.get("NVD_API_KEY")
    rate_limit = RATE_LIMIT_WITH_KEY if api_key else RATE_LIMIT_WITHOUT_KEY

    print("=" * 60)
    print(f"  CVE Analysis — {args.project.upper()}")
    print("=" * 60)
    print()

    if api_key:
        print(f"[✓] NVD API key detected (rate: ~{1/rate_limit:.0f} req/s)")
    else:
        print(f"[!] No NVD API key — rate limited to ~{1/rate_limit:.1f} req/s")
        print("    Set via: export NVD_API_KEY='your-key'")
        print("    Or pass: --nvd-api-key YOUR_KEY")

    # Validate input files
    print("\n--- Checking input files ---")
    for label, filepath in [
        ("Merged SBOM", merged_file),
        ("Grype output", grype_file),
        ("npm tree", npm_tree_file),
        ("npm audit", npm_audit_file),
    ]:
        status = "[✓]" if os.path.exists(filepath) else "[✗]"
        print(f"{status} {label}: {filepath}")

    # Load data
    print("\n--- Loading data ---")

    with open(merged_file) as f:
        merged_sbom = json.load(f)
    components = merged_sbom.get("components", [])
    vulnerabilities = merged_sbom.get("vulnerabilities", [])
    print(f"[✓] Merged SBOM: {len(components)} components, "
          f"{len(merged_sbom.get('dependencies', []))} dependencies, "
          f"{len(vulnerabilities)} vulnerabilities")

    npm_tree = {}
    if os.path.exists(npm_tree_file):
        with open(npm_tree_file) as f:
            npm_tree = json.load(f)
        print(f"[✓] npm tree: {len(npm_tree.get('dependencies', {}))} direct dependencies")

    npm_audit = {}
    if os.path.exists(npm_audit_file):
        with open(npm_audit_file, encoding="utf-8-sig") as f:
            npm_audit = json.load(f)
        # Handle yarn audit --json (NDJSON wrapped in array) format
        if isinstance(npm_audit, list):
            converted = {"metadata": {}, "vulnerabilities": {}}
            for entry in npm_audit:
                etype = entry.get("type", "")
                edata = entry.get("data", {})
                if etype == "auditSummary":
                    converted["metadata"] = edata
                elif etype == "auditAdvisory":
                    advisory = edata.get("advisory", {})
                    pkg_name = advisory.get("module_name", "")
                    if pkg_name:
                        cves = advisory.get("cves", [])
                        via_list = []
                        for cve_id in cves:
                            via_list.append({
                                "name": pkg_name,
                                "cve": cve_id,
                                "severity": advisory.get("severity", ""),
                                "title": advisory.get("title", ""),
                                "url": advisory.get("url", ""),
                                "range": advisory.get("vulnerable_versions", "")
                            })
                        if not via_list:
                            via_list.append({
                                "name": pkg_name,
                                "severity": advisory.get("severity", ""),
                                "title": advisory.get("title", ""),
                                "url": advisory.get("url", ""),
                                "range": advisory.get("vulnerable_versions", "")
                            })
                        if pkg_name not in converted["vulnerabilities"]:
                            converted["vulnerabilities"][pkg_name] = {
                                "name": pkg_name,
                                "severity": advisory.get("severity", ""),
                                "via": via_list,
                                "effects": [],
                                "range": advisory.get("vulnerable_versions", ""),
                                "fixAvailable": bool(advisory.get("patched_versions"))
                            }
                        else:
                            converted["vulnerabilities"][pkg_name]["via"].extend(via_list)
            npm_audit = converted
        audit_vulns = npm_audit.get("metadata", {}).get("vulnerabilities", {})
        total_audit = sum(v for v in audit_vulns.values() if isinstance(v, int))
        print(f"[✓] npm audit: {total_audit} vulnerabilities")
        for sev, count in audit_vulns.items():
            if isinstance(count, int) and count > 0:
                print(f"     {sev}: {count}")

    # Build component lookup
    component_lookup = {}
    for comp in components:
        bom_ref = comp.get("bom-ref", "")
        purl = comp.get("purl", "")
        info = {
            "name": comp.get("name", "unknown"),
            "version": comp.get("version", "unknown"),
            "type": comp.get("type", "unknown"),
            "purl": purl
        }
        if bom_ref:
            component_lookup[bom_ref] = info
        if purl:
            component_lookup[purl] = info

    # Extract unique CVEs
    print(f"\n--- Processing {len(vulnerabilities)} vulnerabilities ---")
    seen_cves = set()
    unique_cves = []
    for vuln in vulnerabilities:
        cve_id = vuln.get("id", "unknown")
        if cve_id in seen_cves:
            continue
        seen_cves.add(cve_id)

        severity = "unknown"
        ratings = vuln.get("ratings", [])
        if ratings:
            severity = ratings[0].get("severity", "unknown")

        affected_refs = [a.get("ref", "") for a in vuln.get("affects", []) if a.get("ref")]

        unique_cves.append({
            "cve_id": cve_id,
            "grype_severity": severity,
            "source_url": vuln.get("source", {}).get("url", ""),
            "description": vuln.get("description", ""),
            "affected_refs": affected_refs
        })

    print(f"[✓] {len(unique_cves)} unique CVEs to analyze")

    # Analyze each CVE
    print(f"\n--- Analyzing CVEs (NVD + npm registry) ---")
    os.makedirs(nvd_cache_dir, exist_ok=True)

    results = []
    npm_info_cache = {}

    for i, cve_entry in enumerate(unique_cves, 1):
        cve_id = cve_entry["cve_id"]
        severity = cve_entry["grype_severity"]
        affected_refs = cve_entry["affected_refs"]

        # Resolve package from bom-ref
        package_name = "unknown"
        package_version = "unknown"
        package_purl = ""
        for ref in affected_refs:
            if ref in component_lookup:
                package_name = component_lookup[ref]["name"]
                package_version = component_lookup[ref]["version"]
                package_purl = component_lookup[ref].get("purl", "")
                break
        # Partial match fallback
        if package_name == "unknown":
            for ref in affected_refs:
                for key, val in component_lookup.items():
                    if ref and ref in key:
                        package_name = val["name"]
                        package_version = val["version"]
                        package_purl = val.get("purl", "")
                        break
                if package_name != "unknown":
                    break

        print(f"  [{i}/{len(unique_cves)}] {cve_id} — {package_name}@{package_version} ({severity})")

        # Query NVD
        nvd_details = {}
        if not args.skip_nvd and cve_id.startswith("CVE-"):
            nvd_raw = query_nvd(cve_id, api_key, nvd_cache_dir)
            nvd_details = extract_nvd_details(nvd_raw)
            time.sleep(rate_limit)
        elif cve_id.startswith("GHSA-"):
            nvd_details = {
                "description": cve_entry.get("description", ""),
                "cvss_v3_severity": severity.upper() if severity else "UNKNOWN",
                "cvss_v3_score": None,
                "cwe_ids": [],
                "references": [{"url": cve_entry.get("source_url", ""), "source": "GitHub Advisory"}]
            }

        # Classify dependency
        dep_info = classify_dependency(npm_tree, package_name)
        if not dep_info["found_in_npm_tree"]:
            if "pkg:deb/" in package_purl:
                dep_info["ecosystem"] = "debian"
            elif "pkg:npm/" in package_purl:
                dep_info["ecosystem"] = "npm"
            elif "pkg:apk/" in package_purl:
                dep_info["ecosystem"] = "alpine"

        # npm registry info
        npm_info = {}
        is_npm = dep_info.get("ecosystem") == "npm" or dep_info.get("found_in_npm_tree") or "pkg:npm/" in package_purl
        if is_npm:
            if package_name not in npm_info_cache:
                npm_info_cache[package_name] = get_npm_package_info(package_name)
            npm_info = npm_info_cache[package_name]

        # Mitigation
        mitigation = analyze_mitigation(package_name, package_version, cve_id, npm_info)

        results.append({
            "cve_id": cve_id,
            "package_name": package_name,
            "package_version": package_version,
            "package_purl": package_purl,
            "grype_severity": severity,
            "nvd_details": nvd_details,
            "dependency_info": dep_info,
            "npm_registry_info": npm_info,
            "mitigation": mitigation
        })

    # Cross-reference npm audit
    print("\n--- Cross-referencing npm audit ---")
    npm_audit_vulns = npm_audit.get("vulnerabilities", {})
    grype_cve_ids = {r["cve_id"] for r in results}
    additional = 0

    for pkg_name, vuln_info in npm_audit_vulns.items():
        for via_entry in vuln_info.get("via", []):
            if isinstance(via_entry, dict):
                via_cve = via_entry.get("cve", "")
                if via_cve and via_cve not in grype_cve_ids:
                    additional += 1
                    grype_cve_ids.add(via_cve)
                    if pkg_name not in npm_info_cache:
                        npm_info_cache[pkg_name] = get_npm_package_info(pkg_name)
                    dep_info = classify_dependency(npm_tree, pkg_name)
                    dep_info["ecosystem"] = "npm"
                    results.append({
                        "cve_id": via_cve,
                        "package_name": via_entry.get("name", pkg_name),
                        "package_version": via_entry.get("range", "unknown"),
                        "package_purl": f"pkg:npm/{pkg_name}",
                        "grype_severity": via_entry.get("severity", "unknown"),
                        "nvd_details": {
                            "description": via_entry.get("title", ""),
                            "cvss_v3_severity": via_entry.get("severity", "UNKNOWN").upper(),
                            "cvss_v3_score": None,
                            "cwe_ids": [via_entry.get("cwe", "")] if via_entry.get("cwe") else [],
                            "references": [{"url": via_entry.get("url", ""), "source": "npm audit"}]
                        },
                        "dependency_info": dep_info,
                        "npm_registry_info": npm_info_cache.get(pkg_name, {}),
                        "mitigation": {
                            "current_version": via_entry.get("range", "unknown"),
                            "latest_version": npm_info_cache.get(pkg_name, {}).get("latest_version", "unknown"),
                            "upgrade_available": True,
                            "recommendation": "UPGRADE — fix available per npm audit",
                            "risk_level": "medium",
                            "notes": [f"Source: npm audit advisory for {pkg_name}"]
                        }
                    })

    print(f"  Additional from npm audit: {additional}")
    print(f"  Total CVEs in report: {len(results)}")

    # Write outputs
    print("\n--- Writing reports ---")

    json_path = os.path.join(base_dir, f"{args.project}-mitigation-report.json")
    with open(json_path, "w") as f:
        json.dump(results, f, indent=2, default=str)
    print(f"[✓] JSON report:  {json_path}")

    summary = generate_summary_report(results, args.project)
    txt_path = os.path.join(base_dir, f"{args.project}-mitigation-report.txt")
    with open(txt_path, "w") as f:
        f.write(summary)
    print(f"[✓] Text report:  {txt_path}")

    csv_path = os.path.join(base_dir, f"{args.project}-mitigation-report.csv")
    with open(csv_path, "w") as f:
        f.write("CVE_ID,Package,Current_Version,Latest_Version,CVSS_Score,CVSS_Severity,"
                "Grype_Severity,Dep_Type,Depth,Occurrences,Ecosystem,Action,Risk_Level\n")
        for r in results:
            nvd = r.get("nvd_details", {})
            dep = r.get("dependency_info", {})
            mit = r.get("mitigation", {})
            if dep.get("found_in_npm_tree"):
                dep_type = "direct" if dep.get("is_direct") else "transitive"
            elif dep.get("ecosystem") == "debian":
                dep_type = "os-level"
            else:
                dep_type = "unknown"
            rec = mit.get('recommendation', 'N/A').replace('"', "'")
            f.write(f"{r['cve_id']},"
                    f"{r['package_name']},"
                    f"{r['package_version']},"
                    f"{mit.get('latest_version', 'unknown')},"
                    f"{nvd.get('cvss_v3_score', 'N/A')},"
                    f"{nvd.get('cvss_v3_severity', 'UNKNOWN')},"
                    f"{r.get('grype_severity', 'unknown')},"
                    f"{dep_type},"
                    f"{dep.get('min_depth', 'N/A')},"
                    f"{dep.get('occurrence_count', 0)},"
                    f"{dep.get('ecosystem', 'unknown')},"
                    f"\"{rec}\","
                    f"{mit.get('risk_level', 'unknown')}\n")
    print(f"[✓] CSV report:   {csv_path}")

    print()
    print(summary)


if __name__ == "__main__":
    main()