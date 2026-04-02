"""
AS-IS CVE matching for the SBOM CVE pipeline.

Methodology v17 Step 2: For each dependency+version in the AS-IS SBOM,
find all CVEs whose affected range includes the version AND whose
published_date <= analysis_date.

Uses semver_engine for npm range matching (never packaging.version).
"""

import json
import os

from src.normalizer import normalize_package_name, log_ambiguous_item
from src import semver_engine


def match_asis_cves(enriched_sbom, master_cve_ref, analysis_date, derived_dir):
    """
    Match all packages in the enriched SBOM against the master CVE reference.

    For each npm package-version:
    1. Find all advisories in master ref that affect this package
    2. Use semver_engine to check if the version falls in the affected range
    3. Filter: only include if published_date <= analysis_date
    4. Tag with severity, ecosystem, direct/transitive from SBOM

    Returns the AS-IS CVE result dict and saves to derived/{month}-asis-cves.json.
    """
    month = enriched_sbom["month"]
    analysis_date_str = analysis_date.strftime("%Y-%m-%d")

    advisories_by_package = _index_advisories_by_package(master_cve_ref)

    all_matches = []
    excluded_advisory_count = 0
    packages_checked = 0
    semver_checks = []
    check_metadata = []

    npm_packages = [p for p in enriched_sbom["packages"] if p["ecosystem"] == "npm"]

    for pkg in npm_packages:
        name = normalize_package_name(pkg["name"])
        version = pkg["version"]
        depth = pkg.get("depth", "unknown_dependency_depth")

        pkg_advisories = advisories_by_package.get(name, [])
        packages_checked += 1

        for adv_id, adv, affected_entry in pkg_advisories:
            pub_date = adv.get("published_date", "")
            if not pub_date or pub_date > analysis_date_str:
                continue

            for range_str in affected_entry.get("vulnerable_ranges", []):
                semver_checks.append((version, range_str))
                check_metadata.append({
                    "adv_id": adv_id,
                    "adv": adv,
                    "pkg": pkg,
                    "depth": depth,
                    "range_str": range_str,
                })

    if semver_checks:
        semver_results = semver_engine.satisfies_batch(semver_checks)
    else:
        semver_results = []

    matched_cves = {}
    for i, result in enumerate(semver_results):
        meta = check_metadata[i]
        if result is None:
            excluded_advisory_count += 1
            log_ambiguous_item(
                package_name=meta["pkg"]["name"],
                version=meta["pkg"]["version"],
                reason=f"unparseable advisory range: {meta['range_str']}",
                month=month,
            )
            continue
        if not result:
            continue

        adv_id = meta["adv_id"]
        adv = meta["adv"]
        pkg = meta["pkg"]
        depth = meta["depth"]

        match_key = f"{adv_id}|{pkg['name']}|{pkg['version']}"
        if match_key in matched_cves:
            continue

        matched_cves[match_key] = {
            "cve_id": adv_id,
            "aliases": adv.get("aliases", []),
            "published_date": adv.get("published_date", ""),
            "severity": adv.get("severity", "UNKNOWN"),
            "package": pkg["name"],
            "version": pkg["version"],
            "ecosystem": pkg["ecosystem"],
            "depth": depth,
            "matched_range": meta["range_str"],
            "source_url": adv.get("source_url", ""),
        }

    cve_list = list(matched_cves.values())

    npm_vuln_packages = set()
    npm_all_packages = set()
    for pkg in npm_packages:
        npm_all_packages.add(f"{pkg['name']}@{pkg['version']}")
    for m in cve_list:
        if m["ecosystem"] == "npm":
            npm_vuln_packages.add(f"{m['package']}@{m['version']}")

    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    for m in cve_list:
        sev = m["severity"]
        if sev in severity_counts:
            severity_counts[sev] += 1
        else:
            severity_counts["UNKNOWN"] += 1

    npm_cves = [m for m in cve_list if m["ecosystem"] == "npm"]
    direct_npm_cves = [m for m in npm_cves if m["depth"] == "direct"]
    transitive_npm_cves = [m for m in npm_cves if m["depth"] == "transitive"]

    direct_vuln_pkgs = set(f"{m['package']}@{m['version']}" for m in direct_npm_cves)
    transitive_vuln_pkgs = set(f"{m['package']}@{m['version']}" for m in transitive_npm_cves)

    unique_cve_ids = set(m["cve_id"] for m in cve_list)

    result = {
        "month": month,
        "analysis_date": analysis_date_str,
        "cves": cve_list,
        "summary": {
            "asis_total_cves": len(unique_cve_ids),
            "asis_npm_cves": len(set(m["cve_id"] for m in npm_cves)),
            "asis_severity_critical": severity_counts["CRITICAL"],
            "asis_severity_high": severity_counts["HIGH"],
            "asis_severity_medium": severity_counts["MEDIUM"],
            "asis_severity_low": severity_counts["LOW"],
            "npm_packages_total": len(npm_all_packages),
            "npm_packages_vulnerable": len(npm_vuln_packages),
            "npm_packages_non_vulnerable": len(npm_all_packages) - len(npm_vuln_packages),
            "direct_vulnerable_npm_packages": len(direct_vuln_pkgs),
            "transitive_vulnerable_npm_packages": len(transitive_vuln_pkgs),
            "direct_npm_dep_cves": len(set(m["cve_id"] for m in direct_npm_cves)),
            "transitive_npm_dep_cves": len(set(m["cve_id"] for m in transitive_npm_cves)),
            "excluded_advisory_count": excluded_advisory_count,
            "packages_checked": packages_checked,
        },
    }

    os.makedirs(derived_dir, exist_ok=True)
    out_path = os.path.join(derived_dir, f"{month}-asis-cves.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)

    return result


def _index_advisories_by_package(master_cve_ref):
    """
    Build a lookup: package_name -> [(adv_id, adv_dict, affected_entry), ...]

    This avoids scanning all 305 advisories for every package.
    """
    index = {}
    for adv_id, adv in master_cve_ref.items():
        for affected in adv.get("affected", []):
            pkg_name = normalize_package_name(affected.get("package", ""))
            if not pkg_name:
                continue
            index.setdefault(pkg_name, []).append((adv_id, adv, affected))
    return index
