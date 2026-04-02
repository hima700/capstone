"""
Patched state computation for the SBOM CVE pipeline.

Methodology v17 Steps 3, 4, 5:
- Step 3: Determine the highest eligible npm version per package (<= analysis_date)
- Step 4: Enumerate intermediate versions between AS-IS and PATCHED
- Step 5: Compute PATCHED CVEs with N-day / zero-day split
"""

import json
import os

from src.normalizer import normalize_package_name, log_ambiguous_item
from src.npm_client import get_latest_by_date, get_versions_between
from src import semver_engine


def compute_patched_versions(enriched_sbom, npm_timeline, analysis_date, derived_dir):
    """
    Step 3: For each npm package, find the highest version published <= analysis_date.

    Returns patched versions dict and saves to derived/{month}-patched-versions.json.
    """
    month = enriched_sbom["month"]
    analysis_date_str = analysis_date.strftime("%Y-%m-%d")
    npm_packages = [p for p in enriched_sbom["packages"] if p["ecosystem"] == "npm"]

    patched = []
    unresolved_count = 0
    unresolved_packages = []

    for pkg in npm_packages:
        name = pkg["name"]
        asis_version = pkg["version"]
        timeline_entry = npm_timeline.get(name, {})

        if not timeline_entry:
            unresolved_count += 1
            unresolved_packages.append(name)
            log_ambiguous_item(
                package_name=name,
                version=asis_version,
                reason="package not found in npm version timeline",
                month=month,
            )
            continue

        patched_version = get_latest_by_date(timeline_entry, analysis_date)

        if not patched_version:
            unresolved_count += 1
            unresolved_packages.append(name)
            log_ambiguous_item(
                package_name=name,
                version=asis_version,
                reason="no eligible version found in timeline for analysis date",
                month=month,
            )
            continue

        asis_publish = timeline_entry.get(asis_version, "")
        patched_publish = timeline_entry.get(patched_version, "")

        patched.append({
            "package": name,
            "asis_version": asis_version,
            "patched_version": patched_version,
            "asis_publish_date": asis_publish[:10] if asis_publish else "",
            "patched_publish_date": patched_publish[:10] if patched_publish else "",
            "already_at_latest": asis_version == patched_version,
            "depth": pkg.get("depth", "unknown_dependency_depth"),
        })

    result = {
        "month": month,
        "analysis_date": analysis_date_str,
        "patched_versions": patched,
        "unresolved_count": unresolved_count,
        "unresolved_packages": unresolved_packages,
    }

    os.makedirs(derived_dir, exist_ok=True)
    out_path = os.path.join(derived_dir, f"{month}-patched-versions.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)

    return result


def enumerate_intermediates(patched_versions_data, npm_timeline, master_cve_ref,
                            analysis_date, derived_dir):
    """
    Step 4: For packages where AS-IS != PATCHED, list all intermediate versions
    and compute CVE counts for each.
    """
    month = patched_versions_data["month"]
    analysis_date_str = analysis_date.strftime("%Y-%m-%d")
    advisories_by_pkg = _index_advisories_by_package(master_cve_ref)

    intermediates = {}

    for pv in patched_versions_data["patched_versions"]:
        if pv["already_at_latest"]:
            continue

        name = pv["package"]
        asis_ver = pv["asis_version"]
        patched_ver = pv["patched_version"]
        timeline_entry = npm_timeline.get(name, {})

        versions = get_versions_between(timeline_entry, asis_ver, patched_ver, analysis_date)
        if not versions:
            continue

        version_data = []
        pkg_advisories = advisories_by_pkg.get(normalize_package_name(name), [])

        if pkg_advisories:
            all_checks = []
            check_map = []
            for ver in versions:
                for adv_id, adv, affected in pkg_advisories:
                    for range_str in affected.get("vulnerable_ranges", []):
                        all_checks.append((ver, range_str))
                        check_map.append((ver, adv_id, adv, range_str))

            if all_checks:
                results = semver_engine.satisfies_batch(all_checks)
            else:
                results = []

            ver_cves = {}
            for i, is_match in enumerate(results):
                if not is_match:
                    continue
                ver, adv_id, adv, _ = check_map[i]
                ver_cves.setdefault(ver, {})[adv_id] = adv

        else:
            ver_cves = {}

        for ver in versions:
            matched = ver_cves.get(ver, {})
            nday = 0
            zeroday = 0
            cve_ids = []
            for adv_id, adv in matched.items():
                pub = adv.get("published_date", "")
                cve_ids.append(adv_id)
                if pub and pub <= analysis_date_str:
                    nday += 1
                else:
                    zeroday += 1

            ver_release = timeline_entry.get(ver, "")
            version_data.append({
                "version": ver,
                "release_date": ver_release[:10] if ver_release else "",
                "cve_count": len(cve_ids),
                "cve_ids": sorted(cve_ids),
                "nday_count": nday,
                "zeroday_count": zeroday,
            })

        intermediates[name] = {
            "asis_version": asis_ver,
            "patched_version": patched_ver,
            "versions_queried": len(version_data),
            "version_data": version_data,
        }

    result = {
        "month": month,
        "analysis_date": analysis_date_str,
        "packages": intermediates,
    }

    os.makedirs(derived_dir, exist_ok=True)
    out_path = os.path.join(derived_dir, f"{month}-intermediate-versions.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)

    return result


def compute_patched_cves(patched_versions_data, asis_cves_data, master_cve_ref,
                         analysis_date, derived_dir):
    """
    Step 5: For each package at its PATCHED version, find all matching CVEs.
    Split into N-day (published <= analysis_date) and zero-day (published > analysis_date).
    Identify churn-introduced CVEs (in PATCHED but not in AS-IS).
    """
    month = patched_versions_data["month"]
    analysis_date_str = analysis_date.strftime("%Y-%m-%d")
    advisories_by_pkg = _index_advisories_by_package(master_cve_ref)

    asis_cve_set = set(m["cve_id"] for m in asis_cves_data.get("cves", []))

    all_checks = []
    check_map = []

    for pv in patched_versions_data["patched_versions"]:
        name = pv["package"]
        patched_ver = pv["patched_version"]
        pkg_advisories = advisories_by_pkg.get(normalize_package_name(name), [])

        for adv_id, adv, affected in pkg_advisories:
            for range_str in affected.get("vulnerable_ranges", []):
                all_checks.append((patched_ver, range_str))
                check_map.append({
                    "package": name,
                    "patched_version": patched_ver,
                    "adv_id": adv_id,
                    "adv": adv,
                    "depth": pv.get("depth", "unknown_dependency_depth"),
                })

    if all_checks:
        semver_results = semver_engine.satisfies_batch(all_checks)
    else:
        semver_results = []

    patched_matches = {}
    for i, result in enumerate(semver_results):
        if not result:
            continue
        meta = check_map[i]
        match_key = f"{meta['adv_id']}|{meta['package']}|{meta['patched_version']}"
        if match_key in patched_matches:
            continue

        adv = meta["adv"]
        pub_date = adv.get("published_date", "")
        is_nday = bool(pub_date and pub_date <= analysis_date_str)
        is_zeroday = bool(pub_date and pub_date > analysis_date_str)
        is_churn = meta["adv_id"] not in asis_cve_set

        patched_matches[match_key] = {
            "cve_id": meta["adv_id"],
            "package": meta["package"],
            "patched_version": meta["patched_version"],
            "published_date": pub_date,
            "severity": adv.get("severity", "UNKNOWN"),
            "depth": meta["depth"],
            "is_nday": is_nday,
            "is_zeroday": is_zeroday,
            "is_churn_introduced": is_churn,
        }

    patched_cve_list = list(patched_matches.values())

    nday_cves = [c for c in patched_cve_list if c["is_nday"]]
    zeroday_cves = [c for c in patched_cve_list if c["is_zeroday"]]
    churn_cves = [c for c in patched_cve_list if c["is_churn_introduced"]]

    patched_vuln_packages = set(
        f"{c['package']}@{c['patched_version']}" for c in patched_cve_list
    )

    unique_nday_ids = set(c["cve_id"] for c in nday_cves)
    unique_zeroday_ids = set(c["cve_id"] for c in zeroday_cves)

    result = {
        "month": month,
        "analysis_date": analysis_date_str,
        "patched_cves": patched_cve_list,
        "summary": {
            "patched_total_cves": len(unique_nday_ids | unique_zeroday_ids),
            "patched_nday": len(unique_nday_ids),
            "patched_zeroday": len(unique_zeroday_ids),
            "patched_npm_packages_vulnerable": len(patched_vuln_packages),
            "churn_introduced_total": len(set(c["cve_id"] for c in churn_cves)),
        },
    }

    os.makedirs(derived_dir, exist_ok=True)
    out_path = os.path.join(derived_dir, f"{month}-patched-cves.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)

    return result


def _index_advisories_by_package(master_cve_ref):
    """Build lookup: normalized_package_name -> [(adv_id, adv, affected_entry), ...]"""
    index = {}
    for adv_id, adv in master_cve_ref.items():
        for affected in adv.get("affected", []):
            pkg_name = normalize_package_name(affected.get("package", ""))
            if pkg_name:
                index.setdefault(pkg_name, []).append((adv_id, adv, affected))
    return index
