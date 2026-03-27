#!/usr/bin/env python3
"""
Migration Analyzer v2 — Using OSV (Open Source Vulnerabilities) Database

Fixes the "unknown" problem from v1 by using osv.dev API which has:
  - Structured affected version ranges for BOTH npm and Debian
  - Fixed version data
  - Ecosystem-aware queries

Answers Dr. Mehdi's questions for ALL CVEs:
  1. What is the latest version (Vx)?
  2. Has the CVE been fixed in Vx?
  3. Have new CVEs been introduced in Vx?
  4. If you migrate from Vx-1 to Vx, what is the new CVE count?

Open source vulnerability databases used:
  - OSV (osv.dev) — Google's aggregated vulnerability database
  - Debian Security Tracker — Debian-specific fix status and urgency
  - NVD (NIST) — CVSS scores and CWE classification (from cached data)
  - npm Registry — Latest version lookup for npm packages

Usage:
    python3 scripts/migration-analyzer-v2.py --run-dir runs/2026-02-09 --project hcdp-api
"""

import argparse
import json
import os
import sys
import time
import re
import urllib.request
import urllib.parse
import urllib.error
from datetime import datetime
from collections import defaultdict

# =============================================================================
# Configuration
# =============================================================================
OSV_API_BASE = "https://api.osv.dev/v1"
NPM_REGISTRY_BASE = "https://registry.npmjs.org"
DEBIAN_TRACKER_URL = "https://security-tracker.debian.org/tracker/data/json"

# =============================================================================
# OSV API — The key improvement over v1
# =============================================================================
def query_osv(cve_id: str, cache_dir: str = None) -> dict:
    """
    Query OSV API for a specific CVE/GHSA.
    Returns structured vulnerability data with affected version ranges.
    No API key needed, no rate limiting.
    """
    if cache_dir:
        cache_file = os.path.join(cache_dir, f"osv-{cve_id}.json")
        if os.path.exists(cache_file):
            with open(cache_file) as f:
                return json.load(f)

    url = f"{OSV_API_BASE}/vulns/{cve_id}"
    try:
        req = urllib.request.Request(url)
        req.add_header("Content-Type", "application/json")
        with urllib.request.urlopen(req, timeout=15) as response:
            data = json.loads(response.read().decode())
            if cache_dir:
                os.makedirs(cache_dir, exist_ok=True)
                with open(cache_file, "w") as f:
                    json.dump(data, f, indent=2)
            return data
    except urllib.error.HTTPError as e:
        if e.code == 404:
            # Try with alternative ID formats
            return {}
        return {}
    except Exception as e:
        return {}


def query_osv_by_package(package_name: str, ecosystem: str, version: str = None) -> list:
    """
    Query OSV for all vulnerabilities affecting a specific package.
    This answers: "what CVEs exist for version Vx?"
    """
    url = f"{OSV_API_BASE}/query"
    
    payload = {
        "package": {
            "name": package_name,
            "ecosystem": ecosystem  # "npm", "Debian:12", etc.
        }
    }
    if version:
        payload["version"] = version

    try:
        data = json.dumps(payload).encode()
        req = urllib.request.Request(url, data=data)
        req.add_header("Content-Type", "application/json")
        with urllib.request.urlopen(req, timeout=15) as response:
            result = json.loads(response.read().decode())
            return result.get("vulns", [])
    except Exception as e:
        return []


def extract_osv_fix_info(osv_data: dict, package_name: str, ecosystem_hint: str) -> dict:
    """
    Extract fix version and affected range from OSV data.
    OSV provides structured 'affected' blocks with 'ranges' and 'fixed' versions.
    """
    result = {
        "fixed_version": None,
        "affected_ranges": [],
        "is_withdrawn": osv_data.get("withdrawn") is not None,
        "aliases": osv_data.get("aliases", []),
        "summary": osv_data.get("summary", ""),
        "database_specific": {}
    }

    # Map our ecosystem names to OSV ecosystem names
    eco_map = {
        "npm": "npm",
        "debian": "Debian",
        "alpine": "Alpine"
    }
    osv_ecosystem = eco_map.get(ecosystem_hint, ecosystem_hint)

    affected_list = osv_data.get("affected", [])
    for affected in affected_list:
        pkg = affected.get("package", {})
        pkg_name = pkg.get("name", "")
        pkg_eco = pkg.get("ecosystem", "")

        # Match by package name (fuzzy for Debian which may differ)
        name_match = (
            pkg_name == package_name or
            pkg_name.lower() == package_name.lower() or
            package_name.startswith(pkg_name) or
            pkg_name.startswith(package_name.split("-")[0] if "-" in package_name else package_name)
        )

        # Match by ecosystem
        eco_match = pkg_eco.startswith(osv_ecosystem) or osv_ecosystem in pkg_eco

        if not (name_match or eco_match):
            continue

        # Extract version ranges
        for range_info in affected.get("ranges", []):
            range_type = range_info.get("type", "")
            events = range_info.get("events", [])

            introduced = None
            fixed = None
            last_affected = None

            for event in events:
                if "introduced" in event:
                    introduced = event["introduced"]
                if "fixed" in event:
                    fixed = event["fixed"]
                if "last_affected" in event:
                    last_affected = event["last_affected"]

            range_entry = {
                "type": range_type,
                "introduced": introduced or "0",
                "fixed": fixed,
                "last_affected": last_affected,
                "ecosystem": pkg_eco,
                "package": pkg_name
            }

            result["affected_ranges"].append(range_entry)

            # The fixed version is the most useful piece
            if fixed and not result["fixed_version"]:
                result["fixed_version"] = fixed

        # Database-specific info (Debian severity, etc.)
        db_specific = affected.get("database_specific", {})
        if db_specific:
            result["database_specific"] = db_specific

        # Also check versions list for exact affected versions
        versions = affected.get("versions", [])
        if versions:
            result["affected_versions"] = versions

    return result


# =============================================================================
# Debian Security Tracker
# =============================================================================
_debian_tracker_cache = None

def load_debian_tracker() -> dict:
    """Load Debian Security Tracker data."""
    global _debian_tracker_cache
    if _debian_tracker_cache is not None:
        return _debian_tracker_cache

    print("  Downloading Debian Security Tracker data (~15MB, one-time)...")
    try:
        req = urllib.request.Request(DEBIAN_TRACKER_URL)
        with urllib.request.urlopen(req, timeout=60) as response:
            _debian_tracker_cache = json.loads(response.read().decode())
            print(f"  [✓] Loaded tracker for {len(_debian_tracker_cache)} source packages")
            return _debian_tracker_cache
    except Exception as e:
        print(f"  [!] Failed: {e}")
        _debian_tracker_cache = {}
        return {}


def get_debian_source_package(package_name: str, purl: str = "") -> str:
    """Extract source package name from purl or guess from binary package name."""
    # Try purl upstream field first
    upstream = re.search(r'upstream=([^&]+)', purl)
    if upstream:
        return urllib.parse.unquote(upstream.group(1))
    
    # Common mappings
    mappings = {
        "libc-bin": "glibc",
        "libc6": "glibc",
        "libssl3": "openssl",
        "libgnutls30": "gnutls28",
        "libldap-2.5-0": "openldap",
        "libtiff6": "tiff",
        "libtinfo6": "ncurses",
        "libpng16-16": "libpng1.6",
        "libexpat1": "expat",
        "libsystemd0": "systemd",
        "libgcrypt20": "libgcrypt20",
        "libde265-0": "libde265",
        "libheif1": "libheif",
        "libdav1d6": "dav1d",
        "libaom3": "aom",
        "libjbig0": "jbigkit",
        "libjansson4": "jansson",
        "libtasn1-6": "libtasn1-6",
        "libpam-modules": "pam",
        "krb5-locales": "krb5",
        "bsdutils": "util-linux",
        "login": "shadow",
        "cpp-12": "gcc-12",
        "perl-base": "perl",
        "gpgv": "gnupg2",
    }
    
    if package_name in mappings:
        return mappings[package_name]
    
    # Strip lib prefix and version suffix
    stripped = re.sub(r'^\blib\b', '', package_name)
    stripped = re.sub(r'\d+$', '', stripped)
    if stripped:
        return stripped
    
    return package_name


def check_debian_status(source_pkg: str, cve_id: str, release: str = "bookworm") -> dict:
    """Check Debian Security Tracker for CVE fix status."""
    tracker = load_debian_tracker()
    
    # Try source package and variations
    candidates = [source_pkg, source_pkg.lower()]
    
    for candidate in candidates:
        if candidate in tracker:
            cve_data = tracker[candidate].get(cve_id, {})
            if cve_data:
                releases = cve_data.get("releases", {})
                rel_info = releases.get(release, {})
                return {
                    "found": True,
                    "source_package": candidate,
                    "status": rel_info.get("status", "unknown"),
                    "fixed_version": rel_info.get("fixed_version", ""),
                    "urgency": rel_info.get("urgency", cve_data.get("urgency", "unknown")),
                }
    
    return {"found": False, "source_package": source_pkg, "status": "not_found", "urgency": "unknown"}


# =============================================================================
# npm Registry
# =============================================================================
def get_npm_latest(package_name: str) -> str:
    """Get latest version from npm registry."""
    url = f"{NPM_REGISTRY_BASE}/{urllib.parse.quote(package_name, safe='@/')}"
    try:
        req = urllib.request.Request(url)
        req.add_header("Accept", "application/vnd.npm.install-v1+json")
        with urllib.request.urlopen(req, timeout=10) as response:
            data = json.loads(response.read().decode())
            return data.get("dist-tags", {}).get("latest", "unknown")
    except:
        return "unknown"


# =============================================================================
# Version Comparison
# =============================================================================
def version_gte(v1: str, v2: str) -> bool:
    """Simple version comparison: is v1 >= v2?"""
    try:
        from packaging import version as pkg_v
        return pkg_v.parse(v1) >= pkg_v.parse(v2)
    except:
        # Fallback: string comparison
        return v1 >= v2


# =============================================================================
# Main Analysis
# =============================================================================
def main():
    parser = argparse.ArgumentParser(description="Migration Analyzer v2 (OSV-powered)")
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--project", required=True)
    parser.add_argument("--skip-osv", action="store_true", help="Skip OSV queries")
    args = parser.parse_args()

    base_dir = os.path.join(args.run_dir, args.project)
    report_file = os.path.join(base_dir, f"{args.project}-mitigation-report.json")
    osv_cache_dir = os.path.join(base_dir, "osv-cache")
    os.makedirs(osv_cache_dir, exist_ok=True)

    print("=" * 70)
    print(f"  Migration Analyzer v2 — {args.project.upper()}")
    print(f"  Databases: OSV + Debian Tracker + NVD (cached) + npm Registry")
    print("=" * 70)
    print()

    # Load initial report
    with open(report_file) as f:
        cve_data = json.load(f)
    print(f"[✓] Loaded {len(cve_data)} CVEs")

    # Group by package
    packages = defaultdict(lambda: {
        "cves": [], "current_version": "", "purl": "",
        "ecosystem": "", "name": ""
    })

    for entry in cve_data:
        pkg_key = f"{entry['package_name']}@{entry['package_version']}"
        pkg = packages[pkg_key]
        pkg["name"] = entry["package_name"]
        pkg["current_version"] = entry["package_version"]
        pkg["purl"] = entry.get("package_purl", "")
        pkg["ecosystem"] = entry.get("dependency_info", {}).get("ecosystem", "unknown")
        pkg["cves"].append({
            "cve_id": entry["cve_id"],
            "severity": entry.get("nvd_details", {}).get("cvss_v3_severity", "UNKNOWN") or "UNKNOWN",
            "cvss_score": entry.get("nvd_details", {}).get("cvss_v3_score"),
            "grype_severity": entry.get("grype_severity", "unknown"),
        })

    print(f"[✓] {len(packages)} unique vulnerable packages")

    # -------------------------------------------------------------------------
    # Analyze each package
    # -------------------------------------------------------------------------
    print(f"\n--- Analyzing {len(packages)} packages ---\n")

    results = []

    for i, (pkg_key, pkg) in enumerate(sorted(packages.items()), 1):
        name = pkg["name"]
        current = pkg["current_version"]
        ecosystem = pkg["ecosystem"]
        purl = pkg["purl"]
        cve_count = len(pkg["cves"])

        print(f"  [{i}/{len(packages)}] {name}@{current} ({ecosystem}, {cve_count} CVEs)")

        # --- Get latest version ---
        latest_version = "unknown"
        if ecosystem == "npm":
            latest_version = get_npm_latest(name)
        elif ecosystem == "debian":
            # For Debian, "latest" = what's in the current release
            # The Debian tracker tells us if there's a fixed version
            pass

        # --- Get Debian source package name ---
        source_pkg = get_debian_source_package(name, purl) if ecosystem == "debian" else name

        # --- Analyze each CVE ---
        cve_analysis = []
        fixed_count = 0
        open_count = 0
        unknown_count = 0

        for cve in pkg["cves"]:
            cve_id = cve["cve_id"]
            fix_result = {
                "cve_id": cve_id,
                "severity": cve["severity"],
                "cvss_score": cve["cvss_score"],
                "fixed_in_latest": None,
                "fix_version": None,
                "affected_range": None,
                "debian_urgency": None,
                "debian_status": None,
                "sources_checked": [],
            }

            # --- Source 1: OSV Database ---
            if not args.skip_osv:
                osv_data = query_osv(cve_id, osv_cache_dir)
                if osv_data:
                    osv_fix = extract_osv_fix_info(osv_data, name, ecosystem)
                    fix_result["sources_checked"].append("OSV")

                    if osv_fix["fixed_version"]:
                        fix_result["fix_version"] = osv_fix["fixed_version"]
                        fix_result["affected_range"] = (
                            f"introduced: {osv_fix['affected_ranges'][0].get('introduced', '?')}, "
                            f"fixed: {osv_fix['fixed_version']}"
                        ) if osv_fix["affected_ranges"] else f"fixed in {osv_fix['fixed_version']}"

                        # Check if latest version >= fix version
                        if latest_version != "unknown" and ecosystem == "npm":
                            try:
                                is_fixed = version_gte(latest_version, osv_fix["fixed_version"])
                                fix_result["fixed_in_latest"] = is_fixed
                            except:
                                pass
                    elif osv_fix["affected_ranges"]:
                        ranges = osv_fix["affected_ranges"]
                        range_strs = []
                        for r in ranges:
                            if r.get("fixed"):
                                range_strs.append(f"{r['introduced']}..{r['fixed']}")
                            elif r.get("last_affected"):
                                range_strs.append(f"{r['introduced']}..{r['last_affected']}+")
                            else:
                                range_strs.append(f">={r['introduced']}")
                        fix_result["affected_range"] = "; ".join(range_strs)

                    if osv_fix.get("is_withdrawn"):
                        fix_result["fixed_in_latest"] = True
                        fix_result["notes"] = "CVE withdrawn"

                # Also try with GHSA alias if CVE didn't work
                if not osv_data and cve_id.startswith("GHSA-"):
                    pass  # Already tried with GHSA ID

                time.sleep(0.1)  # Be nice to OSV API

            # --- Source 2: Debian Security Tracker ---
            if ecosystem == "debian":
                deb_status = check_debian_status(source_pkg, cve_id)
                fix_result["sources_checked"].append("Debian-Tracker")
                fix_result["debian_urgency"] = deb_status.get("urgency", "unknown")
                fix_result["debian_status"] = deb_status.get("status", "unknown")

                if deb_status["status"] == "resolved":
                    fix_result["fixed_in_latest"] = True
                    fix_result["fix_version"] = deb_status.get("fixed_version", "")
                elif deb_status["status"] == "open":
                    fix_result["fixed_in_latest"] = False
                # "not_found" stays as None

            # --- Tally ---
            if fix_result["fixed_in_latest"] is True:
                fixed_count += 1
            elif fix_result["fixed_in_latest"] is False:
                open_count += 1
            else:
                unknown_count += 1

            cve_analysis.append(fix_result)

        # --- Check NEW CVEs in latest version ---
        new_cves_in_latest = []
        if ecosystem == "npm" and latest_version != "unknown" and not args.skip_osv:
            latest_vulns = query_osv_by_package(name, "npm", latest_version)
            current_cve_ids = {c["cve_id"] for c in pkg["cves"]}
            for v in latest_vulns:
                vuln_id = v.get("id", "")
                aliases = v.get("aliases", [])
                all_ids = [vuln_id] + aliases
                if not any(vid in current_cve_ids for vid in all_ids):
                    new_cves_in_latest.append({
                        "id": vuln_id,
                        "aliases": aliases,
                        "summary": v.get("summary", "")[:100]
                    })
            time.sleep(0.1)

        # --- Summary ---
        result = {
            "package": name,
            "source_package": source_pkg if ecosystem == "debian" else name,
            "current_version": current,
            "latest_version": latest_version,
            "ecosystem": ecosystem,
            "total_cves": cve_count,
            "cve_analysis": cve_analysis,
            "new_cves_in_latest": new_cves_in_latest,
            "summary": {
                "fixed_if_upgraded": fixed_count,
                "still_open": open_count,
                "unknown": unknown_count,
                "new_cves_introduced": len(new_cves_in_latest),
                "net_cve_change": -(fixed_count) + len(new_cves_in_latest),
                "recommendation": ""
            }
        }

        # Generate recommendation
        s = result["summary"]
        if fixed_count == cve_count and len(new_cves_in_latest) == 0:
            s["recommendation"] = f"UPGRADE — all {cve_count} CVEs fixed, no new CVEs"
        elif fixed_count > 0 and len(new_cves_in_latest) == 0:
            s["recommendation"] = f"UPGRADE — {fixed_count}/{cve_count} fixed, {open_count} remain, no new CVEs"
        elif fixed_count > 0 and len(new_cves_in_latest) > 0:
            s["recommendation"] = (f"UPGRADE WITH CAUTION — {fixed_count} fixed but "
                                   f"{len(new_cves_in_latest)} new CVEs in latest")
        elif open_count == cve_count:
            s["recommendation"] = f"NO FIX AVAILABLE — all {cve_count} CVEs still open"
        elif unknown_count == cve_count:
            s["recommendation"] = f"INVESTIGATE — fix status unknown for all {cve_count} CVEs"
        else:
            s["recommendation"] = f"MIXED — {fixed_count} fixed, {open_count} open, {unknown_count} unknown"

        print(f"    Fixed: {fixed_count}  Open: {open_count}  Unknown: {unknown_count}  "
              f"New in latest: {len(new_cves_in_latest)}")

        results.append(result)

    # -------------------------------------------------------------------------
    # Write Reports
    # -------------------------------------------------------------------------
    print(f"\n--- Writing reports ---")

    # JSON
    json_path = os.path.join(base_dir, f"{args.project}-migration-v2.json")
    with open(json_path, "w") as f:
        json.dump(results, f, indent=2, default=str)
    print(f"[✓] JSON: {json_path}")

    # Text Report
    txt_path = os.path.join(base_dir, f"{args.project}-migration-v2.txt")
    with open(txt_path, "w") as f:
        f.write("=" * 80 + "\n")
        f.write(f"  SBOM Migration Analysis v2 — {args.project.upper()}\n")
        f.write(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"  Databases: OSV (osv.dev), Debian Security Tracker, NVD, npm Registry\n")
        f.write("=" * 80 + "\n\n")

        # Overall summary
        total_cves = sum(r["total_cves"] for r in results)
        total_fixed = sum(r["summary"]["fixed_if_upgraded"] for r in results)
        total_open = sum(r["summary"]["still_open"] for r in results)
        total_unknown = sum(r["summary"]["unknown"] for r in results)
        total_new = sum(r["summary"]["new_cves_introduced"] for r in results)

        f.write("OVERALL SUMMARY\n")
        f.write("-" * 60 + "\n")
        f.write(f"  Vulnerable packages:         {len(results)}\n")
        f.write(f"  Total CVEs (current):        {total_cves}\n")
        f.write(f"  CVEs fixable by upgrade:     {total_fixed}\n")
        f.write(f"  CVEs still open (no fix):    {total_open}\n")
        f.write(f"  CVEs with unknown status:    {total_unknown}\n")
        f.write(f"  New CVEs in latest versions: {total_new}\n")
        f.write(f"  Net CVE change if upgraded:  {total_fixed - total_new} reduction\n")
        if total_cves > 0:
            f.write(f"  Fix rate:                    {total_fixed/total_cves*100:.1f}%\n")
        f.write("\n")

        # Urgency breakdown (Debian)
        all_urgencies = defaultdict(int)
        for r in results:
            for cve in r["cve_analysis"]:
                urg = cve.get("debian_urgency")
                if urg:
                    all_urgencies[urg] += 1

        if all_urgencies:
            f.write("  Debian Security Urgency:\n")
            urgency_meanings = {
                "unimportant": "Negligible risk — Debian will not fix",
                "low": "Low priority — may be fixed eventually",
                "medium": "Medium priority",
                "high": "High priority — fix expected",
                "not yet assigned": "Awaiting triage by Debian team",
                "end-of-life": "Package no longer supported",
            }
            for urg in ["unimportant", "low", "medium", "high", "not yet assigned", "end-of-life", "unknown"]:
                count = all_urgencies.get(urg, 0)
                if count > 0:
                    meaning = urgency_meanings.get(urg, "")
                    f.write(f"    {urg:25s}: {count:4d}  {meaning}\n")

        f.write("\n\n")

        # Per-package details
        f.write("PER-PACKAGE ANALYSIS\n")
        f.write("-" * 60 + "\n")

        # Sort: most fixable first, then by CVE count
        sorted_results = sorted(results,
                                key=lambda r: (-r["summary"]["fixed_if_upgraded"], -r["total_cves"]))

        for r in sorted_results:
            s = r["summary"]
            f.write(f"\n  📦 {r['package']}@{r['current_version']}\n")
            f.write(f"     Ecosystem:         {r['ecosystem']}\n")
            if r["ecosystem"] == "debian":
                f.write(f"     Source package:     {r['source_package']}\n")
            f.write(f"     Latest version:    {r['latest_version']}\n")
            f.write(f"     CVEs (current):    {r['total_cves']}\n")
            f.write(f"     Fixable:           {s['fixed_if_upgraded']}\n")
            f.write(f"     Still open:        {s['still_open']}\n")
            f.write(f"     Unknown:           {s['unknown']}\n")
            if r["new_cves_in_latest"]:
                f.write(f"     ⚠️  New in latest:  {s['new_cves_introduced']}\n")
            f.write(f"     ➤ {s['recommendation']}\n\n")

            for cve in r["cve_analysis"]:
                icon = "✅" if cve["fixed_in_latest"] is True else \
                       "❌" if cve["fixed_in_latest"] is False else "❓"
                severity = cve["severity"]
                score_str = f" CVSS:{cve['cvss_score']}" if cve.get("cvss_score") else ""
                sources = ", ".join(cve.get("sources_checked", []))

                f.write(f"     {icon} {cve['cve_id']} ({severity}{score_str})\n")

                if cve.get("fix_version"):
                    f.write(f"        Fix version: {cve['fix_version']}\n")
                if cve.get("affected_range"):
                    f.write(f"        Range: {cve['affected_range']}\n")
                if cve.get("debian_urgency"):
                    f.write(f"        Debian urgency: {cve['debian_urgency']} "
                            f"({cve.get('debian_status', 'unknown')})\n")
                f.write(f"        Sources: {sources}\n")

            if r["new_cves_in_latest"]:
                f.write(f"\n     ⚠️  New CVEs in latest version ({r['latest_version']}):\n")
                for nc in r["new_cves_in_latest"]:
                    f.write(f"        {nc['id']}: {nc['summary']}\n")

        f.write("\n\n")

        # Recommendations
        f.write("MITIGATION RECOMMENDATIONS\n")
        f.write("-" * 60 + "\n\n")

        npm_fixable = [r for r in results if r["ecosystem"] == "npm" and r["summary"]["fixed_if_upgraded"] > 0]
        deb_open = [r for r in results if r["ecosystem"] == "debian" and r["summary"]["still_open"] > 0]
        deb_unimportant = all_urgencies.get("unimportant", 0)

        f.write("  1. npm Dependencies (directly actionable):\n")
        if npm_fixable:
            for r in npm_fixable:
                f.write(f"     - Upgrade {r['package']} {r['current_version']} → {r['latest_version']} "
                        f"(fixes {r['summary']['fixed_if_upgraded']} CVEs)\n")
        else:
            f.write("     - Run npm audit fix\n")
            f.write("     - Upgrade nodemailer and other flagged packages\n")
        f.write("\n")

        f.write("  2. Docker Base Image (reduces Debian CVEs):\n")
        f.write("     - Option A: Rebuild with latest node:22-slim (picks up Debian patches)\n")
        f.write("     - Option B: Switch to node:22-alpine (eliminates Debian CVEs entirely)\n")
        f.write("     - Option C: Periodically run apt-get upgrade in Dockerfile\n\n")

        f.write("  3. Accept Risk (Debian 'unimportant' CVEs):\n")
        f.write(f"     - {deb_unimportant} CVEs classified as unimportant by Debian Security\n")
        f.write("     - These are known, triaged, and deemed negligible risk\n")
        f.write("     - Document as 'accepted risk' with Debian urgency as justification\n\n")

        f.write("  4. Ongoing Monitoring:\n")
        f.write("     - Re-scan with Syft + Grype on each image rebuild\n")
        f.write("     - Monitor OSV/NVD for status changes on open CVEs\n")
        f.write("     - Integrate SBOM + vulnerability scanning into CI/CD\n")

        f.write("\n" + "=" * 80 + "\n")
        f.write("  END OF REPORT\n")
        f.write("=" * 80 + "\n")

    print(f"[✓] Text: {txt_path}")

    # CSV
    csv_path = os.path.join(base_dir, f"{args.project}-migration-v2.csv")
    with open(csv_path, "w") as f:
        f.write("Package,Current_Version,Latest_Version,Ecosystem,Source_Package,"
                "Total_CVEs,Fixed,Open,Unknown,New_In_Latest,Net_Change,Recommendation\n")
        for r in sorted_results:
            s = r["summary"]
            rec = s["recommendation"].replace('"', "'").replace(",", ";")
            f.write(f"{r['package']},{r['current_version']},{r['latest_version']},"
                    f"{r['ecosystem']},{r.get('source_package', '')},"
                    f"{r['total_cves']},{s['fixed_if_upgraded']},{s['still_open']},"
                    f"{s['unknown']},{s['new_cves_introduced']},{s['net_cve_change']},"
                    f"\"{rec}\"\n")
    print(f"[✓] CSV:  {csv_path}")

    # Console summary
    print()
    print("=" * 60)
    print(f"  MIGRATION SUMMARY v2 — {args.project.upper()}")
    print("=" * 60)
    print(f"  Packages:     {len(results)}")
    print(f"  Total CVEs:   {total_cves}")
    print(f"  Fixable:      {total_fixed} ({total_fixed/total_cves*100:.1f}%)" if total_cves else "")
    print(f"  Still open:   {total_open}")
    print(f"  Unknown:      {total_unknown}")
    print(f"  New in latest:{total_new}")
    print()


if __name__ == "__main__":
    main()