"""
OSV.dev API client for the SBOM CVE pipeline.

Primary historical CVE source for npm packages (methodology v17 Section 4.2).
Queries all vulnerabilities per package, extracts published dates,
affected version ranges, fixed versions, and severity.

Extracted from migration-analyzer-v2.py lines 80-191 with:
- Pagination support (next_page_token)
- Published date extraction
- Affected range conversion to semver-style strings
- Per-package caching to raw/osv-per-package/
- Raw response saving to raw/osv-responses/
"""

import json
import os
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone

from src.normalizer import normalize_package_name, log_package_match

OSV_API_BASE = "https://api.osv.dev/v1"
REQUEST_DELAY = 0.15
MAX_RETRIES = 3


def _osv_post(url, payload, timeout=20):
    """POST JSON to OSV API, return parsed response."""
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data)
    req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def query_osv_package_vulns(package_name, ecosystem, raw_dir=None):
    """
    Query OSV for ALL vulnerabilities affecting a package (no version filter).

    Handles pagination via next_page_token. Saves raw responses.
    Returns list of full vulnerability objects.
    """
    osv_ecosystem = _ecosystem_to_osv(ecosystem)
    all_vulns = []
    page_token = None
    page_num = 0

    while True:
        payload = {
            "package": {
                "name": package_name,
                "ecosystem": osv_ecosystem,
            }
        }
        if page_token:
            payload["page_token"] = page_token

        result = _osv_request_with_retry(
            f"{OSV_API_BASE}/query", payload
        )

        if raw_dir:
            os.makedirs(raw_dir, exist_ok=True)
            safe_name = _safe_filename(package_name)
            raw_path = os.path.join(
                raw_dir, f"osv-query-{ecosystem}-{safe_name}-p{page_num}.json"
            )
            with open(raw_path, "w", encoding="utf-8") as f:
                json.dump(result, f, indent=2)

        vulns = result.get("vulns", [])
        all_vulns.extend(vulns)

        page_token = result.get("next_page_token")
        if not page_token:
            break
        page_num += 1

    return all_vulns


def parse_osv_advisory(vuln_obj, target_package=None):
    """
    Extract structured CVE record from an OSV vulnerability object.

    Returns dict with: id, aliases, published_date, affected entries
    (each with ecosystem, package, ranges as semver strings, fixed version),
    severity, source_url, fetched_at.
    """
    vuln_id = vuln_obj.get("id", "")
    aliases = vuln_obj.get("aliases", [])
    published = vuln_obj.get("published", "")

    severity = _extract_severity(vuln_obj)
    source_url = f"https://osv.dev/vulnerability/{vuln_id}"

    affected_entries = []
    for affected in vuln_obj.get("affected", []):
        pkg = affected.get("package", {})
        pkg_name = pkg.get("name", "")
        pkg_eco = pkg.get("ecosystem", "")

        if target_package and normalize_package_name(pkg_name) != normalize_package_name(target_package):
            continue

        ranges = []
        fixed_version = None
        for range_info in affected.get("ranges", []):
            range_type = range_info.get("type", "")
            events = range_info.get("events", [])
            range_str, fixed = _events_to_range_string(events, range_type)
            if range_str:
                ranges.append(range_str)
            if fixed and not fixed_version:
                fixed_version = fixed

        affected_entries.append({
            "ecosystem": pkg_eco,
            "package": pkg_name,
            "vulnerable_ranges": ranges,
            "fixed_version": fixed_version,
            "versions_list": affected.get("versions", []),
        })

    return {
        "id": vuln_id,
        "aliases": aliases,
        "published_date": published[:10] if published else "",
        "published_iso": published,
        "severity": severity,
        "source_url": source_url,
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "affected": affected_entries,
    }


def build_master_cve_reference(package_list, ecosystem, raw_dir, cache_dir):
    """
    Build the master CVE reference for a list of packages.

    For each package, queries OSV, parses all advisories, and writes:
    - Raw API responses to raw_dir
    - Per-package normalized cache to cache_dir
    Returns dict keyed by advisory ID.
    """
    os.makedirs(raw_dir, exist_ok=True)
    os.makedirs(cache_dir, exist_ok=True)

    master = {}
    total = len(package_list)

    for i, pkg_name in enumerate(package_list, 1):
        normalized = normalize_package_name(pkg_name)
        safe_name = _safe_filename(normalized)
        cache_path = os.path.join(cache_dir, f"{safe_name}.json")

        if os.path.exists(cache_path):
            with open(cache_path, "r", encoding="utf-8") as f:
                cached = json.load(f)
            for adv_id, adv in cached.items():
                master[adv_id] = adv
            print(f"  [{i}/{total}] {normalized} -- cached ({len(cached)} advisories)")
            continue

        print(f"  [{i}/{total}] {normalized} -- querying OSV...", end="", flush=True)
        vulns = query_osv_package_vulns(normalized, ecosystem, raw_dir)

        pkg_advisories = {}
        for v in vulns:
            parsed = parse_osv_advisory(v, target_package=normalized)
            if parsed["affected"]:
                adv_id = parsed["id"]
                pkg_advisories[adv_id] = parsed
                master[adv_id] = parsed

                log_package_match(
                    raw_name=pkg_name,
                    normalized_name=normalized,
                    ecosystem=ecosystem,
                    match_source="OSV",
                    match_type="exact",
                    matched_id=adv_id,
                )

        with open(cache_path, "w", encoding="utf-8") as f:
            json.dump(pkg_advisories, f, indent=2)

        print(f" {len(vulns)} vulns, {len(pkg_advisories)} advisories")
        time.sleep(REQUEST_DELAY)

    return master


def _osv_request_with_retry(url, payload):
    """POST to OSV with retry on transient errors."""
    for attempt in range(MAX_RETRIES):
        try:
            return _osv_post(url, payload)
        except urllib.error.HTTPError as e:
            if e.code == 429:
                wait = (attempt + 1) * 2
                print(f"  [rate-limited] waiting {wait}s...")
                time.sleep(wait)
                continue
            if e.code >= 500:
                time.sleep(1)
                continue
            raise
        except Exception:
            if attempt < MAX_RETRIES - 1:
                time.sleep(1)
                continue
            raise
    return {"vulns": []}


def _events_to_range_string(events, range_type):
    """
    Convert OSV event pairs to a semver-style range string.

    OSV uses {introduced, fixed} or {introduced, last_affected} pairs.
    Returns (range_string, fixed_version).
    """
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

    if not introduced and introduced != "0":
        return None, None

    if fixed:
        if introduced == "0":
            return f"<{fixed}", fixed
        return f">={introduced} <{fixed}", fixed

    if last_affected:
        if introduced == "0":
            return f"<={last_affected}", None
        return f">={introduced} <={last_affected}", None

    if introduced == "0":
        return ">=0.0.0", None
    return f">={introduced}", None


def _extract_severity(vuln_obj):
    """Extract severity from OSV vulnerability, preferring database_specific."""
    db_severity = vuln_obj.get("database_specific", {}).get("severity", "")
    if db_severity:
        return db_severity.upper()

    for s in vuln_obj.get("severity", []):
        if s.get("type") == "CVSS_V3":
            score_str = s.get("score", "")
            score = _cvss_string_to_severity(score_str)
            if score:
                return score

    return "UNKNOWN"


def _cvss_string_to_severity(cvss_vector):
    """
    Convert a CVSS v3 vector string to a severity label.

    OSV severity[] entries with type CVSS_V3 contain the full vector
    string (e.g. "CVSS:3.1/AV:N/AC:L/..."), not a numeric score.
    Extracting the base score from the vector requires a CVSS library.

    For now we fall back to database_specific.severity (handled by the
    caller). If severity gaps are significant after Phase 0B, add the
    `cvss` library to requirements.txt and compute the score here.
    """
    return None


def _ecosystem_to_osv(ecosystem):
    """Map pipeline ecosystem names to OSV ecosystem names."""
    mapping = {
        "npm": "npm",
        "debian": "Debian:12",
        "golang": "Go",
        "alpine": "Alpine:v3.21",
    }
    return mapping.get(ecosystem, ecosystem)


def _safe_filename(name):
    """Convert a package name to a safe filename."""
    return name.replace("/", "__").replace("@", "_at_").replace(" ", "_")
