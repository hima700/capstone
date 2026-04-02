"""
Package name normalization and audit logging.

Per methodology v17 Section 5.4:
- Normalize all package names before any matching operation
- Log every match to package-match-audit.jsonl
- Log ambiguous items to ambiguous-items.jsonl

Purl parsing extracted from dependency-version-cve-table.py lines 98-120.
"""

import json
import re
import os
import urllib.parse
from datetime import datetime, timezone

LOGS_DIR = "logs"

PURL_ECOSYSTEM_MAP = {
    "npm": "npm",
    "deb": "debian",
    "golang": "golang",
    "apk": "alpine",
}


def normalize_package_name(raw_name):
    """
    Normalize a package name for consistent matching.

    - Lowercase
    - Strip whitespace
    - Preserve @scope/name format for npm
    """
    name = raw_name.strip().lower()
    return name


def parse_purl(purl):
    """
    Extract name, version, ecosystem from a Package URL string.

    Returns dict with {name, version, ecosystem, purl} or None on failure.
    Handles npm scoped packages (@scope/name) and golang namespaces.
    """
    purl_decoded = urllib.parse.unquote(purl)
    m = re.match(r"pkg:(\w+)/(?:([^/]+)/)?([^@?]+)@([^?]+)", purl_decoded)
    if not m:
        return None

    pkg_type = m.group(1)
    namespace = m.group(2) or ""
    name = m.group(3)
    version = m.group(4)

    if pkg_type == "npm" and namespace:
        if namespace.startswith("@"):
            name = f"{namespace}/{name}"
        else:
            name = f"@{namespace}/{name}"
    elif pkg_type == "golang" and namespace:
        name = f"{namespace}/{name}"

    ecosystem = PURL_ECOSYSTEM_MAP.get(pkg_type, pkg_type)

    return {
        "name": normalize_package_name(name),
        "raw_name": name,
        "version": version,
        "ecosystem": ecosystem,
        "purl": purl,
    }


def log_package_match(raw_name, normalized_name, ecosystem,
                      match_source, match_type, matched_id):
    """
    Append a match record to logs/package-match-audit.jsonl.

    Called every time a package name is matched to an OSV/NVD/npm record.
    """
    os.makedirs(LOGS_DIR, exist_ok=True)
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "raw_name": raw_name,
        "normalized_name": normalized_name,
        "ecosystem": ecosystem,
        "match_source": match_source,
        "match_type": match_type,
        "matched_identifier": matched_id,
    }
    path = os.path.join(LOGS_DIR, "package-match-audit.jsonl")
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")


def log_ambiguous_item(package_name, version, reason, month,
                       extra=None):
    """
    Append an entry to logs/ambiguous-items.jsonl.

    Logged when:
    - A version cannot be parsed by the semver engine
    - An advisory's affected range cannot be evaluated
    - A package has unknown_dependency_depth
    - An AS-IS package-version is missing from npm timeline
    """
    os.makedirs(LOGS_DIR, exist_ok=True)
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "package": package_name,
        "version": version,
        "reason": reason,
        "month": month,
    }
    if extra:
        entry["extra"] = extra
    path = os.path.join(LOGS_DIR, "ambiguous-items.jsonl")
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")
