"""
npm registry client for the SBOM CVE pipeline.

Fetches full package metadata including the `time` map that records
the exact publish timestamp for every version. This answers
"what was the latest available version on date X?" without using
today's `latest` tag (methodology v17 Section 4.5).

Extracted from dependency-version-cve-table.py lines 259-292 with:
- Separate raw response saving from per-package cache
- Date-filtered version lookups (get_latest_by_date)
- Chronological sorting by publish timestamp (replaces packaging.version)
"""

import json
import os
import time
import urllib.request
import urllib.parse
from datetime import datetime, timezone

NPM_REGISTRY_BASE = "https://registry.npmjs.org"
REQUEST_DELAY = 0.3
MAX_RETRIES = 3


def fetch_npm_package(package_name, raw_dir=None, cache_dir=None):
    """
    Fetch the full npm registry document for a package.

    Saves raw response to raw_dir, extracts and caches the time map
    (version -> publish timestamp) to cache_dir.
    Returns {latest, versions: [str], time: {version: iso_timestamp}}.
    """
    safe_name = _safe_filename(package_name)

    if cache_dir:
        cache_path = os.path.join(cache_dir, f"{safe_name}.json")
        if os.path.exists(cache_path):
            with open(cache_path, "r", encoding="utf-8") as f:
                return json.load(f)

    encoded = urllib.parse.quote(package_name, safe="@/")
    url = f"{NPM_REGISTRY_BASE}/{encoded}"

    data = _npm_request_with_retry(url)
    if data is None:
        return {"latest": None, "versions": [], "time": {}}

    if raw_dir:
        os.makedirs(raw_dir, exist_ok=True)
        raw_path = os.path.join(raw_dir, f"{safe_name}.json")
        with open(raw_path, "w", encoding="utf-8") as f:
            json.dump(data, f)

    latest = data.get("dist-tags", {}).get("latest")
    all_versions = list(data.get("versions", {}).keys())
    version_times = data.get("time", {})

    result = {
        "latest": latest,
        "versions": all_versions,
        "time": version_times,
    }

    if cache_dir:
        os.makedirs(cache_dir, exist_ok=True)
        cache_path = os.path.join(cache_dir, f"{safe_name}.json")
        with open(cache_path, "w", encoding="utf-8") as f:
            json.dump(result, f)

    return result


def build_npm_version_timeline(package_list, raw_dir, cache_dir):
    """
    Build the npm version timeline for all packages.

    Returns dict: {package_name: {version: publish_iso, ...}, ...}
    """
    os.makedirs(raw_dir, exist_ok=True)
    os.makedirs(cache_dir, exist_ok=True)

    timeline = {}
    total = len(package_list)

    for i, pkg_name in enumerate(package_list, 1):
        safe_name = _safe_filename(pkg_name)
        was_cached = os.path.exists(os.path.join(cache_dir, f"{safe_name}.json"))

        pkg_data = fetch_npm_package(pkg_name, raw_dir, cache_dir)

        filtered_time = {}
        for ver, ts in pkg_data.get("time", {}).items():
            if ver in ("created", "modified"):
                continue
            filtered_time[ver] = ts

        timeline[pkg_name] = filtered_time

        status = "cached" if was_cached else "fetched"
        print(f"  [{i}/{total}] {pkg_name} -- {status} ({len(filtered_time)} versions)")

        if not was_cached:
            time.sleep(REQUEST_DELAY)

    return timeline


def get_latest_by_date(timeline_entry, analysis_date):
    """
    Return the highest version published on or before analysis_date.

    Sorts by publish timestamp (chronological), then returns the last
    version whose timestamp <= analysis_date. Uses timestamps, not
    semver ordering, because the registry's chronological order is
    authoritative for "what was available on date X."
    """
    candidates = []
    for version, ts in timeline_entry.items():
        pub_date = _parse_npm_timestamp(ts)
        if pub_date and pub_date <= analysis_date:
            candidates.append((pub_date, version))

    if not candidates:
        return None

    candidates.sort(key=lambda x: x[0])
    return candidates[-1][1]


def get_versions_between(timeline_entry, v_low, v_high, analysis_date):
    """
    Return all versions published between v_low and v_high (inclusive),
    filtered to only those published on or before analysis_date.

    Sorted by publish timestamp (chronological order).
    """
    ts_low = timeline_entry.get(v_low)
    ts_high = timeline_entry.get(v_high)

    if not ts_low or not ts_high:
        return []

    date_low = _parse_npm_timestamp(ts_low)
    date_high = _parse_npm_timestamp(ts_high)

    if not date_low or not date_high:
        return []

    results = []
    for version, ts in timeline_entry.items():
        pub_date = _parse_npm_timestamp(ts)
        if not pub_date:
            continue
        if pub_date < date_low or pub_date > date_high:
            continue
        if pub_date > analysis_date:
            continue
        results.append((pub_date, version))

    results.sort(key=lambda x: x[0])
    return [v for _, v in results]


def _npm_request_with_retry(url):
    """GET from npm registry with retry."""
    for attempt in range(MAX_RETRIES):
        try:
            req = urllib.request.Request(url)
            req.add_header("Accept", "application/json")
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            if e.code == 429:
                wait = (attempt + 1) * 3
                print(f"  [npm rate-limited] waiting {wait}s...")
                time.sleep(wait)
                continue
            if e.code >= 500:
                time.sleep(2)
                continue
            raise
        except Exception:
            if attempt < MAX_RETRIES - 1:
                time.sleep(2)
                continue
            raise
    return None


def _parse_npm_timestamp(ts):
    """Parse an npm registry timestamp to a UTC datetime."""
    if not ts:
        return None
    try:
        ts_clean = ts.replace("Z", "+00:00")
        return datetime.fromisoformat(ts_clean).astimezone(timezone.utc)
    except (ValueError, TypeError):
        return None


def _safe_filename(name):
    """Convert a package name to a safe filename."""
    return name.replace("/", "__").replace("@", "_at_").replace(" ", "_")
