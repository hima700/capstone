"""
SBOM generation and enrichment for the SBOM CVE pipeline.

Methodology v17 Step 1: Reconstruct AS-IS SBOM.
- Runs Syft on the checked-out repo (filesystem mode, no Docker)
- Parses package-lock.json for resolved versions and dependency tree
- Tags every package as direct / transitive / unknown_dependency_depth
- Produces the enriched SBOM (authoritative monthly inventory)
"""

import json
import os
import subprocess

from src.normalizer import normalize_package_name, parse_purl, log_ambiguous_item


def generate_sbom(repo_path, output_path):
    """
    Run Syft on a checked-out repo directory and save raw JSON output.

    Uses filesystem mode: syft dir:<path> -o syft-json
    """
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    result = subprocess.run(
        ["syft", f"dir:{repo_path}", "-o", "syft-json", "-q"],
        capture_output=True,
        text=True,
        timeout=120,
    )
    if result.returncode != 0:
        raise RuntimeError(f"Syft failed: {result.stderr[:500]}")

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(result.stdout)

    return json.loads(result.stdout)


def parse_lockfile(repo_path):
    """
    Parse package-lock.json and return a dict of resolved packages.

    Returns: {normalized_name: {version, dev, ...}, ...}
    Handles lockfile v2/v3 (packages field) and v1 (dependencies field).
    """
    lockfile_path = os.path.join(repo_path, "package-lock.json")
    if not os.path.exists(lockfile_path):
        return None

    with open(lockfile_path, "r", encoding="utf-8") as f:
        lockfile = json.load(f)

    packages = {}

    lf_packages = lockfile.get("packages", {})
    if lf_packages:
        for key, info in lf_packages.items():
            if not key:
                continue
            parts = key.split("node_modules/")
            name = parts[-1]
            if not name:
                continue
            normalized = normalize_package_name(name)
            packages[normalized] = {
                "version": info.get("version", ""),
                "dev": info.get("dev", False),
                "resolved": info.get("resolved", ""),
                "lockfile_key": key,
            }
        return packages

    def _walk_deps(deps, is_dev=False):
        for name, info in deps.items():
            normalized = normalize_package_name(name)
            packages[normalized] = {
                "version": info.get("version", ""),
                "dev": is_dev or info.get("dev", False),
                "resolved": info.get("resolved", ""),
                "lockfile_key": name,
            }
            sub = info.get("dependencies", {})
            if sub:
                _walk_deps(sub, is_dev)

    _walk_deps(lockfile.get("dependencies", {}))
    return packages


def parse_package_json(repo_path):
    """
    Parse package.json to identify direct dependencies.

    Returns: {normalized_name: "direct", ...} for all dependencies
    and devDependencies.
    """
    pkg_path = os.path.join(repo_path, "package.json")
    if not os.path.exists(pkg_path):
        return {}

    with open(pkg_path, "r", encoding="utf-8") as f:
        pkg = json.load(f)

    direct = {}
    for section in ("dependencies", "devDependencies"):
        for name in pkg.get(section, {}):
            direct[normalize_package_name(name)] = section

    return direct


def extract_packages_from_syft(syft_output):
    """
    Extract npm packages from Syft JSON output.

    Returns list of {name, version, ecosystem, purl} dicts.
    """
    artifacts = syft_output.get("artifacts", [])
    packages = []
    seen = set()

    for artifact in artifacts:
        purl = artifact.get("purl", "")
        if not purl:
            continue

        parsed = parse_purl(purl)
        if not parsed:
            continue

        dedup_key = f"{parsed['name']}@{parsed['version']}@{parsed['ecosystem']}"
        if dedup_key in seen:
            continue
        seen.add(dedup_key)

        packages.append({
            "name": parsed["name"],
            "version": parsed["version"],
            "ecosystem": parsed["ecosystem"],
            "purl": purl,
        })

    return packages


def tag_dependency_depth(packages, lockfile_data, direct_deps, month_label):
    """
    Classify each package as direct / transitive / unknown_dependency_depth.

    Direct: listed in package.json dependencies or devDependencies.
    Transitive: in lockfile but not in package.json direct deps.
    Unknown: in Syft SBOM but not in lockfile (logged to ambiguous-items).
    """
    for pkg in packages:
        name = pkg["name"]

        if pkg["ecosystem"] != "npm":
            pkg["depth"] = "unknown_dependency_depth"
            continue

        if name in direct_deps:
            pkg["depth"] = "direct"
        elif lockfile_data and name in lockfile_data:
            pkg["depth"] = "transitive"
        else:
            pkg["depth"] = "unknown_dependency_depth"
            log_ambiguous_item(
                package_name=name,
                version=pkg["version"],
                reason="package in Syft SBOM but not found in lockfile",
                month=month_label,
            )

    return packages


def build_enriched_sbom(month_label, repo_path, raw_dir, derived_dir):
    """
    Orchestrate full SBOM generation and enrichment for one month.

    1. Run Syft to get raw SBOM
    2. Parse lockfile for resolved versions
    3. Parse package.json for direct deps
    4. Merge: use lockfile versions as authoritative, fall back to Syft
    5. Tag depth (direct/transitive/unknown)

    Returns enriched SBOM dict and saves to derived/{month}-asis-sbom.json.
    """
    raw_path = os.path.join(raw_dir, "syft", f"{month_label}-raw-sbom.json")
    syft_output = generate_sbom(repo_path, raw_path)

    lockfile_data = parse_lockfile(repo_path)
    direct_deps = parse_package_json(repo_path)

    syft_packages = extract_packages_from_syft(syft_output)

    if lockfile_data:
        merged = _merge_lockfile_and_syft(lockfile_data, syft_packages, direct_deps)
    else:
        merged = syft_packages

    tagged = tag_dependency_depth(merged, lockfile_data, direct_deps, month_label)

    npm_packages = [p for p in tagged if p["ecosystem"] == "npm"]
    non_npm = [p for p in tagged if p["ecosystem"] != "npm"]

    npm_direct = sum(1 for p in npm_packages if p["depth"] == "direct")
    npm_transitive = sum(1 for p in npm_packages if p["depth"] == "transitive")
    npm_unknown = sum(1 for p in npm_packages if p["depth"] == "unknown_dependency_depth")

    enriched = {
        "month": month_label,
        "lockfile_present": lockfile_data is not None,
        "packages": tagged,
        "counts": {
            "npm_packages_total": len(npm_packages),
            "npm_packages_direct": npm_direct,
            "npm_packages_transitive": npm_transitive,
            "npm_unknown_depth": npm_unknown,
            "non_npm_packages": len(non_npm),
            "total_packages": len(tagged),
        },
    }

    os.makedirs(derived_dir, exist_ok=True)
    out_path = os.path.join(derived_dir, f"{month_label}-asis-sbom.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(enriched, f, indent=2)

    return enriched


def _merge_lockfile_and_syft(lockfile_data, syft_packages, direct_deps):
    """
    Merge lockfile and Syft data, using lockfile as authoritative for npm.

    Lockfile versions are trusted over Syft for npm packages. Non-npm
    packages from Syft are included as-is.
    """
    merged = []
    seen = set()

    for name, info in lockfile_data.items():
        version = info.get("version", "")
        if not version:
            continue
        dedup_key = f"{name}@{version}"
        if dedup_key in seen:
            continue
        seen.add(dedup_key)
        merged.append({
            "name": name,
            "version": version,
            "ecosystem": "npm",
            "purl": f"pkg:npm/{name}@{version}",
        })

    for pkg in syft_packages:
        if pkg["ecosystem"] == "npm":
            continue
        dedup_key = f"{pkg['name']}@{pkg['version']}"
        if dedup_key in seen:
            continue
        seen.add(dedup_key)
        merged.append(pkg)

    return merged
