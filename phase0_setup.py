"""
Phase 0 -- One-Time Setup

Builds all master reference data before the monthly analysis loop:
  1. Clone/update the target repository
  2. Identify lockfile-changing commits
  3. Compute monthly selected commits
  4. Discover all unique packages across all relevant commits
  5. Build master CVE reference (OSV.dev)
  6. Build npm version timeline (npm registry)
  7. Write repo-facts.json

Outputs to master/:
  - lockfile-change-commits.json
  - monthly-selected-commits.json
  - master-cve-reference.v1.json
  - npm-version-timeline.v1.json
  - repo-facts.json
"""

import json
import os
import sys
from datetime import datetime, timezone

from src.config import load_config, compute_analysis_dates, get_month_label, format_analysis_date
from src.git_ops import (
    clone_repo, get_all_commits, select_commit_for_date,
    get_lockfile_changing_commits, checkout_commit,
    has_file_at_commit, show_file_at_commit,
)
from src.normalizer import normalize_package_name
from src.osv_client import build_master_cve_reference
from src.npm_client import build_npm_version_timeline

MASTER_DIR = "master"
RAW_DIR = "raw"
LOGS_DIR = "logs"


def extract_packages_from_lockfile_content(content):
    """
    Parse package-lock.json content and return set of package names.

    Handles lockfile v2/v3 (packages field) and v1 (dependencies field).
    """
    if not content:
        return set()

    try:
        lockfile = json.loads(content)
    except json.JSONDecodeError:
        return set()

    packages = set()

    lf_packages = lockfile.get("packages", {})
    if lf_packages:
        for key, info in lf_packages.items():
            if not key or key == "":
                continue
            name = key.lstrip("node_modules/")
            if name.startswith("node_modules/"):
                name = name.split("node_modules/")[-1]
            if name:
                packages.add(normalize_package_name(name))
        return packages

    def _walk_deps(deps):
        for name, info in deps.items():
            packages.add(normalize_package_name(name))
            sub = info.get("dependencies", {})
            if sub:
                _walk_deps(sub)

    deps = lockfile.get("dependencies", {})
    _walk_deps(deps)
    return packages


def discover_all_packages(config, commits, lockfile_commits, analysis_dates):
    """
    Discover all unique package names across the project history.

    Per methodology v17 Section 5.2: extract the lockfile at every
    lockfile-changing commit AND every unique monthly selected commit,
    union all package names.
    """
    repo_path = config["repo_local_path"]

    commit_hashes_to_check = set()
    for lc in lockfile_commits:
        commit_hashes_to_check.add(lc["hash"])
    for ad in analysis_dates:
        sel = select_commit_for_date(commits, ad)
        if sel:
            commit_hashes_to_check.add(sel["hash"])

    all_packages = set()
    print(f"\nDiscovering packages from {len(commit_hashes_to_check)} unique commits...")

    for commit_hash in sorted(commit_hashes_to_check):
        if not has_file_at_commit(repo_path, commit_hash, "package-lock.json"):
            print(f"  {commit_hash[:7]}: no package-lock.json")
            continue

        content = show_file_at_commit(repo_path, commit_hash, "package-lock.json")
        pkgs = extract_packages_from_lockfile_content(content)
        print(f"  {commit_hash[:7]}: {len(pkgs)} packages")
        all_packages.update(pkgs)

    print(f"\nTotal unique packages discovered: {len(all_packages)}")
    return all_packages


def run_phase0(config_path="study-config.json"):
    """Execute the full Phase 0 setup."""
    print("=" * 60)
    print("  Phase 0 -- One-Time Setup")
    print("=" * 60)

    config = load_config(config_path)
    repo_path = config["repo_local_path"]

    for d in [MASTER_DIR, LOGS_DIR,
              os.path.join(RAW_DIR, "osv-responses"),
              os.path.join(RAW_DIR, "osv-per-package"),
              os.path.join(RAW_DIR, "npm-registry-responses"),
              os.path.join(RAW_DIR, "npm-per-package")]:
        os.makedirs(d, exist_ok=True)

    # --- Step 1: Clone/verify repo ---
    print(f"\n[1/7] Repository: {config['repo_url']}")
    cloned = clone_repo(config["repo_url"], repo_path)
    if cloned:
        print(f"  Cloned to {repo_path}")
    else:
        print(f"  Already exists at {repo_path}")

    # --- Step 2: Enumerate commits ---
    print(f"\n[2/7] Enumerating commits...")
    commits = get_all_commits(repo_path)
    print(f"  Total commits: {len(commits)}")
    print(f"  First: {commits[0]['hash'][:7]} {commits[0]['date'].date()} \"{commits[0]['message']}\"")
    print(f"  Last:  {commits[-1]['hash'][:7]} {commits[-1]['date'].date()} \"{commits[-1]['message']}\"")

    # --- Step 3: Lockfile-changing commits ---
    print(f"\n[3/7] Finding lockfile-changing commits...")
    lf_commits = get_lockfile_changing_commits(repo_path)
    print(f"  Found: {len(lf_commits)}")
    lf_data = []
    for c in lf_commits:
        entry = {
            "hash": c["hash"],
            "date": c["date"].isoformat(),
            "message": c["message"],
        }
        lf_data.append(entry)
        print(f"    {c['hash'][:7]} {c['date'].date()} \"{c['message']}\"")

    lf_path = os.path.join(MASTER_DIR, "lockfile-change-commits.json")
    with open(lf_path, "w", encoding="utf-8") as f:
        json.dump(lf_data, f, indent=2)
    print(f"  Saved: {lf_path}")

    # --- Step 4: Monthly selected commits ---
    print(f"\n[4/7] Computing monthly selected commits...")
    analysis_dates = compute_analysis_dates(config)
    monthly_commits = []
    prev_hash = None
    for ad in analysis_dates:
        sel = select_commit_for_date(commits, ad)
        reused = sel["hash"] == prev_hash if prev_hash and sel else False
        has_lock = has_file_at_commit(repo_path, sel["hash"], "package-lock.json") if sel else False
        entry = {
            "analysis_date": format_analysis_date(ad),
            "month_label": get_month_label(ad),
            "selected_commit_hash": sel["hash"] if sel else None,
            "selected_commit_date": sel["date"].isoformat() if sel else None,
            "same_commit_reused": reused,
            "lockfile_present": has_lock,
        }
        monthly_commits.append(entry)
        flag = " (reused)" if reused else ""
        hash_str = sel['hash'][:7] if sel else "NONE"
        print(f"    {get_month_label(ad)}: {hash_str}{flag} lockfile={has_lock}")
        prev_hash = sel["hash"] if sel else prev_hash

    mc_path = os.path.join(MASTER_DIR, "monthly-selected-commits.json")
    with open(mc_path, "w", encoding="utf-8") as f:
        json.dump(monthly_commits, f, indent=2)
    print(f"  Saved: {mc_path}")

    # --- Step 5: Package discovery ---
    print(f"\n[5/7] Package discovery from lockfiles...")
    all_packages = discover_all_packages(config, commits, lf_commits, analysis_dates)
    npm_packages = sorted(all_packages)

    # --- Step 6: Master CVE reference ---
    print(f"\n[6/7] Building master CVE reference ({len(npm_packages)} packages)...")
    master_cves = build_master_cve_reference(
        package_list=npm_packages,
        ecosystem="npm",
        raw_dir=os.path.join(RAW_DIR, "osv-responses"),
        cache_dir=os.path.join(RAW_DIR, "osv-per-package"),
    )
    cve_ref_path = os.path.join(MASTER_DIR, "master-cve-reference.v1.json")
    with open(cve_ref_path, "w", encoding="utf-8") as f:
        json.dump(master_cves, f, indent=2)
    print(f"  Total advisories: {len(master_cves)}")
    print(f"  Saved: {cve_ref_path}")

    # --- Step 7: npm version timeline ---
    print(f"\n[7/7] Building npm version timeline ({len(npm_packages)} packages)...")
    timeline = build_npm_version_timeline(
        package_list=npm_packages,
        raw_dir=os.path.join(RAW_DIR, "npm-registry-responses"),
        cache_dir=os.path.join(RAW_DIR, "npm-per-package"),
    )
    timeline_path = os.path.join(MASTER_DIR, "npm-version-timeline.v1.json")
    with open(timeline_path, "w", encoding="utf-8") as f:
        json.dump(timeline, f, indent=2)
    total_versions = sum(len(v) for v in timeline.values())
    print(f"  Total version entries: {total_versions}")
    print(f"  Saved: {timeline_path}")

    # --- Repo facts ---
    contributors = set()
    for c in commits:
        pass
    repo_facts = {
        "repo_url": config["repo_url"],
        "first_commit_hash": commits[0]["hash"],
        "first_commit_date": commits[0]["date"].isoformat(),
        "last_commit_hash": commits[-1]["hash"],
        "last_commit_date": commits[-1]["date"].isoformat(),
        "total_commits": len(commits),
        "lockfile_change_commits": len(lf_commits),
        "total_unique_packages": len(all_packages),
        "total_advisories_in_master_ref": len(master_cves),
        "monthly_checkpoints": len(analysis_dates),
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
    facts_path = os.path.join(MASTER_DIR, "repo-facts.json")
    with open(facts_path, "w", encoding="utf-8") as f:
        json.dump(repo_facts, f, indent=2)
    print(f"\n  Saved: {facts_path}")

    # --- Summary ---
    print("\n" + "=" * 60)
    print("  Phase 0 Complete")
    print("=" * 60)
    print(f"  Commits:           {len(commits)}")
    print(f"  Lockfile changes:  {len(lf_commits)}")
    print(f"  Unique packages:   {len(all_packages)}")
    print(f"  OSV advisories:    {len(master_cves)}")
    print(f"  npm timeline pkgs: {len(timeline)}")
    print(f"  Version entries:   {total_versions}")
    print()

    return {
        "commits": commits,
        "lockfile_commits": lf_commits,
        "monthly_commits": monthly_commits,
        "packages": npm_packages,
        "master_cves": master_cves,
        "timeline": timeline,
    }


if __name__ == "__main__":
    run_phase0()
