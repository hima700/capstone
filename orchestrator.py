"""
Orchestrator -- Main entry point for the SBOM CVE pipeline.

CLI subcommands:
  python orchestrator.py phase0                # Run one-time setup
  python orchestrator.py run --month 2025-03   # Run single month
  python orchestrator.py run --all             # Run all 13 months
  python orchestrator.py run --resume          # Resume from last completed
  python orchestrator.py inspect --month 2025-03  # Dry-run (no writes)
  python orchestrator.py report                # Generate all graphs

Methodology v17 Section 11: phased execution with checkpoint/resume.
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone

from src.config import load_config, compute_analysis_dates, get_month_label, format_analysis_date
from src.git_ops import (
    get_all_commits, select_commit_for_date,
    checkout_commit, has_file_at_commit,
)
from src.sbom import build_enriched_sbom
from src.cve_matcher import match_asis_cves
from src.patched_state import (
    compute_patched_versions, enumerate_intermediates, compute_patched_cves,
)
from src.delta import compute_delta
from src.validator import validate_month
from src.confidence import assign_confidence
from src.execution_log import append_log_entry, MASTER_LOG_PATH

RAW_DIR = "raw"
DERIVED_DIR = "derived"
MASTER_DIR = "master"
LOGS_DIR = "logs"


def load_master_data():
    """Load the master CVE reference and npm version timeline."""
    cve_path = os.path.join(MASTER_DIR, "master-cve-reference.v1.json")
    timeline_path = os.path.join(MASTER_DIR, "npm-version-timeline.v1.json")

    if not os.path.exists(cve_path) or not os.path.exists(timeline_path):
        print("[ERROR] Master data not found. Run 'orchestrator.py phase0' first.")
        sys.exit(1)

    with open(cve_path, "r", encoding="utf-8") as f:
        master_cves = json.load(f)
    with open(timeline_path, "r", encoding="utf-8") as f:
        npm_timeline = json.load(f)

    return master_cves, npm_timeline


def load_monthly_commits():
    """Load pre-computed monthly selected commits from Phase 0."""
    path = os.path.join(MASTER_DIR, "monthly-selected-commits.json")
    if not os.path.exists(path):
        print("[ERROR] monthly-selected-commits.json not found. Run phase0 first.")
        sys.exit(1)
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def get_completed_months():
    """Read the master execution log to find which months are already done."""
    if not os.path.exists(MASTER_LOG_PATH):
        return set()
    with open(MASTER_LOG_PATH, "r", encoding="utf-8") as f:
        entries = json.load(f)
    return set(
        datetime.fromisoformat(e["analysis_date"].replace("Z", "+00:00")).strftime("%Y-%m")
        for e in entries
    )


def run_single_month(month_label, analysis_date, config, commits,
                     monthly_commit_entry, master_cves, npm_timeline,
                     prev_month_data, consecutive_reuse):
    """
    Execute the full 7-step monthly analysis pipeline for one month.

    Returns (result_summary, consecutive_reuse_count) or raises on hard-stop.
    """
    print(f"\n{'='*60}")
    print(f"  Month: {month_label}  |  Analysis date: {analysis_date.date()}")
    print(f"{'='*60}")

    repo_path = config["repo_local_path"]

    commit = select_commit_for_date(commits, analysis_date)
    if not commit:
        print(f"  [ERROR] No eligible commit for {analysis_date.date()}")
        sys.exit(1)

    same_reused = monthly_commit_entry.get("same_commit_reused", False)
    if same_reused:
        consecutive_reuse += 1
    else:
        consecutive_reuse = 0

    has_lock = has_file_at_commit(repo_path, commit["hash"], "package-lock.json")

    commit_info = {
        "hash": commit["hash"],
        "date": commit["date"],
        "message": commit["message"],
        "same_commit_reused": same_reused,
    }

    print(f"  Commit:  {commit['hash'][:7]} ({commit['date'].date()}) "
          f"{'(reused)' if same_reused else ''}")
    print(f"  Lockfile: {'yes' if has_lock else 'NO'}")

    # Step 1: Reconstruct AS-IS SBOM
    print(f"\n  [Step 1] Building enriched SBOM...")
    checkout_commit(repo_path, commit["hash"])
    enriched_sbom = build_enriched_sbom(month_label, repo_path, RAW_DIR, DERIVED_DIR)
    c = enriched_sbom["counts"]
    print(f"    npm packages: {c['npm_packages_total']} "
          f"(direct={c['npm_packages_direct']}, "
          f"transitive={c['npm_packages_transitive']}, "
          f"unknown={c['npm_unknown_depth']})")

    # Step 2: Calculate AS-IS known CVEs
    print(f"\n  [Step 2] Matching AS-IS CVEs...")
    asis_cves = match_asis_cves(enriched_sbom, master_cves, analysis_date, DERIVED_DIR)
    s = asis_cves["summary"]
    print(f"    Total CVEs: {s['asis_total_cves']} "
          f"(C={s['asis_severity_critical']} H={s['asis_severity_high']} "
          f"M={s['asis_severity_medium']} L={s['asis_severity_low']})")
    print(f"    Vulnerable npm packages: {s['npm_packages_vulnerable']} / {s['npm_packages_total']}")

    # Step 3: Determine PATCHED versions
    print(f"\n  [Step 3] Computing patched versions...")
    patched_versions = compute_patched_versions(
        enriched_sbom, npm_timeline, analysis_date, DERIVED_DIR
    )
    already_latest = sum(1 for pv in patched_versions["patched_versions"] if pv["already_at_latest"])
    upgradeable = len(patched_versions["patched_versions"]) - already_latest
    print(f"    Upgradeable: {upgradeable}, Already at latest: {already_latest}, "
          f"Unresolved: {patched_versions['unresolved_count']}")

    # Step 4: Enumerate intermediate versions
    print(f"\n  [Step 4] Enumerating intermediate versions...")
    intermediate_data = enumerate_intermediates(
        patched_versions, npm_timeline, master_cves, analysis_date, DERIVED_DIR
    )
    pkg_count = len(intermediate_data.get("packages", {}))
    print(f"    Packages with intermediates: {pkg_count}")

    # Step 5: Calculate PATCHED CVEs
    print(f"\n  [Step 5] Computing patched CVEs...")
    patched_cves = compute_patched_cves(
        patched_versions, asis_cves, master_cves, analysis_date, DERIVED_DIR
    )
    ps = patched_cves["summary"]
    print(f"    Patched total: {ps['patched_total_cves']} "
          f"(N-day={ps['patched_nday']}, Zero-day={ps['patched_zeroday']})")

    # Step 6: Calculate monthly delta
    print(f"\n  [Step 6] Computing delta...")
    delta = compute_delta(asis_cves, patched_cves, intermediate_data, DERIVED_DIR)
    print(f"    Fixed: {delta['cves_fixed']}, N-day introduced: {delta['nday_introduced']}, "
          f"Zero-day introduced: {delta['zeroday_introduced']}")
    print(f"    Net reduction: {delta['net_reduction']}")

    # Step 7: Validation
    print(f"\n  [Step 7] Running validation gates...")
    validation = validate_month(
        month_label, analysis_date, commit_info,
        enriched_sbom, asis_cves, patched_versions,
        patched_cves, delta, npm_timeline,
        commits, prev_month_data,
        consecutive_reuse_count=consecutive_reuse,
    )

    if not validation["passed"]:
        print(f"\n  [HARD STOP] Validation failed:")
        for err in validation["errors"]:
            print(f"    ERROR: {err}")
        print(f"\n  Pipeline halted at {month_label}. Fix errors before proceeding.")
        sys.exit(1)

    if validation["manual_review_flags"]:
        print(f"    Flags (acknowledged):")
        for flag in validation["manual_review_flags"]:
            print(f"      - {flag}")

    print(f"    Validation: PASSED")

    # Confidence
    confidence = assign_confidence(enriched_sbom, asis_cves, patched_versions)
    print(f"    Confidence: {confidence}")

    # Write execution log entry
    entry = append_log_entry(
        analysis_date, commit_info, config,
        enriched_sbom, asis_cves, patched_versions,
        patched_cves, delta, validation, confidence,
    )

    # Verify output files
    expected_files = [
        f"{month_label}-asis-sbom.json",
        f"{month_label}-asis-cves.json",
        f"{month_label}-patched-versions.json",
        f"{month_label}-intermediate-versions.json",
        f"{month_label}-patched-cves.json",
        f"{month_label}-delta.json",
    ]
    for fname in expected_files:
        fpath = os.path.join(DERIVED_DIR, fname)
        if not os.path.exists(fpath) or os.path.getsize(fpath) == 0:
            print(f"  [WARNING] Missing or empty: {fpath}")

    val_path = os.path.join(LOGS_DIR, f"validation-report-{month_label}.json")
    if not os.path.exists(val_path):
        print(f"  [WARNING] Missing: {val_path}")

    summary = {
        "asis_total_cves": s["asis_total_cves"],
        "npm_packages_total": s["npm_packages_total"],
        "npm_packages_vulnerable": s["npm_packages_vulnerable"],
        "consecutive_reuse": consecutive_reuse,
    }

    return summary, consecutive_reuse


def cmd_run(args, config):
    """Handle the 'run' subcommand."""
    master_cves, npm_timeline = load_master_data()
    monthly_commits = load_monthly_commits()
    commits = get_all_commits(config["repo_local_path"])
    analysis_dates = compute_analysis_dates(config)

    completed = get_completed_months()

    if args.month:
        targets = [(ad, mc) for ad, mc in zip(analysis_dates, monthly_commits)
                    if get_month_label(ad) == args.month]
        if not targets:
            print(f"[ERROR] Unknown month: {args.month}")
            sys.exit(1)
    elif args.resume:
        targets = [(ad, mc) for ad, mc in zip(analysis_dates, monthly_commits)
                    if get_month_label(ad) not in completed]
        if not targets:
            print("All months already completed.")
            return
        print(f"Resuming: {len(completed)} months done, {len(targets)} remaining.")
    else:
        targets = list(zip(analysis_dates, monthly_commits))

    prev_month_data = None
    consecutive_reuse = 0

    if completed and args.resume:
        existing_log = []
        if os.path.exists(MASTER_LOG_PATH):
            with open(MASTER_LOG_PATH, "r", encoding="utf-8") as f:
                existing_log = json.load(f)
        if existing_log:
            last = existing_log[-1]
            prev_month_data = {
                "asis_total_cves": last.get("asis_total_cves", 0),
                "npm_packages_total": last.get("npm_packages_total", 0),
            }

    for analysis_date, mc_entry in targets:
        month_label = get_month_label(analysis_date)

        if month_label in completed and not args.month:
            print(f"\n  Skipping {month_label} (already completed)")
            continue

        summary, consecutive_reuse = run_single_month(
            month_label, analysis_date, config, commits,
            mc_entry, master_cves, npm_timeline,
            prev_month_data, consecutive_reuse,
        )
        prev_month_data = summary

    print(f"\n{'='*60}")
    print(f"  Run complete.")
    print(f"{'='*60}")


def cmd_inspect(args, config):
    """Handle the 'inspect' subcommand -- dry-run, no writes."""
    commits = get_all_commits(config["repo_local_path"])
    monthly_commits = load_monthly_commits()
    analysis_dates = compute_analysis_dates(config)

    targets = [(ad, mc) for ad, mc in zip(analysis_dates, monthly_commits)
                if get_month_label(ad) == args.month]

    if not targets:
        print(f"[ERROR] Unknown month: {args.month}")
        sys.exit(1)

    analysis_date, mc_entry = targets[0]
    month_label = get_month_label(analysis_date)
    repo_path = config["repo_local_path"]

    commit = select_commit_for_date(commits, analysis_date)
    has_lock = has_file_at_commit(repo_path, commit["hash"], "package-lock.json") if commit else False

    print(f"\n  Inspect: {month_label}")
    print(f"  Analysis date:      {analysis_date.date()}")
    print(f"  Selected commit:    {commit['hash'][:7] if commit else 'NONE'}")
    print(f"  Commit date:        {commit['date'].date() if commit else 'N/A'}")
    print(f"  Same commit reused: {mc_entry.get('same_commit_reused', False)}")
    print(f"  Lockfile present:   {has_lock}")

    completed = get_completed_months()
    print(f"  Already processed:  {month_label in completed}")
    print(f"\n  (No files written -- inspect mode)")


def cmd_phase0(args, config):
    """Handle the 'phase0' subcommand."""
    from phase0_setup import run_phase0
    run_phase0()


def cmd_report(args, config):
    """Handle the 'report' subcommand."""
    try:
        from src.reporter import generate_all_reports
        generate_all_reports()
    except ImportError:
        print("[ERROR] src/reporter.py not yet implemented (Phase 4)")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="SBOM CVE Pipeline Orchestrator (Methodology v17)"
    )
    subparsers = parser.add_subparsers(dest="command", help="Subcommand")

    sub_phase0 = subparsers.add_parser("phase0", help="Run one-time setup")

    sub_run = subparsers.add_parser("run", help="Run monthly analysis")
    run_group = sub_run.add_mutually_exclusive_group(required=True)
    run_group.add_argument("--month", help="Run single month (YYYY-MM)")
    run_group.add_argument("--all", action="store_true", help="Run all 13 months")
    run_group.add_argument("--resume", action="store_true", help="Resume from last completed")

    sub_inspect = subparsers.add_parser("inspect", help="Dry-run for a month")
    sub_inspect.add_argument("--month", required=True, help="Month to inspect (YYYY-MM)")

    sub_report = subparsers.add_parser("report", help="Generate graphs and tables")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    config = load_config()

    if args.command == "phase0":
        cmd_phase0(args, config)
    elif args.command == "run":
        cmd_run(args, config)
    elif args.command == "inspect":
        cmd_inspect(args, config)
    elif args.command == "report":
        cmd_report(args, config)


if __name__ == "__main__":
    main()
