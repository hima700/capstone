"""
Master execution log for the SBOM CVE pipeline.

Methodology v17 Section 6.7: Appends one JSON object per month to
logs/master-execution-log.json with all 45 fields. reporter.py reads
these exact field names for all 14 graphs.

Three fields are required even when zero:
  unknown_dependency_depth_count, patch_sim_unresolved_count, excluded_advisory_count
"""

import json
import os
from src.config import format_analysis_date


MASTER_LOG_PATH = os.path.join("logs", "master-execution-log.json")


def append_log_entry(analysis_date, commit_data, config,
                     enriched_sbom, asis_cves, patched_versions,
                     patched_cves, delta, validation, confidence):
    """
    Build and append one month's execution log entry.

    The 45 fields are grouped by source module, matching the plan's schema.
    """
    counts = enriched_sbom.get("counts", {})
    a_summary = asis_cves.get("summary", {})
    p_summary = patched_cves.get("summary", {})
    pv = patched_versions

    entry = {
        # From sbom / commit selection (11 fields)
        "analysis_date": format_analysis_date(analysis_date),
        "selected_commit_hash": commit_data["hash"] if commit_data else None,
        "selected_commit_date": commit_data["date"].isoformat() if commit_data else None,
        "selection_rule": "latest commit on or before analysis_date",
        "same_commit_reused": commit_data.get("same_commit_reused", False) if commit_data else False,
        "lockfile_present": enriched_sbom.get("lockfile_present", False),
        "dev_dependencies_included": config.get("dev_dependencies_included", True),
        "patch_simulation_policy": config.get("patch_simulation_policy", ""),
        "npm_packages_total": counts.get("npm_packages_total", 0),
        "npm_packages_direct": counts.get("npm_packages_direct", 0),
        "npm_packages_transitive": counts.get("npm_packages_transitive", 0),

        # From cve_matcher (15 fields)
        "asis_total_cves": a_summary.get("asis_total_cves", 0),
        "asis_npm_cves": a_summary.get("asis_npm_cves", 0),
        "asis_debian_cves": 0,
        "asis_go_cves": 0,
        "asis_severity_critical": a_summary.get("asis_severity_critical", 0),
        "asis_severity_high": a_summary.get("asis_severity_high", 0),
        "asis_severity_medium": a_summary.get("asis_severity_medium", 0),
        "asis_severity_low": a_summary.get("asis_severity_low", 0),
        "npm_packages_vulnerable": a_summary.get("npm_packages_vulnerable", 0),
        "npm_packages_non_vulnerable": a_summary.get("npm_packages_non_vulnerable", 0),
        "direct_vulnerable_npm_packages": a_summary.get("direct_vulnerable_npm_packages", 0),
        "transitive_vulnerable_npm_packages": a_summary.get("transitive_vulnerable_npm_packages", 0),
        "direct_npm_dep_cves": a_summary.get("direct_npm_dep_cves", 0),
        "transitive_npm_dep_cves": a_summary.get("transitive_npm_dep_cves", 0),

        # From patched_state / delta (13 fields)
        "patched_total_cves": p_summary.get("patched_total_cves", 0),
        "patched_nday": p_summary.get("patched_nday", 0),
        "patched_zeroday": p_summary.get("patched_zeroday", 0),
        "patched_npm_packages_vulnerable": p_summary.get("patched_npm_packages_vulnerable", 0),
        "cves_fixed": delta.get("cves_fixed", 0),
        "nday_introduced": delta.get("nday_introduced", 0),
        "zeroday_introduced": delta.get("zeroday_introduced", 0),
        "churn_introduced": delta.get("churn_introduced", 0),
        "net_reduction": delta.get("net_reduction", 0),
        "patched_retained": delta.get("patched_retained", 0),
        "intermediate_peak_package": delta.get("intermediate_peak_package", ""),
        "intermediate_peak_count": delta.get("intermediate_peak_count", 0),

        # From confidence / validator (8 fields)
        "data_confidence": confidence,
        "unknown_dependency_depth_count": counts.get("npm_unknown_depth", 0),
        "patch_sim_unresolved_count": pv.get("unresolved_count", 0),
        "patch_sim_unresolved_packages": pv.get("unresolved_packages", []),
        "excluded_advisory_count": a_summary.get("excluded_advisory_count", 0),
        "warnings": validation.get("warnings", []),
        "errors": validation.get("errors", []),
        "manual_review_flags": validation.get("manual_review_flags", []),
    }

    os.makedirs("logs", exist_ok=True)

    existing = []
    if os.path.exists(MASTER_LOG_PATH):
        with open(MASTER_LOG_PATH, "r", encoding="utf-8") as f:
            existing = json.load(f)

    existing.append(entry)

    with open(MASTER_LOG_PATH, "w", encoding="utf-8") as f:
        json.dump(existing, f, indent=2)

    return entry
