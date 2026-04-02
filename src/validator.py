"""
Validation framework for the SBOM CVE pipeline.

Methodology v17 Section 7: Hard-stop gates, reconciliation checks,
and anomaly detection. Pipeline halts if any hard-stop gate fails.
"""

import json
import os


def validate_month(month_label, analysis_date, commit_data,
                   enriched_sbom, asis_cves, patched_versions,
                   patched_cves, delta, npm_timeline,
                   all_commits, prev_month_data=None,
                   consecutive_reuse_count=0):
    """
    Run all validation gates for a single month.

    Returns: {passed: bool, errors: [], warnings: [], manual_review_flags: []}
    Saves validation report to logs/validation-report-{month}.json.
    """
    errors = []
    warnings = []
    flags = []
    analysis_date_str = analysis_date.strftime("%Y-%m-%d")

    # === Date Validation Rules ===

    # A2: commit date <= analysis_date
    if commit_data:
        commit_date_str = commit_data["date"].strftime("%Y-%m-%d")
        if commit_date_str > analysis_date_str:
            errors.append(
                f"A2: selected commit date {commit_date_str} is after "
                f"analysis date {analysis_date_str}"
            )

    # A3: all patched version publish dates <= analysis_date
    for pv in patched_versions.get("patched_versions", []):
        pub = pv.get("patched_publish_date", "")
        if pub and pub > analysis_date_str:
            errors.append(
                f"A3: patched version {pv['package']}@{pv['patched_version']} "
                f"published {pub} is after analysis date {analysis_date_str}"
            )

    # A4: all AS-IS CVE published_dates <= analysis_date
    for cve in asis_cves.get("cves", []):
        pub = cve.get("published_date", "")
        if pub and pub > analysis_date_str:
            errors.append(
                f"A4: AS-IS CVE {cve['cve_id']} published {pub} is after "
                f"analysis date {analysis_date_str}"
            )

    # A5/A6: zero-day and N-day bucket checks
    for pc in patched_cves.get("patched_cves", []):
        pub = pc.get("published_date", "")
        if pc["is_zeroday"] and pub and pub <= analysis_date_str:
            errors.append(
                f"A5: zero-day CVE {pc['cve_id']} has published_date {pub} "
                f"<= analysis_date (should be strictly after)"
            )
        if pc["is_nday"] and pub and pub > analysis_date_str:
            errors.append(
                f"A6: N-day CVE {pc['cve_id']} has published_date {pub} "
                f"> analysis_date (should be on or before)"
            )

    # === Reconciliation Checks ===

    asis_set = set(m["cve_id"] for m in asis_cves.get("cves", []))
    patched_all = patched_cves.get("patched_cves", [])
    patched_nday_set = set(c["cve_id"] for c in patched_all if c["is_nday"])
    patched_zeroday_set = set(c["cve_id"] for c in patched_all if c["is_zeroday"])
    patched_set = patched_nday_set | patched_zeroday_set

    expected_fixed = len(asis_set - patched_set)
    if delta["cves_fixed"] != expected_fixed:
        errors.append(
            f"Reconciliation: cves_fixed={delta['cves_fixed']} != "
            f"|AS-IS \\ PATCHED|={expected_fixed}"
        )

    p_summary = patched_cves.get("summary", {})
    expected_total = p_summary.get("patched_nday", 0) + p_summary.get("patched_zeroday", 0)
    if p_summary.get("patched_total_cves", 0) != expected_total:
        errors.append(
            f"Reconciliation: patched_total={p_summary.get('patched_total_cves')} != "
            f"nday+zeroday={expected_total}"
        )

    expected_churn = delta["nday_introduced"] + delta["zeroday_introduced"]
    if delta["churn_introduced"] != expected_churn:
        errors.append(
            f"Reconciliation: churn={delta['churn_introduced']} != "
            f"nday_intro+zeroday_intro={expected_churn}"
        )

    expected_net = delta["cves_fixed"] - delta["nday_introduced"]
    if delta["net_reduction"] != expected_net:
        errors.append(
            f"Reconciliation: net_reduction={delta['net_reduction']} != "
            f"fixed-nday_intro={expected_net}"
        )

    a_summary = asis_cves.get("summary", {})
    npm_v = a_summary.get("npm_packages_vulnerable", 0)
    npm_nv = a_summary.get("npm_packages_non_vulnerable", 0)
    npm_t = a_summary.get("npm_packages_total", 0)
    if npm_v + npm_nv != npm_t:
        errors.append(
            f"Reconciliation: vuln({npm_v})+non_vuln({npm_nv}) != total({npm_t})"
        )

    counts = enriched_sbom.get("counts", {})
    npm_d = counts.get("npm_packages_direct", 0)
    npm_tr = counts.get("npm_packages_transitive", 0)
    npm_u = counts.get("npm_unknown_depth", 0)
    npm_total = counts.get("npm_packages_total", 0)
    if npm_d + npm_tr + npm_u != npm_total:
        errors.append(
            f"Reconciliation: direct({npm_d})+trans({npm_tr})+unknown({npm_u}) "
            f"!= total({npm_total})"
        )

    # Duplicate checks
    cve_pkg_keys = set()
    for cve in asis_cves.get("cves", []):
        key = f"{cve['cve_id']}|{cve['package']}|{cve['version']}"
        if key in cve_pkg_keys:
            errors.append(f"Duplicate CVE-package-version: {key}")
        cve_pkg_keys.add(key)

    # === Anomaly Detection (flags, not hard stops) ===

    if a_summary.get("asis_total_cves", 0) == 0 and prev_month_data:
        prev_total = prev_month_data.get("asis_total_cves", 0)
        if prev_total > 0:
            flags.append("AS-IS CVE count dropped to zero unexpectedly")

    if prev_month_data:
        prev_npm_total = prev_month_data.get("npm_packages_total", 0)
        curr_npm_total = npm_total
        if prev_npm_total > 0:
            change_pct = abs(curr_npm_total - prev_npm_total) / prev_npm_total * 100
            if change_pct > 30:
                flags.append(
                    f"Dependency count changed by {change_pct:.0f}% "
                    f"({prev_npm_total} -> {curr_npm_total})"
                )

    if consecutive_reuse_count > 3:
        flags.append(
            f"Same commit reused for {consecutive_reuse_count} consecutive months"
        )

    result = {
        "month": month_label,
        "analysis_date": analysis_date_str,
        "passed": len(errors) == 0,
        "errors": errors,
        "warnings": warnings,
        "manual_review_flags": flags,
        "checks_run": {
            "date_validations": 5,
            "reconciliation_checks": 6,
            "anomaly_detections": 3,
        },
    }

    os.makedirs("logs", exist_ok=True)
    out_path = os.path.join("logs", f"validation-report-{month_label}.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)

    return result
