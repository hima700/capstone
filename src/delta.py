"""
Monthly delta computation for the SBOM CVE pipeline.

Methodology v17 Step 6: Calculate the delta between AS-IS and PATCHED states.
All metrics are set operations on CVE IDs.
"""

import json
import os


def compute_delta(asis_cves_data, patched_cves_data, intermediate_data, derived_dir):
    """
    Compute all monthly delta metrics per methodology Section 6.6.

    Returns delta dict and saves to derived/{month}-delta.json.
    """
    month = asis_cves_data["month"]

    asis_set = set(m["cve_id"] for m in asis_cves_data.get("cves", []))

    patched_all = patched_cves_data.get("patched_cves", [])
    patched_nday_set = set(c["cve_id"] for c in patched_all if c["is_nday"])
    patched_zeroday_set = set(c["cve_id"] for c in patched_all if c["is_zeroday"])
    patched_set = patched_nday_set | patched_zeroday_set

    cves_fixed = asis_set - patched_set
    nday_introduced = patched_nday_set - asis_set
    zeroday_introduced = patched_zeroday_set - asis_set
    churn_introduced = nday_introduced | zeroday_introduced
    patched_retained = asis_set & patched_set
    net_reduction = len(cves_fixed) - len(nday_introduced)

    intermediate_peak_package = ""
    intermediate_peak_count = 0
    intermediate_spikes = []

    for pkg_name, pkg_data in intermediate_data.get("packages", {}).items():
        asis_count = 0
        peak_count = 0
        for vd in pkg_data.get("version_data", []):
            if vd["version"] == pkg_data.get("asis_version"):
                asis_count = vd["cve_count"]
            if vd["cve_count"] > peak_count:
                peak_count = vd["cve_count"]

        if peak_count > intermediate_peak_count:
            intermediate_peak_count = peak_count
            intermediate_peak_package = pkg_name

        if peak_count > asis_count:
            intermediate_spikes.append({
                "package": pkg_name,
                "asis_count": asis_count,
                "peak_count": peak_count,
            })

    result = {
        "month": month,
        "cves_fixed": len(cves_fixed),
        "cves_fixed_ids": sorted(cves_fixed),
        "nday_introduced": len(nday_introduced),
        "nday_introduced_ids": sorted(nday_introduced),
        "zeroday_introduced": len(zeroday_introduced),
        "zeroday_introduced_ids": sorted(zeroday_introduced),
        "churn_introduced": len(churn_introduced),
        "net_reduction": net_reduction,
        "patched_retained": len(patched_retained),
        "patched_retained_ids": sorted(patched_retained),
        "intermediate_peak_package": intermediate_peak_package,
        "intermediate_peak_count": intermediate_peak_count,
        "intermediate_spikes": intermediate_spikes,
    }

    os.makedirs(derived_dir, exist_ok=True)
    out_path = os.path.join(derived_dir, f"{month}-delta.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)

    return result
