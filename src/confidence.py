"""
Confidence level assignment for the SBOM CVE pipeline.

Methodology v17 Section 7.5:
  HIGH:   lockfile present, all resolved, zero unknowns/exclusions
  MEDIUM: lockfile missing OR any non-zero unknowns/unresolved/excluded
  LOW:    incomplete metadata OR > 5% excluded/unresolved

Thresholds are reproducible: any non-zero exclusion downgrades HIGH->MEDIUM;
exceeding 5% of the relevant population downgrades to LOW.
"""


def assign_confidence(enriched_sbom, asis_cves, patched_versions):
    """
    Assign confidence level for a single month.

    Returns: "HIGH", "MEDIUM", or "LOW"
    """
    lockfile_present = enriched_sbom.get("lockfile_present", False)
    counts = enriched_sbom.get("counts", {})
    unknown_depth = counts.get("npm_unknown_depth", 0)
    npm_total = counts.get("npm_packages_total", 0)

    a_summary = asis_cves.get("summary", {})
    excluded_advisories = a_summary.get("excluded_advisory_count", 0)
    packages_checked = a_summary.get("packages_checked", 0)

    pv = patched_versions
    unresolved = pv.get("unresolved_count", 0)
    npm_eligible = len(pv.get("patched_versions", [])) + unresolved

    if not lockfile_present:
        if npm_total > 0:
            return "LOW"
        return "MEDIUM"

    has_any_issue = (unknown_depth > 0 or unresolved > 0 or excluded_advisories > 0)

    if has_any_issue:
        exceeds_threshold = False

        if packages_checked > 0 and excluded_advisories / packages_checked > 0.05:
            exceeds_threshold = True
        if npm_eligible > 0 and unresolved / npm_eligible > 0.05:
            exceeds_threshold = True

        return "LOW" if exceeds_threshold else "MEDIUM"

    return "HIGH"
