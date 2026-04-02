"""
Report generator for the SBOM CVE pipeline.

Methodology v17 Section 9: All graphs read the master execution log
as their primary data source. 8 required + 6 recommended graphs.

Styling extracted from plot-cve-trajectories.py with adaptations
for time-series line charts, stacked bars, and stacked area plots.
"""

import json
import os
import csv

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker

EXECUTION_LOG = os.path.join("logs", "master-execution-log.json")
PLOTS_DIR = os.path.join("reports", "plots")
TABLES_DIR = os.path.join("reports", "tables")

COLORS = {
    "asis": "#2196F3",
    "patched": "#4CAF50",
    "fixed": "#66BB6A",
    "nday": "#FF9800",
    "zeroday": "#F44336",
    "net": "#1565C0",
    "direct": "#7B1FA2",
    "transitive": "#00897B",
    "critical": "#D32F2F",
    "high": "#F57C00",
    "medium": "#FBC02D",
    "low": "#388E3C",
}


def load_execution_log():
    """Load and return the master execution log entries."""
    with open(EXECUTION_LOG, "r", encoding="utf-8") as f:
        return json.load(f)


def _month_labels(entries):
    """Extract short month labels from analysis_date fields."""
    labels = []
    for e in entries:
        ad = e["analysis_date"]
        labels.append(ad[:7])
    return labels


def _setup_axes(ax, title, ylabel, months):
    """Apply consistent styling to a chart."""
    ax.set_title(title, fontsize=13, fontweight="bold", pad=12)
    ax.set_ylabel(ylabel, fontsize=10)
    ax.set_xticks(range(len(months)))
    ax.set_xticklabels(months, rotation=45, ha="right", fontsize=8)
    ax.yaxis.set_major_locator(ticker.MaxNLocator(integer=True))
    ax.grid(axis="y", alpha=0.3, linewidth=0.5)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)


def _save(fig, filename):
    """Save figure to plots directory."""
    os.makedirs(PLOTS_DIR, exist_ok=True)
    path = os.path.join(PLOTS_DIR, filename)
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"  [OK] {filename}")


# =========================================================================
# 8 Required Graphs
# =========================================================================

def graph_01_asis_cves(entries, months):
    """Graph 1: AS-IS total known CVEs over time."""
    fig, ax = plt.subplots(figsize=(12, 5))
    vals = [e["asis_total_cves"] for e in entries]
    ax.plot(range(len(months)), vals, color=COLORS["asis"], marker="o",
            markersize=5, linewidth=2, label="AS-IS Known CVEs")
    for i, v in enumerate(vals):
        ax.annotate(str(v), (i, v), textcoords="offset points",
                    xytext=(0, 8), ha="center", fontsize=7)
    _setup_axes(ax, "AS-IS Total Known CVEs Over Time", "CVE Count", months)
    ax.legend(fontsize=9)
    _save(fig, "01-asis-total-cves.png")


def graph_02_patched_cves(entries, months):
    """Graph 2: PATCHED total CVEs over time (N-day + zero-day)."""
    fig, ax = plt.subplots(figsize=(12, 5))
    nday = [e["patched_nday"] for e in entries]
    zday = [e["patched_zeroday"] for e in entries]
    total = [n + z for n, z in zip(nday, zday)]
    ax.plot(range(len(months)), total, color=COLORS["patched"], marker="o",
            markersize=5, linewidth=2, label="PATCHED Total CVEs")
    ax.fill_between(range(len(months)), nday, total, alpha=0.3,
                    color=COLORS["zeroday"], label="Zero-day portion")
    ax.fill_between(range(len(months)), 0, nday, alpha=0.3,
                    color=COLORS["nday"], label="N-day portion")
    _setup_axes(ax, "PATCHED Total CVEs Over Time", "CVE Count", months)
    ax.legend(fontsize=9)
    _save(fig, "02-patched-total-cves.png")


def graph_03_cves_fixed(entries, months):
    """Graph 3: CVEs fixed by patching over time."""
    fig, ax = plt.subplots(figsize=(12, 5))
    vals = [e["cves_fixed"] for e in entries]
    ax.bar(range(len(months)), vals, color=COLORS["fixed"], width=0.6,
           edgecolor="white", linewidth=0.5)
    for i, v in enumerate(vals):
        ax.annotate(str(v), (i, v), textcoords="offset points",
                    xytext=(0, 5), ha="center", fontsize=7)
    _setup_axes(ax, "CVEs Fixed by Patching Over Time", "CVEs Fixed", months)
    _save(fig, "03-cves-fixed.png")


def graph_04_nday(entries, months):
    """Graph 4: N-day CVEs in the patched state over time."""
    fig, ax = plt.subplots(figsize=(12, 5))
    vals = [e["patched_nday"] for e in entries]
    ax.plot(range(len(months)), vals, color=COLORS["nday"], marker="s",
            markersize=5, linewidth=2, label="N-day CVEs (Patched)")
    _setup_axes(ax, "N-day CVEs in Patched State Over Time", "CVE Count", months)
    ax.legend(fontsize=9)
    _save(fig, "04-nday-patched.png")


def graph_05_zeroday(entries, months):
    """Graph 5: Zero-day CVEs in the patched state over time."""
    fig, ax = plt.subplots(figsize=(12, 5))
    vals = [e["patched_zeroday"] for e in entries]
    ax.plot(range(len(months)), vals, color=COLORS["zeroday"], marker="s",
            markersize=5, linewidth=2, label="Zero-day CVEs (Patched)")
    for i, v in enumerate(vals):
        ax.annotate(str(v), (i, v), textcoords="offset points",
                    xytext=(0, 8), ha="center", fontsize=7)
    _setup_axes(ax, "Zero-day CVEs in Patched State Over Time", "CVE Count", months)
    ax.legend(fontsize=9)
    _save(fig, "05-zeroday-patched.png")


def graph_06_net_reduction(entries, months):
    """Graph 6: Net reduction over time."""
    fig, ax = plt.subplots(figsize=(12, 5))
    vals = [e["net_reduction"] for e in entries]
    colors = [COLORS["net"] if v >= 0 else COLORS["zeroday"] for v in vals]
    ax.bar(range(len(months)), vals, color=colors, width=0.6,
           edgecolor="white", linewidth=0.5)
    for i, v in enumerate(vals):
        ax.annotate(str(v), (i, v), textcoords="offset points",
                    xytext=(0, 5), ha="center", fontsize=7)
    ax.axhline(y=0, color="gray", linewidth=0.8, linestyle="--")
    _setup_axes(ax, "Net CVE Reduction Over Time", "Net Reduction", months)
    _save(fig, "06-net-reduction.png")


def graph_07_dependency_count(entries, months):
    """Graph 7: Total npm dependency count over time."""
    fig, ax = plt.subplots(figsize=(12, 5))
    vals = [e["npm_packages_total"] for e in entries]
    ax.plot(range(len(months)), vals, color=COLORS["asis"], marker="o",
            markersize=5, linewidth=2)
    for i, v in enumerate(vals):
        ax.annotate(str(v), (i, v), textcoords="offset points",
                    xytext=(0, 8), ha="center", fontsize=7)
    _setup_axes(ax, "Total npm Dependency Count Over Time", "Package Count", months)
    _save(fig, "07-npm-dependency-count.png")


def graph_08_ecosystem_breakdown(entries, months):
    """Graph 8: Ecosystem breakdown over time (npm / Debian / Go)."""
    fig, ax = plt.subplots(figsize=(12, 5))
    npm = [e["asis_npm_cves"] for e in entries]
    deb = [e["asis_debian_cves"] for e in entries]
    go = [e["asis_go_cves"] for e in entries]
    x = range(len(months))
    ax.bar(x, npm, width=0.6, label="npm", color=COLORS["asis"])
    ax.bar(x, deb, width=0.6, bottom=npm, label="Debian", color="#78909C")
    bottom2 = [n + d for n, d in zip(npm, deb)]
    ax.bar(x, go, width=0.6, bottom=bottom2, label="Go", color="#A1887F")
    _setup_axes(ax, "AS-IS CVEs by Ecosystem Over Time", "CVE Count", months)
    ax.legend(fontsize=9)
    _save(fig, "08-ecosystem-breakdown.png")


# =========================================================================
# 6 Recommended Graphs
# =========================================================================

def graph_09_vuln_ratio(entries, months):
    """Graph 9: Vulnerability ratio over time."""
    fig, ax = plt.subplots(figsize=(12, 5))
    vals = []
    for e in entries:
        total = e["npm_packages_total"]
        vuln = e["npm_packages_vulnerable"]
        vals.append(vuln / total * 100 if total > 0 else 0)
    ax.plot(range(len(months)), vals, color=COLORS["zeroday"], marker="o",
            markersize=5, linewidth=2)
    for i, v in enumerate(vals):
        ax.annotate(f"{v:.1f}%", (i, v), textcoords="offset points",
                    xytext=(0, 8), ha="center", fontsize=7)
    _setup_axes(ax, "Vulnerability Ratio Over Time (% npm packages with CVEs)",
                "Vulnerable %", months)
    _save(fig, "09-vulnerability-ratio.png")


def graph_10_vuln_packages(entries, months):
    """Graph 10: npm vulnerable package count AS-IS vs PATCHED."""
    fig, ax = plt.subplots(figsize=(12, 5))
    asis = [e["npm_packages_vulnerable"] for e in entries]
    patched = [e["patched_npm_packages_vulnerable"] for e in entries]
    ax.plot(range(len(months)), asis, color=COLORS["asis"], marker="o",
            markersize=5, linewidth=2, label="AS-IS Vulnerable Packages")
    ax.plot(range(len(months)), patched, color=COLORS["patched"], marker="s",
            markersize=5, linewidth=2, label="PATCHED Vulnerable Packages")
    _setup_axes(ax, "Vulnerable npm Package Count: AS-IS vs PATCHED",
                "Package Count", months)
    ax.legend(fontsize=9)
    _save(fig, "10-vuln-packages-comparison.png")


def graph_11_severity_distribution(entries, months):
    """Graph 11: Severity distribution over time (stacked bar)."""
    fig, ax = plt.subplots(figsize=(12, 5))
    x = range(len(months))
    crit = [e["asis_severity_critical"] for e in entries]
    high = [e["asis_severity_high"] for e in entries]
    med = [e["asis_severity_medium"] for e in entries]
    low = [e["asis_severity_low"] for e in entries]
    ax.bar(x, crit, width=0.6, label="Critical", color=COLORS["critical"])
    ax.bar(x, high, width=0.6, bottom=crit, label="High", color=COLORS["high"])
    b2 = [c + h for c, h in zip(crit, high)]
    ax.bar(x, med, width=0.6, bottom=b2, label="Medium", color=COLORS["medium"])
    b3 = [a + m for a, m in zip(b2, med)]
    ax.bar(x, low, width=0.6, bottom=b3, label="Low", color=COLORS["low"])
    _setup_axes(ax, "AS-IS CVE Severity Distribution Over Time",
                "CVE Count", months)
    ax.legend(fontsize=9, loc="upper left")
    _save(fig, "11-severity-distribution.png")


def graph_12_direct_transitive(entries, months):
    """Graph 12: Direct vs transitive CVE split over time."""
    fig, ax = plt.subplots(figsize=(12, 5))
    x = range(len(months))
    direct = [e["direct_npm_dep_cves"] for e in entries]
    trans = [e["transitive_npm_dep_cves"] for e in entries]
    ax.bar(x, direct, width=0.6, label="Direct", color=COLORS["direct"])
    ax.bar(x, trans, width=0.6, bottom=direct, label="Transitive",
           color=COLORS["transitive"])
    _setup_axes(ax, "Direct vs Transitive npm CVE Split Over Time",
                "CVE Count", months)
    ax.legend(fontsize=9)
    _save(fig, "12-direct-transitive-split.png")


def graph_13_intermediate_spikes(entries, months):
    """Graph 13: Intermediate version spike count over time."""
    fig, ax = plt.subplots(figsize=(12, 5))
    vals = [e["intermediate_peak_count"] for e in entries]
    pkgs = [e["intermediate_peak_package"] for e in entries]
    ax.bar(range(len(months)), vals, color=COLORS["nday"], width=0.6,
           edgecolor="white", linewidth=0.5)
    for i, (v, p) in enumerate(zip(vals, pkgs)):
        if v > 0:
            ax.annotate(f"{v}\n({p[:15]})", (i, v), textcoords="offset points",
                        xytext=(0, 5), ha="center", fontsize=6)
    _setup_axes(ax, "Intermediate Version Peak CVE Count Over Time",
                "Peak CVE Count", months)
    _save(fig, "13-intermediate-spikes.png")


def graph_14_churn_introduced(entries, months):
    """Graph 14: Churn-introduced CVEs over time (N-day + zero-day stacked)."""
    fig, ax = plt.subplots(figsize=(12, 5))
    x = range(len(months))
    nday = [e["nday_introduced"] for e in entries]
    zday = [e["zeroday_introduced"] for e in entries]
    ax.bar(x, nday, width=0.6, label="N-day Introduced", color=COLORS["nday"])
    ax.bar(x, zday, width=0.6, bottom=nday, label="Zero-day Introduced",
           color=COLORS["zeroday"])
    _setup_axes(ax, "Churn-Introduced CVEs Over Time",
                "CVE Count", months)
    ax.legend(fontsize=9)
    _save(fig, "14-churn-introduced.png")


# =========================================================================
# CSV Tables
# =========================================================================

def write_summary_table(entries, months):
    """Write the monthly summary CSV table."""
    os.makedirs(TABLES_DIR, exist_ok=True)
    path = os.path.join(TABLES_DIR, "monthly-summary.csv")

    fields = [
        "month", "commit", "npm_total", "npm_direct", "npm_transitive",
        "asis_cves", "severity_C", "severity_H", "severity_M", "severity_L",
        "vuln_packages", "patched_total", "patched_nday", "patched_zeroday",
        "cves_fixed", "nday_intro", "zeroday_intro", "net_reduction",
        "confidence",
    ]

    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for e, m in zip(entries, months):
            writer.writerow({
                "month": m,
                "commit": e["selected_commit_hash"][:7] if e["selected_commit_hash"] else "",
                "npm_total": e["npm_packages_total"],
                "npm_direct": e["npm_packages_direct"],
                "npm_transitive": e["npm_packages_transitive"],
                "asis_cves": e["asis_total_cves"],
                "severity_C": e["asis_severity_critical"],
                "severity_H": e["asis_severity_high"],
                "severity_M": e["asis_severity_medium"],
                "severity_L": e["asis_severity_low"],
                "vuln_packages": e["npm_packages_vulnerable"],
                "patched_total": e["patched_total_cves"],
                "patched_nday": e["patched_nday"],
                "patched_zeroday": e["patched_zeroday"],
                "cves_fixed": e["cves_fixed"],
                "nday_intro": e["nday_introduced"],
                "zeroday_intro": e["zeroday_introduced"],
                "net_reduction": e["net_reduction"],
                "confidence": e["data_confidence"],
            })

    print(f"  [OK] {path}")


# =========================================================================
# Main entry point
# =========================================================================

def generate_all_reports():
    """Generate all graphs and tables from the execution log."""
    print("=" * 60)
    print("  Generating Reports")
    print("=" * 60)

    entries = load_execution_log()
    months = _month_labels(entries)
    print(f"  Loaded {len(entries)} months from execution log\n")

    print("  Required graphs (8):")
    graph_01_asis_cves(entries, months)
    graph_02_patched_cves(entries, months)
    graph_03_cves_fixed(entries, months)
    graph_04_nday(entries, months)
    graph_05_zeroday(entries, months)
    graph_06_net_reduction(entries, months)
    graph_07_dependency_count(entries, months)
    graph_08_ecosystem_breakdown(entries, months)

    print("\n  Recommended graphs (6):")
    graph_09_vuln_ratio(entries, months)
    graph_10_vuln_packages(entries, months)
    graph_11_severity_distribution(entries, months)
    graph_12_direct_transitive(entries, months)
    graph_13_intermediate_spikes(entries, months)
    graph_14_churn_introduced(entries, months)

    print("\n  Tables:")
    write_summary_table(entries, months)

    print(f"\n  Done. {14} graphs + 1 table generated.")
    print(f"  Plots: {PLOTS_DIR}/")
    print(f"  Tables: {TABLES_DIR}/")


if __name__ == "__main__":
    generate_all_reports()
