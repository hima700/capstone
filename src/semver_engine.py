"""
node-semver subprocess wrapper for the SBOM CVE pipeline.

All npm version range matching goes through this module.
Uses tools/semver_check.js for correctness (methodology v17 Section 3.2
forbids PEP 440 / packaging.version for npm ranges).

Batch mode: sends multiple checks in a single subprocess call to
avoid spawning thousands of processes across 13 months.
"""

import json
import subprocess
import os

SEMVER_HELPER = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "tools", "semver_check.js",
)


def check_batch(checks):
    """
    Run a batch of semver operations via node-semver.

    Each check is a dict with an "op" key:
      {"op": "satisfies", "version": "1.2.3", "range": ">=1.0.0 <2.0.0"}
      {"op": "compare", "a": "1.2.3", "b": "2.0.0"}
      {"op": "sort", "versions": ["3.0.0", "1.0.0"]}

    Returns a list of results (bool/int/list/None) in the same order.
    None means the input could not be parsed by node-semver.
    """
    if not checks:
        return []

    input_json = json.dumps(checks)
    result = subprocess.run(
        ["node", SEMVER_HELPER],
        input=input_json,
        capture_output=True,
        text=True,
        timeout=60,
    )

    if result.returncode != 0:
        raise RuntimeError(
            f"semver_check.js failed (exit {result.returncode}): {result.stderr}"
        )

    return json.loads(result.stdout)


def satisfies(version, range_str):
    """Check if a version satisfies an npm semver range. Returns bool or None."""
    results = check_batch([{"op": "satisfies", "version": version, "range": range_str}])
    return results[0]


def satisfies_batch(version_range_pairs):
    """
    Check multiple (version, range) pairs in one subprocess call.

    Input: list of (version_str, range_str) tuples.
    Returns: list of bool/None in the same order.
    """
    checks = [
        {"op": "satisfies", "version": v, "range": r}
        for v, r in version_range_pairs
    ]
    return check_batch(checks)


def compare(v1, v2):
    """Compare two versions. Returns -1, 0, 1, or None."""
    results = check_batch([{"op": "compare", "a": v1, "b": v2}])
    return results[0]


def sort_versions(versions):
    """Sort a list of version strings using node-semver ordering."""
    if not versions:
        return []
    results = check_batch([{"op": "sort", "versions": versions}])
    return results[0] if results[0] is not None else versions
