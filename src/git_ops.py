"""
Git operations for the SBOM CVE pipeline.

Handles cloning, commit enumeration, date-based commit selection,
checkout, and lockfile-change detection. All operations use
subprocess.run -- no git libraries.
"""

import subprocess
import os
from datetime import datetime, timezone
from pathlib import Path


def _run_git(args, cwd, check=True):
    """Run a git command and return stdout as a string."""
    result = subprocess.run(
        ["git"] + args,
        cwd=cwd,
        capture_output=True,
        text=True,
        check=check,
    )
    return result.stdout.strip()


def clone_repo(url, dest):
    """Clone the repository if it does not already exist."""
    dest_path = Path(dest)
    if dest_path.exists() and (dest_path / ".git").exists():
        return False  # already cloned
    dest_path.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["git", "clone", url, str(dest_path)],
        check=True,
        capture_output=True,
        text=True,
    )
    return True


def get_all_commits(repo_path):
    """
    Return all commits sorted by author date (oldest first).

    Each entry: {"hash": str, "date": datetime(UTC), "message": str}
    """
    log_format = "%H|%aI|%s"
    raw = _run_git(
        ["log", "--all", "--format=" + log_format, "--date-order"],
        cwd=repo_path,
    )
    if not raw:
        return []

    commits = []
    for line in raw.splitlines():
        parts = line.split("|", 2)
        if len(parts) < 3:
            continue
        commit_hash = parts[0]
        date_str = parts[1]
        message = parts[2]
        commit_date = datetime.fromisoformat(date_str).astimezone(timezone.utc)
        commits.append({
            "hash": commit_hash,
            "date": commit_date,
            "message": message,
        })

    commits.sort(key=lambda c: c["date"])
    return commits


def select_commit_for_date(commits, analysis_date):
    """
    Select the latest commit on or before analysis_date.

    Returns the commit dict, or None if no eligible commit exists.
    Never hardcoded -- purely algorithmic selection per methodology.
    """
    eligible = [c for c in commits if c["date"] <= analysis_date]
    if not eligible:
        return None
    return eligible[-1]


def checkout_commit(repo_path, commit_hash):
    """Check out a specific commit (detached HEAD)."""
    _run_git(["checkout", commit_hash, "--quiet", "--force"], cwd=repo_path)


def get_lockfile_changing_commits(repo_path):
    """
    Return commits that added, changed, or deleted package-lock.json.

    Used by Phase 0 for package discovery: extracting the lockfile at
    each of these commits catches transiently-present packages that
    would be missed by examining only the initial and final states.
    """
    raw = _run_git(
        [
            "log", "--all", "--format=%H|%aI|%s",
            "--diff-filter=ACDM", "--", "package-lock.json",
        ],
        cwd=repo_path,
    )
    if not raw:
        return []

    commits = []
    for line in raw.splitlines():
        parts = line.split("|", 2)
        if len(parts) < 3:
            continue
        commits.append({
            "hash": parts[0],
            "date": datetime.fromisoformat(parts[1]).astimezone(timezone.utc),
            "message": parts[2],
        })

    commits.sort(key=lambda c: c["date"])
    return commits


def get_contributor_count(repo_path):
    """Return the number of unique commit authors."""
    raw = _run_git(["log", "--all", "--format=%aN"], cwd=repo_path)
    if not raw:
        return 0
    return len(set(raw.splitlines()))


def has_file_at_commit(repo_path, commit_hash, filepath):
    """Check whether a file exists at a given commit."""
    result = subprocess.run(
        ["git", "cat-file", "-e", f"{commit_hash}:{filepath}"],
        cwd=repo_path,
        capture_output=True,
    )
    return result.returncode == 0


def show_file_at_commit(repo_path, commit_hash, filepath):
    """Return the contents of a file at a given commit, or None."""
    result = subprocess.run(
        ["git", "show", f"{commit_hash}:{filepath}"],
        cwd=repo_path,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return None
    return result.stdout
