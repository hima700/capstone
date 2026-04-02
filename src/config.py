"""
Study configuration loader and analysis date computation.

Loads study-config.json and generates the 13 monthly analysis dates
(end-of-month 23:59:59 UTC) from 2025-03-31 through 2026-03-31.
"""

import json
import calendar
from datetime import datetime, timezone
from pathlib import Path

REQUIRED_CONFIG_KEYS = [
    "project_name", "repo_url", "repo_local_path",
    "first_commit_hash", "first_commit_date",
    "study_start", "study_end", "analysis_date_rule",
    "patch_simulation_policy", "dev_dependencies_included",
    "package_counting_unit", "semver_engine",
]


def load_config(path="study-config.json"):
    """Load and validate the frozen study configuration."""
    config_path = Path(path)
    if not config_path.exists():
        raise FileNotFoundError(f"Study config not found: {config_path}")

    with open(config_path, "r", encoding="utf-8") as f:
        config = json.load(f)

    missing = [k for k in REQUIRED_CONFIG_KEYS if k not in config]
    if missing:
        raise ValueError(f"Missing required config keys: {missing}")

    if config["analysis_date_rule"] != "end-of-month 23:59:59 UTC":
        raise ValueError(
            f"Unsupported analysis_date_rule: {config['analysis_date_rule']}"
        )

    return config


def compute_analysis_dates(config):
    """
    Generate the list of monthly analysis dates as datetime objects.

    Each date is the last day of the month at 23:59:59 UTC,
    starting from study_start through study_end (inclusive).
    """
    start = datetime.strptime(config["study_start"], "%Y-%m-%d").replace(
        tzinfo=timezone.utc
    )
    end = datetime.strptime(config["study_end"], "%Y-%m-%d").replace(
        tzinfo=timezone.utc
    )

    dates = []
    year, month = start.year, start.month

    while True:
        last_day = calendar.monthrange(year, month)[1]
        analysis_date = datetime(
            year, month, last_day, 23, 59, 59, tzinfo=timezone.utc
        )

        if analysis_date > end.replace(hour=23, minute=59, second=59):
            break

        dates.append(analysis_date)

        month += 1
        if month > 12:
            month = 1
            year += 1

    return dates


def get_month_label(analysis_date):
    """Return 'YYYY-MM' string for file naming."""
    return analysis_date.strftime("%Y-%m")


def format_analysis_date(analysis_date):
    """Return ISO 8601 string for JSON output."""
    return analysis_date.strftime("%Y-%m-%dT%H:%M:%SZ")
