# Build Log -- Longitudinal SBOM CVE Analysis Pipeline v17

## Pre-Requisites Verified
- Python 3.12.3
- Node.js v22.11.0
- Git 2.47.0
- Syft 1.29.0
- OS: Windows 10

---

## Phase 0A -- Bootstrap

### Step 1: Create directory structure
Directories created:
- `src/` -- Python pipeline modules
- `tools/` -- Node.js semver helper
- `raw/syft/` -- Raw Syft SBOM outputs
- `raw/osv-responses/` -- Raw OSV.dev API responses
- `raw/osv-per-package/` -- Normalized per-package OSV cache
- `raw/npm-registry-responses/` -- Raw npm registry responses
- `raw/npm-per-package/` -- Normalized per-package npm timeline cache
- `derived/` -- Computed monthly analysis files
- `logs/` -- Execution logs, validation reports, audit trails
- `master/` -- One-time reference data (CVE ref, npm timeline, etc.)
- `reports/plots/` -- Generated graphs (PNG)
- `reports/tables/` -- Summary tables (CSV)

Command: `mkdir src, tools, raw/syft, raw/osv-responses, ...` (see below)

### Step 2: Create study-config.json
Frozen study configuration per methodology v17 Section 3.2.
All policy decisions documented before first run.

### Step 3: Create src/__init__.py
Empty file. Required for `from src.config import ...` imports.

### Step 4: Create requirements.txt
Only non-stdlib dependency: matplotlib>=3.7 (for reporter.py in Phase 4).

### Step 5: Update .gitignore
Added: raw/, derived/, master/, reports/, tools/node_modules/, runs/

### Step 6: Create tools/semver_check.js
Batch-mode Node.js helper for npm semver range matching.
Reads JSON array from stdin, returns boolean results.

Command: `cd tools; npm init -y; npm install semver`

### Step 6b: Verify semver_check.js
Command: `echo '[{"op":"satisfies","version":"1.2.3","range":">=1.0.0 <2.0.0"}]' | node semver_check.js`
Result: `[true]` -- working correctly.

### Step 6c: Fetch latest repo commits
Local clone only had 15 commits (Burst 1). Needed `git fetch --all` + merge
to get all 24 commits including the March 2026 Angular upgrade chain.
Command: `git -C repos/hcdp_file_explorer fetch --all`
Command: `git -C repos/hcdp_file_explorer merge origin/main --ff-only`
Result: 24 commits, first=4d887cb (2025-03-12), last=619c10f (2026-03-17)

### Step 7: Create src/config.py
Functions: load_config(), compute_analysis_dates(), get_month_label()
Generates 13 end-of-month analysis dates (2025-03-31 through 2026-03-31).

### Step 8: Create src/git_ops.py
Functions: clone_repo(), get_all_commits(), select_commit_for_date(),
           checkout_commit(), get_lockfile_changing_commits()
All git operations via subprocess.run.

### Step 9: Create src/normalizer.py
Functions: normalize_package_name(), parse_purl(), log_package_match(),
           log_ambiguous_item()
Package name normalization + audit logging per methodology Section 5.4.

### Step 9b: Fix purl scoped-package bug
parse_purl was producing `@@angular/core` (double @) for URL-encoded scoped
package purls like `pkg:npm/%40angular/core@17.3.0`. Fixed by checking if
namespace already starts with `@` before prepending.

### Verification Results
- 24 commits found (matches checklist: 15 Burst 1 + 9 Burst 2)
- 13 analysis dates computed (2025-03-31 through 2026-03-31)
- Month 1 -> commit 4712ac7 (2025-03-15), lockfile present
- Month 13 -> commit 619c10f (2026-03-17)
- Months 1-12: same_commit_reused=True (12-month gap, expected)
- Month 13: same_commit_reused=False (Angular upgrade burst)
- 6 lockfile-changing commits found: initial, app, angular 18/19/20/21
- Purl parsing: scoped (@angular/core), unscoped (express), debian (openssl) all correct

### Bug Fixes (pre-Phase 0B review)
1. CRITICAL: phase0_setup.py -- lstrip("node_modules/") strips chars not substring.
   Fixed with split("node_modules/")[-1] to extract last segment (handles nested deps).
2. HIGH: osv_client.py -- _cvss_string_to_severity was stub returning None.
   Documented limitation explicitly. Falls back to database_specific.severity.
3. MEDIUM: npm_client.py -- rate limiting never fired (cache check after write).
   Fixed by checking was_cached BEFORE calling fetch_npm_package.
4. LOW: phase0_setup.py -- dead contributors loop. Added get_contributor_count()
   to git_ops.py, wired it into repo-facts.json.
5. LOW: osv_client.py -- removed unused `import hashlib` and unused `modified` var.

### Phase 0A Status: COMPLETE

---

## Phase 0B -- Master Reference Data

### Step 1: Create src/osv_client.py
OSV.dev API client with pagination, per-package caching, and rate limiting.
Queries POST /v1/query per package to get all advisories.

### Step 2: Create src/npm_client.py
npm registry client fetching full package documents (including `time` map).
Date-filtered version lookups replace packaging.version sorting.

### Step 3: Create phase0_setup.py
One-time orchestrator: package discovery -> OSV queries -> npm queries.

### Step 4: Run phase0_setup.py
Command: `python phase0_setup.py`
Required 3 attempts due to network interruptions (caching made restarts instant).

Results:
- 1015 unique packages discovered from 8 lockfile commits
- 305 OSV advisories found across all packages
- 166,063 npm version timeline entries
- All 1015/1015 OSV and 1015/1015 npm packages cached

Master artifacts produced:
  master/lockfile-change-commits.json    (0.9 KB, 6 commits)
  master/monthly-selected-commits.json   (3.6 KB, 13 checkpoints)
  master/master-cve-reference.v1.json    (229 KB, 305 advisories)
  master/npm-version-timeline.v1.json    (8.7 MB, 166,063 versions)
  master/repo-facts.json                 (0.5 KB)

### Phase 0B Status: COMPLETE

---

## Phase 1 -- Monthly Loop Modules

### Module 1: src/semver_engine.py
Python wrapper around tools/semver_check.js.
Functions: check_batch(), satisfies(), satisfies_batch(), compare(), sort_versions()
All npm range matching routes through here (never packaging.version).

### Module 2: src/sbom.py (Step 1)
Syft filesystem SBOM generation + lockfile parsing + depth tagging.
Functions: generate_sbom(), parse_lockfile(), parse_package_json(),
           extract_packages_from_syft(), tag_dependency_depth(), build_enriched_sbom()
Uses lockfile as authoritative source, Syft for non-npm packages.

### Module 3: src/cve_matcher.py (Step 2)
AS-IS CVE matching against master reference with date filtering.
Functions: match_asis_cves()
Batch semver checks for efficiency. Produces severity/ecosystem/depth breakdowns.

### Module 4: src/patched_state.py (Steps 3, 4, 5)
Step 3: compute_patched_versions() -- highest npm version <= analysis_date
Step 4: enumerate_intermediates() -- all versions between AS-IS and PATCHED
Step 5: compute_patched_cves() -- N-day/zero-day split, churn-introduced detection

### Module 5: src/delta.py (Step 6)
Set operations: cves_fixed, nday_introduced, zeroday_introduced,
churn_introduced, net_reduction, patched_retained, intermediate peaks.

### Module 6: src/validator.py (Step 7)
Hard-stop gates (A2-A7), reconciliation checks (6 invariants),
anomaly detection (3 triggers). Pipeline halts on any error.

### Module 7: src/confidence.py
HIGH/MEDIUM/LOW assignment per methodology Section 7.5 thresholds.

### Module 8: src/execution_log.py
Appends 45-field JSON entry to logs/master-execution-log.json.
Field names match reporter.py graph-to-field mapping exactly.

### Phase 1 Status: COMPLETE (code written, not yet executed)
Files created:
  study-config.json        src/__init__.py      requirements.txt
  tools/semver_check.js    tools/package.json   tools/package-lock.json
  src/config.py            src/git_ops.py       src/normalizer.py
  .gitignore (updated)     BUILD_LOG.md
