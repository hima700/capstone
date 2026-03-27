#!/usr/bin/env bash
# =============================================================================
# Universal SBOM Vulnerability Analysis Pipeline
#
# A reusable, semi-automated pipeline that generates SBOMs, scans for
# vulnerabilities, queries open source databases (OSV, NVD, Debian Tracker),
# and produces a complete mitigation plan for ANY containerized project.
#
# Usage:
#   # If Docker image already exists:
#   ./pipeline.sh --project myapp --image myapp:latest
#
#   # If you need to build from a repo:
#   ./pipeline.sh --project myapp --repo ./repos/myapp --image myapp:capstone
#
#   # Full example with all options:
#   ./pipeline.sh \
#     --project hcdp-file-explorer \
#     --repo ./repos/hcdp_file_explorer \
#     --image hcdp-file-explorer:capstone \
#     --run-dir ./runs/2026-02-10 \
#     --skip-build        # if image already exists
#     --skip-nvd          # if no NVD API key
#
# Output structure:
#   runs/<date>/<project>/
#     sbom/          - Syft CycloneDX SBOM
#     grype/         - Grype vulnerability scan
#     merged/        - Combined SBOM + vulnerabilities
#     npm/           - npm/yarn audit + dependency tree
#     nvd/           - Cached NVD API responses
#     osv-cache/     - Cached OSV API responses
#     <project>-mitigation-report.json   - Full CVE analysis
#     <project>-migration-v2.json        - Migration analysis
#
# Requirements:
#   - Docker (for Syft, Grype, and project builds)
#   - Python 3 (for analysis scripts)
#   - jq (for JSON processing)
#   - NVD_API_KEY environment variable (optional, for NVD enrichment)
#
# Author: Ibrahim Matar
# Project: Capstone — University of Hawaii at Manoa
# =============================================================================

set -euo pipefail

# ─── Colors ───
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

log()  { echo -e "${GREEN}[✓]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[✗]${NC} $1"; }
info() { echo -e "${CYAN}[i]${NC} $1"; }
header() { echo -e "\n${BOLD}=== $1 ===${NC}\n"; }

# ─── Defaults ───
PROJECT=""
IMAGE=""
REPO_DIR=""
RUN_DIR=""
SCRIPTS_DIR=""
SKIP_BUILD=false
SKIP_NVD=false
SKIP_AUDIT=false
DATE_TAG=$(date +%Y-%m-%d)

# ─── Parse arguments ───
usage() {
    echo "Usage: $0 --project NAME --image TAG [options]"
    echo ""
    echo "Required:"
    echo "  --project NAME       Project name (used for output naming)"
    echo "  --image TAG          Docker image to scan (e.g. myapp:latest)"
    echo ""
    echo "Optional:"
    echo "  --repo PATH          Path to source repo (for building + audit)"
    echo "  --run-dir PATH       Output directory (default: ./runs/YYYY-MM-DD)"
    echo "  --scripts-dir PATH   Path to analysis scripts (default: ./scripts)"
    echo "  --skip-build         Don't build Docker image (assume it exists)"
    echo "  --skip-nvd           Skip NVD API queries in analysis"
    echo "  --skip-audit         Skip npm/yarn audit step"
    echo "  --help               Show this help"
    exit 1
}

while [[ $# -gt 0 ]]; do
    case $1 in
        --project)     PROJECT="$2"; shift 2 ;;
        --image)       IMAGE="$2"; shift 2 ;;
        --repo)        REPO_DIR="$2"; shift 2 ;;
        --run-dir)     RUN_DIR="$2"; shift 2 ;;
        --scripts-dir) SCRIPTS_DIR="$2"; shift 2 ;;
        --skip-build)  SKIP_BUILD=true; shift ;;
        --skip-nvd)    SKIP_NVD=true; shift ;;
        --skip-audit)  SKIP_AUDIT=true; shift ;;
        --help)        usage ;;
        *)             err "Unknown option: $1"; usage ;;
    esac
done

# Validate required args
if [ -z "$PROJECT" ] || [ -z "$IMAGE" ]; then
    err "Missing required arguments: --project and --image"
    usage
fi

# Set defaults
RUN_DIR="${RUN_DIR:-./runs/${DATE_TAG}}"
SCRIPTS_DIR="${SCRIPTS_DIR:-./scripts}"
OUTPUT_DIR="${RUN_DIR}/${PROJECT}"

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║   Universal SBOM Vulnerability Analysis Pipeline            ║"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║   Project:  ${PROJECT}"
echo "║   Image:    ${IMAGE}"
echo "║   Repo:     ${REPO_DIR:-N/A}"
echo "║   Output:   ${OUTPUT_DIR}"
echo "║   Date:     ${DATE_TAG}"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# ─── Pre-flight checks ───
header "Pre-flight Checks"

if ! command -v docker &>/dev/null; then
    err "Docker is not installed or not in PATH"
    exit 1
fi
log "Docker: $(docker --version | head -1)"

if ! command -v jq &>/dev/null; then
    err "jq is not installed (apt install jq / brew install jq)"
    exit 1
fi
log "jq: $(jq --version)"

if ! command -v python3 &>/dev/null; then
    err "Python3 is not installed"
    exit 1
fi
log "Python3: $(python3 --version)"

# Check for analysis scripts
if [ ! -d "$SCRIPTS_DIR" ]; then
    warn "Scripts directory not found: $SCRIPTS_DIR"
    warn "Phase 2 (analysis) will be skipped"
fi

# Check NVD API key
if [ -n "${NVD_API_KEY:-}" ]; then
    log "NVD API key: configured"
else
    warn "NVD_API_KEY not set — NVD enrichment will be slower or skipped"
    if [ "$SKIP_NVD" = false ]; then
        info "Use --skip-nvd to skip NVD queries, or set NVD_API_KEY"
    fi
fi

# Create output directories
mkdir -p "$OUTPUT_DIR"/{sbom,grype,merged,npm,nvd,osv-cache}
log "Output directories created: $OUTPUT_DIR"

# ═════════════════════════════════════════════════════════════════════
# PHASE 1: Build Docker Image (optional)
# ═════════════════════════════════════════════════════════════════════
header "Phase 1: Docker Image"

if [ "$SKIP_BUILD" = true ]; then
    info "Skipping build (--skip-build). Assuming image exists: $IMAGE"
    # Verify image exists
    if ! docker image inspect "$IMAGE" &>/dev/null; then
        err "Image '$IMAGE' not found. Remove --skip-build or build it first."
        exit 1
    fi
    log "Image found: $IMAGE"
elif [ -n "$REPO_DIR" ] && [ -d "$REPO_DIR" ]; then
    if [ -f "$REPO_DIR/Dockerfile" ]; then
        info "Building Docker image from $REPO_DIR ..."
        docker build -t "$IMAGE" "$REPO_DIR" 2>&1 | tail -5
        log "Built: $IMAGE"
    else
        warn "No Dockerfile found in $REPO_DIR — scanning image as-is"
        if ! docker image inspect "$IMAGE" &>/dev/null; then
            err "Image '$IMAGE' not found and no Dockerfile to build from."
            exit 1
        fi
    fi
else
    info "No --repo specified. Assuming image exists: $IMAGE"
    if ! docker image inspect "$IMAGE" &>/dev/null; then
        err "Image '$IMAGE' not found. Provide --repo to build, or build it manually."
        exit 1
    fi
    log "Image found: $IMAGE"
fi

# ═════════════════════════════════════════════════════════════════════
# PHASE 2: Syft SBOM Generation
# ═════════════════════════════════════════════════════════════════════
header "Phase 2: Syft SBOM Generation"

SYFT_OUTPUT="$OUTPUT_DIR/sbom/${PROJECT}-sbom.cdx.json"

info "Running Syft on $IMAGE ..."
docker run --rm \
    -v /var/run/docker.sock:/var/run/docker.sock \
    anchore/syft:latest \
    "$IMAGE" \
    -o cyclonedx-json 2>/dev/null | jq '.' > "$SYFT_OUTPUT"

COMP_COUNT=$(jq '.components | length' "$SYFT_OUTPUT")
DEP_COUNT=$(jq '.dependencies | length // 0' "$SYFT_OUTPUT")
log "SBOM generated: $COMP_COUNT components, $DEP_COUNT dependencies"

# Component breakdown
echo ""
info "Component breakdown:"
jq -r '.components | group_by(.type) | .[] | "    \(.[0].type // "unknown"): \(length)"' "$SYFT_OUTPUT"

# ═════════════════════════════════════════════════════════════════════
# PHASE 3: Grype Vulnerability Scan
# ═════════════════════════════════════════════════════════════════════
header "Phase 3: Grype Vulnerability Scan"

GRYPE_OUTPUT="$OUTPUT_DIR/grype/${PROJECT}-grype.cdx.json"

info "Running Grype on $IMAGE ..."
docker run --rm \
    -v /var/run/docker.sock:/var/run/docker.sock \
    anchore/grype:latest \
    "$IMAGE" \
    -o cyclonedx-json 2>/dev/null | jq '.' > "$GRYPE_OUTPUT"

VULN_COUNT=$(jq '.vulnerabilities | length // 0' "$GRYPE_OUTPUT")
UNIQUE_CVES=$(jq '[.vulnerabilities[].id] | unique | length' "$GRYPE_OUTPUT")
log "Scan complete: $VULN_COUNT entries, $UNIQUE_CVES unique CVEs"

echo ""
info "Severity breakdown:"
jq -r '.vulnerabilities // [] | group_by(.ratings[0].severity // "unknown") | .[] | "    \(.[0].ratings[0].severity // "unknown"): \(length)"' "$GRYPE_OUTPUT"

# ═════════════════════════════════════════════════════════════════════
# PHASE 4: Merge SBOM + Vulnerabilities
# ═════════════════════════════════════════════════════════════════════
header "Phase 4: Merge SBOM + Vulnerabilities"

MERGED_OUTPUT="$OUTPUT_DIR/merged/${PROJECT}-merged.cdx.json"

# Use merge script if available, otherwise use jq
if [ -f "$SCRIPTS_DIR/merge_cdx_vulns.py" ]; then
    python3 "$SCRIPTS_DIR/merge_cdx_vulns.py" "$SYFT_OUTPUT" "$GRYPE_OUTPUT" "$MERGED_OUTPUT"
else
    jq -s '.[0] + { "vulnerabilities": (.[1].vulnerabilities // []) }' \
        "$SYFT_OUTPUT" "$GRYPE_OUTPUT" | jq '.' > "$MERGED_OUTPUT"
    log "Merged SBOM: $MERGED_OUTPUT"
fi

MERGED_VULNS=$(jq '.vulnerabilities | length // 0' "$MERGED_OUTPUT")
log "Merged: $COMP_COUNT components + $MERGED_VULNS vulnerabilities"

# ═════════════════════════════════════════════════════════════════════
# PHASE 5: Package Manager Audit (npm/yarn)
# ═════════════════════════════════════════════════════════════════════
header "Phase 5: Package Manager Audit"

if [ "$SKIP_AUDIT" = true ]; then
    info "Skipping audit (--skip-audit)"
else
    # Auto-detect package manager from the Docker image
    PKG_MANAGER="unknown"

    # Check what's in the image
    HAS_YARN_LOCK=$(docker run --rm "$IMAGE" sh -c "test -f yarn.lock && echo yes || echo no" 2>/dev/null || echo "no")
    HAS_PACKAGE_LOCK=$(docker run --rm "$IMAGE" sh -c "test -f package-lock.json && echo yes || echo no" 2>/dev/null || echo "no")
    HAS_PACKAGE_JSON=$(docker run --rm "$IMAGE" sh -c "test -f package.json && echo yes || echo no" 2>/dev/null || echo "no")

    # Also check source repo if available
    if [ -n "$REPO_DIR" ] && [ -d "$REPO_DIR" ]; then
        [ -f "$REPO_DIR/yarn.lock" ] && HAS_YARN_LOCK="yes"
        [ -f "$REPO_DIR/package-lock.json" ] && HAS_PACKAGE_LOCK="yes"
        [ -f "$REPO_DIR/package.json" ] && HAS_PACKAGE_JSON="yes"

        # Check subdirectories for monorepos
        for sub in webstack app src; do
            [ -f "$REPO_DIR/$sub/yarn.lock" ] && HAS_YARN_LOCK="yes"
            [ -f "$REPO_DIR/$sub/package-lock.json" ] && HAS_PACKAGE_LOCK="yes"
        done
    fi

    if [ "$HAS_YARN_LOCK" = "yes" ]; then
        PKG_MANAGER="yarn"
    elif [ "$HAS_PACKAGE_LOCK" = "yes" ] || [ "$HAS_PACKAGE_JSON" = "yes" ]; then
        PKG_MANAGER="npm"
    fi

    info "Detected package manager: $PKG_MANAGER"

    AUDIT_OUTPUT="$OUTPUT_DIR/npm/${PROJECT}-npm-audit.json"
    TREE_OUTPUT="$OUTPUT_DIR/npm/${PROJECT}-npm-tree.json"

    case "$PKG_MANAGER" in
        npm)
            info "Running npm audit inside container..."
            docker run --rm "$IMAGE" sh -c "npm audit --json 2>/dev/null" \
                > "$AUDIT_OUTPUT" 2>/dev/null || true

            info "Running npm ls inside container..."
            docker run --rm "$IMAGE" sh -c "npm ls --all --json 2>/dev/null" \
                > "$TREE_OUTPUT" 2>/dev/null || true

            AUDIT_VULNS=$(jq '.metadata.vulnerabilities // {} | to_entries | map(.value) | add // 0' "$AUDIT_OUTPUT" 2>/dev/null || echo "0")
            log "npm audit: $AUDIT_VULNS vulnerabilities"
            ;;
        yarn)
            info "Running yarn audit inside container..."
            docker run --rm "$IMAGE" sh -c "yarn audit --json 2>/dev/null" \
                > "$AUDIT_OUTPUT" 2>/dev/null || true

            info "Running yarn list inside container..."
            docker run --rm "$IMAGE" sh -c "yarn list --json 2>/dev/null" \
                > "$TREE_OUTPUT" 2>/dev/null || true

            log "yarn audit output saved"
            ;;
        *)
            warn "No recognized package manager found — skipping audit"
            echo '{}' > "$AUDIT_OUTPUT"
            echo '{}' > "$TREE_OUTPUT"
            ;;
    esac
fi

# ═════════════════════════════════════════════════════════════════════
# PHASE 6: CVE Analysis (analyze-cves.py)
# ═════════════════════════════════════════════════════════════════════
header "Phase 6: CVE Analysis & Enrichment"

# Find the analyze-cves script (may be named differently)
ANALYZE_SCRIPT=""
for candidate in \
    "$SCRIPTS_DIR/analyze-cves.py" \
    "$SCRIPTS_DIR/01_extract_vulnerable_dependencies.py" \
    "$SCRIPTS_DIR/analyze_cves.py"; do
    if [ -f "$candidate" ]; then
        ANALYZE_SCRIPT="$candidate"
        break
    fi
done

if [ -n "$ANALYZE_SCRIPT" ]; then
    info "Running CVE analysis: $ANALYZE_SCRIPT"

    NVD_FLAG=""
    if [ "$SKIP_NVD" = true ]; then
        NVD_FLAG="--skip-nvd"
    fi

    python3 "$ANALYZE_SCRIPT" \
        --run-dir "$RUN_DIR" \
        --project "$PROJECT" \
        $NVD_FLAG \
        || warn "CVE analysis had errors (continuing)"

    # Check if output was generated
    if [ -f "$OUTPUT_DIR/${PROJECT}-mitigation-report.json" ]; then
        CVE_COUNT=$(jq 'length' "$OUTPUT_DIR/${PROJECT}-mitigation-report.json")
        log "CVE analysis complete: $CVE_COUNT CVEs analyzed"
    else
        warn "Mitigation report not generated — check script output"
    fi
else
    warn "No analyze-cves.py found in $SCRIPTS_DIR — skipping CVE analysis"
    warn "Expected one of: analyze-cves.py, 01_extract_vulnerable_dependencies.py"
fi

# ═════════════════════════════════════════════════════════════════════
# PHASE 7: Migration Analysis (migration-analyzer-v2.py)
# ═════════════════════════════════════════════════════════════════════
header "Phase 7: Migration Analysis (OSV + Debian Tracker + NVD)"

MIGRATION_SCRIPT=""
for candidate in \
    "$SCRIPTS_DIR/migration-analyzer-v2.py" \
    "$SCRIPTS_DIR/migration_analyzer_v2.py"; do
    if [ -f "$candidate" ]; then
        MIGRATION_SCRIPT="$candidate"
        break
    fi
done

if [ -n "$MIGRATION_SCRIPT" ] && [ -f "$OUTPUT_DIR/${PROJECT}-mitigation-report.json" ]; then
    info "Running migration analysis: $MIGRATION_SCRIPT"

    SKIP_OSV_FLAG=""
    # migration-analyzer-v2.py doesn't have --skip-nvd, it reads from cached data

    python3 "$MIGRATION_SCRIPT" \
        --run-dir "$RUN_DIR" \
        --project "$PROJECT" \
        || warn "Migration analysis had errors (continuing)"

    if [ -f "$OUTPUT_DIR/${PROJECT}-migration-v2.json" ]; then
        PKG_COUNT=$(jq 'length' "$OUTPUT_DIR/${PROJECT}-migration-v2.json")
        log "Migration analysis complete: $PKG_COUNT packages analyzed"
    fi
else
    if [ -z "$MIGRATION_SCRIPT" ]; then
        warn "No migration-analyzer-v2.py found in $SCRIPTS_DIR — skipping"
    else
        warn "Skipping migration analysis — mitigation report not available"
    fi
fi

# ═════════════════════════════════════════════════════════════════════
# SUMMARY
# ═════════════════════════════════════════════════════════════════════
echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                    PIPELINE COMPLETE                        ║"
echo "╠══════════════════════════════════════════════════════════════╣"
printf "║  Project:       %-42s ║\n" "$PROJECT"
printf "║  Image:         %-42s ║\n" "$IMAGE"
printf "║  Components:    %-42s ║\n" "$COMP_COUNT"
printf "║  Unique CVEs:   %-42s ║\n" "$UNIQUE_CVES"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║  Output files:                                              ║"
echo "║    $OUTPUT_DIR/"
echo "║      sbom/     - Syft CycloneDX SBOM                       ║"
echo "║      grype/    - Grype vulnerability scan                   ║"
echo "║      merged/   - Combined SBOM + vulnerabilities            ║"
echo "║      npm/      - Package manager audit results              ║"

if [ -f "$OUTPUT_DIR/${PROJECT}-mitigation-report.json" ]; then
echo "║      ${PROJECT}-mitigation-report.json"
fi
if [ -f "$OUTPUT_DIR/${PROJECT}-migration-v2.json" ]; then
echo "║      ${PROJECT}-migration-v2.json"
echo "║      ${PROJECT}-migration-v2.txt"
echo "║      ${PROJECT}-migration-v2.csv"
fi

echo "╠══════════════════════════════════════════════════════════════╣"
echo "║  Next steps:                                                ║"
echo "║  1. Review the migration analysis report                    ║"
echo "║  2. Build variant images (patched-slim, alpine)             ║"
echo "║  3. Run this pipeline on each variant                       ║"
echo "║  4. Compare variants:                                       ║"
echo "║     python3 scripts/compare-variants.py \\                   ║"
echo "║       --run-dir $RUN_DIR \\                "
echo "║       --baseline $PROJECT \\               "
echo "║       --variants ${PROJECT}-patched-slim ${PROJECT}-alpine  "
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""