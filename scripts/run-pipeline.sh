#!/usr/bin/env bash
# =============================================================================
# SBOM Pipeline — HCDP API (Docker-based)
# Generates: Syft SBOM, Grype vulnerabilities, merged SBOM, npm audit/tree
# All tools run via Docker images for reproducibility
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration — adjust these for each repo
# ---------------------------------------------------------------------------
REPO_DIR="${1:-.}"                          # Path to cloned HCDP API repo
PROJECT_NAME="hcdp-api"                     # Used for output file naming
DOCKER_IMAGE_TAG="${PROJECT_NAME}:baseline"  # Tag for the built image
OUTPUT_DIR="${REPO_DIR}/sbom-output"         # All outputs land here

# CycloneDX format version
CDX_FORMAT="cyclonedx-json"

# Colors for terminal output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

log()  { echo -e "${GREEN}[✓]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[✗]${NC} $1"; }

# ---------------------------------------------------------------------------
# Pre-flight checks
# ---------------------------------------------------------------------------
echo "============================================================"
echo "  SBOM Pipeline — ${PROJECT_NAME}"
echo "============================================================"
echo ""

# Check Docker is available
if ! command -v docker &>/dev/null; then
    err "Docker is not installed or not in PATH. Please install Docker first."
    exit 1
fi
log "Docker found: $(docker --version)"

# Check jq is available
if ! command -v jq &>/dev/null; then
    err "jq is not installed. Please install jq (brew install jq / apt install jq)."
    exit 1
fi
log "jq found: $(jq --version)"

# Verify repo directory exists and has a Dockerfile
if [ ! -d "$REPO_DIR" ]; then
    err "Repository directory not found: $REPO_DIR"
    exit 1
fi

if [ ! -f "$REPO_DIR/Dockerfile" ]; then
    warn "No Dockerfile found in $REPO_DIR. Will attempt to scan the directory directly."
    HAS_DOCKERFILE=false
else
    HAS_DOCKERFILE=true
    log "Dockerfile found in $REPO_DIR"
fi

# Create output directory
mkdir -p "$OUTPUT_DIR"
log "Output directory: $OUTPUT_DIR"

# Pull latest Syft and Grype Docker images
echo ""
echo "--- Pulling latest tool images ---"
docker pull anchore/syft:latest
log "Syft image pulled"
docker pull anchore/grype:latest
log "Grype image pulled"

# ---------------------------------------------------------------------------
# Step 1: Build the project Docker image
# ---------------------------------------------------------------------------
echo ""
echo "--- Step 1: Building project Docker image ---"

if [ "$HAS_DOCKERFILE" = true ]; then
    docker build -t "$DOCKER_IMAGE_TAG" "$REPO_DIR" 2>&1 | tail -5
    log "Docker image built: $DOCKER_IMAGE_TAG"
    SCAN_TARGET="$DOCKER_IMAGE_TAG"
else
    warn "Skipping Docker build — will scan repo directory instead."
    SCAN_TARGET="dir:$REPO_DIR"
fi

# ---------------------------------------------------------------------------
# Step 2: Run Syft — Generate CycloneDX SBOM
# ---------------------------------------------------------------------------
echo ""
echo "--- Step 2: Running Syft (SBOM generation) ---"

SYFT_OUTPUT="$OUTPUT_DIR/${PROJECT_NAME}-sbom.cdx.json"

if [ "$HAS_DOCKERFILE" = true ]; then
    # Scan the Docker image
    docker run --rm \
        -v /var/run/docker.sock:/var/run/docker.sock \
        anchore/syft:latest \
        "${SCAN_TARGET}" \
        -o "${CDX_FORMAT}" 2>/dev/null | jq '.' > "$SYFT_OUTPUT"
else
    # Scan the directory
    docker run --rm \
        -v "$(cd "$REPO_DIR" && pwd):/src:ro" \
        anchore/syft:latest \
        "dir:/src" \
        -o "${CDX_FORMAT}" 2>/dev/null | jq '.' > "$SYFT_OUTPUT"
fi

# Count what Syft found
COMPONENT_COUNT=$(jq '.components | length' "$SYFT_OUTPUT")
DEP_COUNT=$(jq '.dependencies | length // 0' "$SYFT_OUTPUT")
log "Syft SBOM generated: $SYFT_OUTPUT"
log "  Components: $COMPONENT_COUNT"
log "  Dependencies: $DEP_COUNT"

# Quick breakdown by type (npm vs deb vs other)
echo ""
echo "  Component breakdown by type:"
jq -r '.components | group_by(.type) | .[] | "    \(.[0].type // "unknown"): \(length)"' "$SYFT_OUTPUT"

# ---------------------------------------------------------------------------
# Step 3: Run Grype — Vulnerability scan
# ---------------------------------------------------------------------------
echo ""
echo "--- Step 3: Running Grype (vulnerability scan) ---"

GRYPE_OUTPUT="$OUTPUT_DIR/${PROJECT_NAME}-grype.cdx.json"

if [ "$HAS_DOCKERFILE" = true ]; then
    docker run --rm \
        -v /var/run/docker.sock:/var/run/docker.sock \
        anchore/grype:latest \
        "${SCAN_TARGET}" \
        -o "${CDX_FORMAT}" 2>/dev/null | jq '.' > "$GRYPE_OUTPUT"
else
    docker run --rm \
        -v "$(cd "$REPO_DIR" && pwd):/src:ro" \
        anchore/grype:latest \
        "dir:/src" \
        -o "${CDX_FORMAT}" 2>/dev/null | jq '.' > "$GRYPE_OUTPUT"
fi

# Count vulnerabilities
VULN_COUNT=$(jq '.vulnerabilities | length // 0' "$GRYPE_OUTPUT")
log "Grype scan complete: $GRYPE_OUTPUT"
log "  Vulnerabilities found: $VULN_COUNT"

# Severity breakdown
echo ""
echo "  Vulnerability breakdown by severity:"
jq -r '
  .vulnerabilities // [] |
  group_by(.ratings[0].severity // "Unknown") |
  .[] |
  "    \(.[0].ratings[0].severity // "Unknown"): \(length)"
' "$GRYPE_OUTPUT"

# ---------------------------------------------------------------------------
# Step 4: Merge Syft SBOM + Grype vulnerabilities
# ---------------------------------------------------------------------------
echo ""
echo "--- Step 4: Merging SBOM + Vulnerabilities ---"

MERGED_OUTPUT="$OUTPUT_DIR/${PROJECT_NAME}-merged.cdx.json"

# Merge: take Syft's SBOM (components + dependencies) and inject Grype's vulnerabilities[]
jq -s '
  # .[0] = Syft SBOM, .[1] = Grype output
  .[0] as $sbom | .[1] as $grype |
  $sbom + {
    "vulnerabilities": ($grype.vulnerabilities // [])
  }
' "$SYFT_OUTPUT" "$GRYPE_OUTPUT" | jq '.' > "$MERGED_OUTPUT"

# Validate the merged file has all three key arrays
MERGED_COMPONENTS=$(jq '.components | length' "$MERGED_OUTPUT")
MERGED_DEPS=$(jq '.dependencies | length // 0' "$MERGED_OUTPUT")
MERGED_VULNS=$(jq '.vulnerabilities | length // 0' "$MERGED_OUTPUT")

log "Merged SBOM generated: $MERGED_OUTPUT"
log "  Components:      $MERGED_COMPONENTS"
log "  Dependencies:    $MERGED_DEPS"
log "  Vulnerabilities: $MERGED_VULNS"

# Validate all three arrays exist
if [ "$MERGED_COMPONENTS" -gt 0 ] && [ "$MERGED_VULNS" -gt 0 ]; then
    log "✅ Merged file contains components[], dependencies[], and vulnerabilities[]"
else
    warn "⚠️  Merged file may be missing data — check manually"
fi

# ---------------------------------------------------------------------------
# Step 5: npm audit and npm dependency tree
# ---------------------------------------------------------------------------
echo ""
echo "--- Step 5: npm audit + dependency tree ---"

NPM_AUDIT_OUTPUT="$OUTPUT_DIR/${PROJECT_NAME}-npm-audit.json"
NPM_TREE_OUTPUT="$OUTPUT_DIR/${PROJECT_NAME}-npm-tree.json"

# Check if package.json exists in the repo
if [ -f "$REPO_DIR/package.json" ]; then
    # Run npm install + audit + ls inside a Node container for consistency
    # Mount the repo as a volume
    REPO_ABS_PATH="$(cd "$REPO_DIR" && pwd)"

    echo "  Running npm install (this may take a minute)..."
    docker run --rm \
        -v "${REPO_ABS_PATH}:/app" \
        -w /app \
        node:lts \
        sh -c "npm install --ignore-scripts 2>/dev/null && npm audit --json 2>/dev/null" \
        | jq '.' > "$NPM_AUDIT_OUTPUT" 2>/dev/null || true

    NPM_AUDIT_VULNS=$(jq '.metadata.vulnerabilities // {} | to_entries | map(.value) | add // 0' "$NPM_AUDIT_OUTPUT" 2>/dev/null || echo "0")
    log "npm audit complete: $NPM_AUDIT_OUTPUT"
    log "  npm audit vulnerabilities: $NPM_AUDIT_VULNS"

    # npm audit severity breakdown
    echo ""
    echo "  npm audit severity breakdown:"
    jq -r '
      .metadata.vulnerabilities // {} |
      to_entries[] |
      select(.value > 0) |
      "    \(.key): \(.value)"
    ' "$NPM_AUDIT_OUTPUT" 2>/dev/null || echo "    (could not parse)"

    echo ""
    echo "  Generating npm dependency tree (this may take a moment)..."
    docker run --rm \
        -v "${REPO_ABS_PATH}:/app" \
        -w /app \
        node:lts \
        sh -c "npm ls --all --json 2>/dev/null" \
        | jq '.' > "$NPM_TREE_OUTPUT" 2>/dev/null || true

    NPM_DIRECT_DEPS=$(jq '.dependencies | length // 0' "$NPM_TREE_OUTPUT" 2>/dev/null || echo "0")
    log "npm dependency tree generated: $NPM_TREE_OUTPUT"
    log "  Direct dependencies: $NPM_DIRECT_DEPS"
else
    warn "No package.json found — skipping npm audit and tree."
    echo '{}' > "$NPM_AUDIT_OUTPUT"
    echo '{}' > "$NPM_TREE_OUTPUT"
fi

# ---------------------------------------------------------------------------
# Step 6: Extract unique CVE list for Python analysis
# ---------------------------------------------------------------------------
echo ""
echo "--- Step 6: Extracting CVE list for NVD analysis ---"

CVE_LIST_OUTPUT="$OUTPUT_DIR/${PROJECT_NAME}-cve-list.json"

# Extract unique CVE IDs from Grype output
jq '[
  .vulnerabilities[]? |
  {
    cve_id: (.id // "unknown"),
    source_url: (.source.url // ""),
    severity: (.ratings[0].severity // "unknown"),
    description: (.description // ""),
    affected_components: [
      .affects[]? | .ref // ""
    ]
  }
] | unique_by(.cve_id)' "$GRYPE_OUTPUT" | jq '.' > "$CVE_LIST_OUTPUT"

UNIQUE_CVES=$(jq 'length' "$CVE_LIST_OUTPUT")
log "Unique CVE list extracted: $CVE_LIST_OUTPUT"
log "  Unique CVEs: $UNIQUE_CVES"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "============================================================"
echo "  Pipeline Complete — Output Files"
echo "============================================================"
echo ""
echo "  📄 Syft SBOM:        $SYFT_OUTPUT"
echo "  📄 Grype Vulns:      $GRYPE_OUTPUT"
echo "  📄 Merged SBOM:      $MERGED_OUTPUT"
echo "  📄 npm audit:        $NPM_AUDIT_OUTPUT"
echo "  📄 npm tree:         $NPM_TREE_OUTPUT"
echo "  📄 CVE list:         $CVE_LIST_OUTPUT"
echo ""
echo "  Next step: Run the Python analysis script"
echo "    python3 analyze-cves.py --output-dir $OUTPUT_DIR --project $PROJECT_NAME"
echo ""