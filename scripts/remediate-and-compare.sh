#!/usr/bin/env bash
# =============================================================================
# SBOM Remediation & Comparison Pipeline — HCDP API
# 
# Workflow:
#   1. Patch npm dependencies on a test branch
#   2. Rebuild with latest node:22-slim
#   3. Build alpine variant (node:22-alpine)
#   4. Re-scan each with Syft + Grype
#   5. Compare before/after
#
# Run from: capstone-sbom root directory
# =============================================================================

set -euo pipefail

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m'

log()  { echo -e "${GREEN}[✓]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[✗]${NC} $1"; }
info() { echo -e "${CYAN}[i]${NC} $1"; }

PROJECT_ROOT="$(pwd)"
REPO_DIR="${PROJECT_ROOT}/repos/hcdp-api"
RUNS_DIR="${PROJECT_ROOT}/runs/2026-02-09/hcdp-api"
BASELINE_DIR="${RUNS_DIR}"

echo "============================================================"
echo "  SBOM Remediation Pipeline — HCDP-API"
echo "============================================================"
echo ""

# ---------------------------------------------------------------------------
# Phase 1: Patch npm dependencies
# ---------------------------------------------------------------------------
echo "=== Phase 1: Patching npm dependencies ==="
echo ""

cd "$REPO_DIR"

# Create a remediation branch
info "Creating remediation branch..."
git checkout -b capstone-remediation 2>/dev/null || git checkout capstone-remediation 2>/dev/null || true

# Show current vulnerable npm packages
echo ""
info "Current vulnerable npm packages:"
echo "  nodemailer: $(node -e "console.log(require('./package.json').dependencies?.nodemailer || 'not found')" 2>/dev/null || echo 'check manually')"
echo ""

# Upgrade nodemailer (the only DIRECT npm dependency with CVEs)
info "Upgrading nodemailer to latest..."
npm install nodemailer@latest --save 2>&1 | tail -3
echo ""

# Run npm audit fix for transitive dependencies
info "Running npm audit fix..."
npm audit fix 2>&1 | tail -10 || true
echo ""

# Show what changed
info "Updated versions:"
echo "  nodemailer: $(node -e "console.log(require('./package.json').dependencies?.nodemailer || 'not found')" 2>/dev/null || echo 'check manually')"
echo ""

# Run npm audit to see remaining issues
info "Post-patch npm audit:"
npm audit 2>/dev/null || true
echo ""

cd "$PROJECT_ROOT"

# ---------------------------------------------------------------------------
# Phase 2: Create Dockerfile variants
# ---------------------------------------------------------------------------
echo ""
echo "=== Phase 2: Creating Dockerfile variants ==="
echo ""

# Create Alpine variant Dockerfile
ALPINE_DOCKERFILE="${REPO_DIR}/Dockerfile.alpine"
info "Creating Alpine variant Dockerfile..."

# Read the original Dockerfile and create an Alpine version
if [ -f "$REPO_DIR/Dockerfile" ]; then
    # Create Alpine variant by replacing base image and adjusting apt -> apk
    sed \
        -e 's|FROM node:22-slim|FROM node:22-alpine|' \
        -e 's|apt-get update|apk update|g' \
        -e 's|apt-get install -y|apk add --no-cache|g' \
        -e 's|uuid-runtime|util-linux|g' \
        "$REPO_DIR/Dockerfile" > "$ALPINE_DOCKERFILE"
    log "Alpine Dockerfile created: $ALPINE_DOCKERFILE"
else
    err "No Dockerfile found in $REPO_DIR"
    exit 1
fi

# ---------------------------------------------------------------------------
# Phase 3: Pull latest base images and build all variants
# ---------------------------------------------------------------------------
echo ""
echo "=== Phase 3: Building Docker image variants ==="
echo ""

# Pull fresh base images
info "Pulling latest base images..."
docker pull node:22-slim
docker pull node:22-alpine
echo ""

# Build Variant 1: Patched npm + latest node:22-slim
info "Building: hcdp-api:patched-slim (patched npm + latest node:22-slim)..."
docker build -t hcdp-api:patched-slim "$REPO_DIR" 2>&1 | tail -3
log "Built hcdp-api:patched-slim"
echo ""

# Build Variant 2: Patched npm + node:22-alpine
info "Building: hcdp-api:patched-alpine (patched npm + node:22-alpine)..."
docker build -t hcdp-api:patched-alpine -f "$ALPINE_DOCKERFILE" "$REPO_DIR" 2>&1 | tail -3
log "Built hcdp-api:patched-alpine"
echo ""

# ---------------------------------------------------------------------------
# Phase 4: Scan all variants
# ---------------------------------------------------------------------------
echo ""
echo "=== Phase 4: Scanning all variants ==="
echo ""

# Function to scan a variant
scan_variant() {
    local IMAGE_TAG="$1"
    local VARIANT_NAME="$2"
    local OUTPUT_DIR="${RUNS_DIR}/${VARIANT_NAME}"

    info "Scanning ${IMAGE_TAG} → ${VARIANT_NAME}..."
    mkdir -p "$OUTPUT_DIR"/{sbom,grype,merged,npm}

    # Syft
    docker run --rm \
        -v /var/run/docker.sock:/var/run/docker.sock \
        anchore/syft:latest \
        "${IMAGE_TAG}" \
        -o cyclonedx-json 2>/dev/null | jq '.' > "$OUTPUT_DIR/sbom/${VARIANT_NAME}-sbom.cdx.json"

    local COMP_COUNT=$(jq '.components | length' "$OUTPUT_DIR/sbom/${VARIANT_NAME}-sbom.cdx.json")
    log "  Syft: ${COMP_COUNT} components"

    # Grype
    docker run --rm \
        -v /var/run/docker.sock:/var/run/docker.sock \
        anchore/grype:latest \
        "${IMAGE_TAG}" \
        -o cyclonedx-json 2>/dev/null | jq '.' > "$OUTPUT_DIR/grype/${VARIANT_NAME}-grype.cdx.json"

    local VULN_COUNT=$(jq '.vulnerabilities | length' "$OUTPUT_DIR/grype/${VARIANT_NAME}-grype.cdx.json")
    log "  Grype: ${VULN_COUNT} vulnerabilities"

    # Merge
    jq -s '.[0] + { "vulnerabilities": (.[1].vulnerabilities // []) }' \
        "$OUTPUT_DIR/sbom/${VARIANT_NAME}-sbom.cdx.json" \
        "$OUTPUT_DIR/grype/${VARIANT_NAME}-grype.cdx.json" \
        | jq '.' > "$OUTPUT_DIR/merged/${VARIANT_NAME}-merged.cdx.json"

    local MERGED_VULNS=$(jq '.vulnerabilities | length' "$OUTPUT_DIR/merged/${VARIANT_NAME}-merged.cdx.json")
    log "  Merged: ${MERGED_VULNS} vulnerabilities"

    echo ""
}

# Scan both variants
scan_variant "hcdp-api:patched-slim" "patched-slim"
scan_variant "hcdp-api:patched-alpine" "patched-alpine"

# ---------------------------------------------------------------------------
# Phase 5: Quick comparison
# ---------------------------------------------------------------------------
echo ""
echo "=== Phase 5: Before / After Comparison ==="
echo ""

echo "┌──────────────────────┬──────────┬──────────┬──────────┐"
echo "│ Metric               │ Baseline │ Patched  │ Alpine   │"
echo "│                      │ (slim)   │ (slim)   │          │"
echo "├──────────────────────┼──────────┼──────────┼──────────┤"

# Component counts
BASE_COMP=$(jq '.components | length' "$BASELINE_DIR/sbom/hcdp-api-sbom.cdx.json")
SLIM_COMP=$(jq '.components | length' "$RUNS_DIR/patched-slim/sbom/patched-slim-sbom.cdx.json")
ALP_COMP=$(jq '.components | length' "$RUNS_DIR/patched-alpine/sbom/patched-alpine-sbom.cdx.json")
printf "│ %-20s │ %8s │ %8s │ %8s │\n" "Components" "$BASE_COMP" "$SLIM_COMP" "$ALP_COMP"

# Dependency counts
BASE_DEP=$(jq '.dependencies | length' "$BASELINE_DIR/sbom/hcdp-api-sbom.cdx.json")
SLIM_DEP=$(jq '.dependencies | length' "$RUNS_DIR/patched-slim/sbom/patched-slim-sbom.cdx.json")
ALP_DEP=$(jq '.dependencies | length' "$RUNS_DIR/patched-alpine/sbom/patched-alpine-sbom.cdx.json")
printf "│ %-20s │ %8s │ %8s │ %8s │\n" "Dependencies" "$BASE_DEP" "$SLIM_DEP" "$ALP_DEP"

# Total vulnerability counts
BASE_VULN=$(jq '.vulnerabilities | length' "$BASELINE_DIR/grype/hcdp-api-grype.cdx.json")
SLIM_VULN=$(jq '.vulnerabilities | length' "$RUNS_DIR/patched-slim/grype/patched-slim-grype.cdx.json")
ALP_VULN=$(jq '.vulnerabilities | length' "$RUNS_DIR/patched-alpine/grype/patched-alpine-grype.cdx.json")
printf "│ %-20s │ %8s │ %8s │ %8s │\n" "Total Vulns" "$BASE_VULN" "$SLIM_VULN" "$ALP_VULN"

# Unique CVE counts
BASE_UCVE=$(jq '[.vulnerabilities[].id] | unique | length' "$BASELINE_DIR/grype/hcdp-api-grype.cdx.json")
SLIM_UCVE=$(jq '[.vulnerabilities[].id] | unique | length' "$RUNS_DIR/patched-slim/grype/patched-slim-grype.cdx.json")
ALP_UCVE=$(jq '[.vulnerabilities[].id] | unique | length' "$RUNS_DIR/patched-alpine/grype/patched-alpine-grype.cdx.json")
printf "│ %-20s │ %8s │ %8s │ %8s │\n" "Unique CVEs" "$BASE_UCVE" "$SLIM_UCVE" "$ALP_UCVE"

echo "├──────────────────────┼──────────┼──────────┼──────────┤"

# Severity breakdown
for SEV in critical high medium low none; do
    BASE_SEV=$(jq --arg s "$SEV" '[.vulnerabilities[] | select(.ratings[0].severity == $s)] | length' "$BASELINE_DIR/grype/hcdp-api-grype.cdx.json")
    SLIM_SEV=$(jq --arg s "$SEV" '[.vulnerabilities[] | select(.ratings[0].severity == $s)] | length' "$RUNS_DIR/patched-slim/grype/patched-slim-grype.cdx.json")
    ALP_SEV=$(jq --arg s "$SEV" '[.vulnerabilities[] | select(.ratings[0].severity == $s)] | length' "$RUNS_DIR/patched-alpine/grype/patched-alpine-grype.cdx.json")
    printf "│ %-20s │ %8s │ %8s │ %8s │\n" "  $SEV" "$BASE_SEV" "$SLIM_SEV" "$ALP_SEV"
done

echo "└──────────────────────┴──────────┴──────────┴──────────┘"
echo ""

# Calculate reductions
SLIM_REDUCTION=$((BASE_UCVE - SLIM_UCVE))
ALP_REDUCTION=$((BASE_UCVE - ALP_UCVE))
echo "  CVE Reduction (patched-slim): -${SLIM_REDUCTION} ($(( SLIM_REDUCTION * 100 / BASE_UCVE ))%)"
echo "  CVE Reduction (alpine):       -${ALP_REDUCTION} ($(( ALP_REDUCTION * 100 / BASE_UCVE ))%)"

# ---------------------------------------------------------------------------
# Phase 6: Find newly introduced CVEs (if any)
# ---------------------------------------------------------------------------
echo ""
echo "=== New CVEs introduced by upgrades ==="
echo ""

# CVEs in patched-slim that weren't in baseline
info "New CVEs in patched-slim (not in baseline):"
diff <(jq -r '[.vulnerabilities[].id] | unique | .[]' "$BASELINE_DIR/grype/hcdp-api-grype.cdx.json" | sort) \
     <(jq -r '[.vulnerabilities[].id] | unique | .[]' "$RUNS_DIR/patched-slim/grype/patched-slim-grype.cdx.json" | sort) \
     | grep '^>' | sed 's/^> /  /' || echo "  None — no new CVEs introduced!"

echo ""
info "New CVEs in alpine (not in baseline):"
diff <(jq -r '[.vulnerabilities[].id] | unique | .[]' "$BASELINE_DIR/grype/hcdp-api-grype.cdx.json" | sort) \
     <(jq -r '[.vulnerabilities[].id] | unique | .[]' "$RUNS_DIR/patched-alpine/grype/patched-alpine-grype.cdx.json" | sort) \
     | grep '^>' | sed 's/^> /  /' || echo "  None — no new CVEs introduced!"

echo ""
info "CVEs REMOVED by patched-slim:"
diff <(jq -r '[.vulnerabilities[].id] | unique | .[]' "$BASELINE_DIR/grype/hcdp-api-grype.cdx.json" | sort) \
     <(jq -r '[.vulnerabilities[].id] | unique | .[]' "$RUNS_DIR/patched-slim/grype/patched-slim-grype.cdx.json" | sort) \
     | grep '^<' | head -20 | sed 's/^< /  /' || echo "  None"
SLIM_REMOVED=$(diff <(jq -r '[.vulnerabilities[].id] | unique | .[]' "$BASELINE_DIR/grype/hcdp-api-grype.cdx.json" | sort) \
     <(jq -r '[.vulnerabilities[].id] | unique | .[]' "$RUNS_DIR/patched-slim/grype/patched-slim-grype.cdx.json" | sort) \
     | grep -c '^<' || true)
echo "  (${SLIM_REMOVED} total removed)"

echo ""
info "CVEs REMOVED by alpine:"
diff <(jq -r '[.vulnerabilities[].id] | unique | .[]' "$BASELINE_DIR/grype/hcdp-api-grype.cdx.json" | sort) \
     <(jq -r '[.vulnerabilities[].id] | unique | .[]' "$RUNS_DIR/patched-alpine/grype/patched-alpine-grype.cdx.json" | sort) \
     | grep '^<' | head -20 | sed 's/^< /  /' || echo "  None"
ALP_REMOVED=$(diff <(jq -r '[.vulnerabilities[].id] | unique | .[]' "$BASELINE_DIR/grype/hcdp-api-grype.cdx.json" | sort) \
     <(jq -r '[.vulnerabilities[].id] | unique | .[]' "$RUNS_DIR/patched-alpine/grype/patched-alpine-grype.cdx.json" | sort) \
     | grep -c '^<' || true)
echo "  (${ALP_REMOVED} total removed)"

echo ""
echo "============================================================"
echo "  Remediation pipeline complete!"
echo "  Results in: $RUNS_DIR/"
echo "============================================================"
echo ""
echo "  Next step: Run the comparison report generator:"
echo "    python3 scripts/compare-variants.py --run-dir runs/2026-02-09 --project hcdp-api"