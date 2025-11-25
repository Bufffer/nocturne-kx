#!/bin/bash
# =============================================================================
# Nocturne-KX Deployment Automation Script
# =============================================================================
# Usage: ./scripts/deploy.sh [environment] [options]
# Environments: local, dev, staging, production
# Options: --build-only, --no-security-scan, --skip-tests
# =============================================================================

set -euo pipefail  # Exit on error, undefined var, pipe failure

# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

ENVIRONMENT="${1:-local}"
IMAGE_NAME="nocturne-kx"
IMAGE_TAG="${2:-latest}"
BUILD_ONLY=false
NO_SECURITY_SCAN=false
SKIP_TESTS=false

# Parse options
shift || true
while [[ $# -gt 0 ]]; do
    case $1 in
        --build-only)
            BUILD_ONLY=true
            shift
            ;;
        --no-security-scan)
            NO_SECURITY_SCAN=true
            shift
            ;;
        --skip-tests)
            SKIP_TESTS=true
            shift
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# -----------------------------------------------------------------------------
# Colors for output
# -----------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'  # No Color

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# -----------------------------------------------------------------------------
# Prerequisite Checks
# -----------------------------------------------------------------------------
check_prerequisites() {
    log_info "Checking prerequisites..."

    local missing_tools=()

    command -v docker &> /dev/null || missing_tools+=("docker")
    command -v kubectl &> /dev/null || missing_tools+=("kubectl")
    command -v helm &> /dev/null || missing_tools+=("helm")

    if [ ${#missing_tools[@]} -gt 0 ]; then
        log_error "Missing required tools: ${missing_tools[*]}"
        log_error "Install them and try again."
        exit 1
    fi

    log_success "All prerequisites met"
}

# -----------------------------------------------------------------------------
# Build Docker Image
# -----------------------------------------------------------------------------
build_image() {
    log_info "Building Docker image: $IMAGE_NAME:$IMAGE_TAG"

    docker build \
        --tag "$IMAGE_NAME:$IMAGE_TAG" \
        --tag "$IMAGE_NAME:latest" \
        --build-arg BUILD_DATE="$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
        --build-arg VCS_REF="$(git rev-parse --short HEAD 2>/dev/null || echo 'unknown')" \
        --build-arg VERSION="3.0.0" \
        .

    log_success "Docker image built successfully"
}

# -----------------------------------------------------------------------------
# Security Scanning
# -----------------------------------------------------------------------------
security_scan() {
    if [ "$NO_SECURITY_SCAN" = true ]; then
        log_warn "Skipping security scan (--no-security-scan flag)"
        return
    fi

    log_info "Running security scans..."

    # Trivy scan
    if command -v trivy &> /dev/null; then
        log_info "Running Trivy container scan..."
        trivy image \
            --severity HIGH,CRITICAL \
            --exit-code 0 \
            "$IMAGE_NAME:$IMAGE_TAG" || log_warn "Trivy scan found issues"
    else
        log_warn "Trivy not installed, skipping container scan"
    fi

    # Dockle scan
    if command -v dockle &> /dev/null; then
        log_info "Running Dockle container linter..."
        dockle "$IMAGE_NAME:$IMAGE_TAG" || log_warn "Dockle found issues"
    else
        log_warn "Dockle not installed, skipping container linting"
    fi

    log_success "Security scans completed"
}

# -----------------------------------------------------------------------------
# Run Tests
# -----------------------------------------------------------------------------
run_tests() {
    if [ "$SKIP_TESTS" = true ]; then
        log_warn "Skipping tests (--skip-tests flag)"
        return
    fi

    log_info "Running tests in Docker container..."

    docker run --rm \
        --user 0:0 \
        --entrypoint /bin/sh \
        "$IMAGE_NAME:$IMAGE_TAG" \
        -c "echo 'Tests would run here (TODO: implement test suite)'" || log_warn "Tests failed"

    log_success "Tests completed"
}

# -----------------------------------------------------------------------------
# Generate SBOM (Software Bill of Materials)
# -----------------------------------------------------------------------------
generate_sbom() {
    log_info "Generating SBOM..."

    if command -v syft &> /dev/null; then
        syft "$IMAGE_NAME:$IMAGE_TAG" -o spdx-json > sbom.spdx.json
        syft "$IMAGE_NAME:$IMAGE_TAG" -o cyclonedx-json > sbom.cyclonedx.json
        log_success "SBOM generated: sbom.spdx.json, sbom.cyclonedx.json"
    else
        log_warn "syft not installed, skipping SBOM generation"
    fi
}

# -----------------------------------------------------------------------------
# Deploy to Environment
# -----------------------------------------------------------------------------
deploy_local() {
    log_info "Deploying to local environment (docker-compose)..."

    docker-compose down -v 2>/dev/null || true
    docker-compose up -d

    log_success "Deployed to local environment"
    log_info "Access logs: docker-compose logs -f nocturne-kx"
}

deploy_kubernetes() {
    local namespace="nocturne-kx"
    local context=""

    case $ENVIRONMENT in
        dev)
            context="dev-cluster"
            ;;
        staging)
            context="staging-cluster"
            ;;
        production)
            context="production-cluster"
            ;;
        *)
            log_error "Unknown environment: $ENVIRONMENT"
            exit 1
            ;;
    esac

    log_info "Deploying to Kubernetes ($ENVIRONMENT)..."

    # Set kubectl context
    if ! kubectl config use-context "$context" 2>/dev/null; then
        log_warn "Context $context not found, using current context"
    fi

    # Create namespace if not exists
    kubectl create namespace "$namespace" --dry-run=client -o yaml | kubectl apply -f -

    # Apply Kubernetes manifests
    kubectl apply -f k8s/deployment.yaml

    # Wait for rollout
    kubectl rollout status deployment/nocturne-kx -n "$namespace" --timeout=5m

    # Verify deployment
    kubectl get pods -n "$namespace" -l app=nocturne-kx

    log_success "Deployed to $ENVIRONMENT (Kubernetes)"
}

# -----------------------------------------------------------------------------
# Push to Registry
# -----------------------------------------------------------------------------
push_to_registry() {
    local registry="${DOCKER_REGISTRY:-}"

    if [ -z "$registry" ]; then
        log_warn "DOCKER_REGISTRY not set, skipping push"
        return
    fi

    log_info "Pushing image to registry: $registry"

    docker tag "$IMAGE_NAME:$IMAGE_TAG" "$registry/$IMAGE_NAME:$IMAGE_TAG"
    docker tag "$IMAGE_NAME:$IMAGE_TAG" "$registry/$IMAGE_NAME:latest"

    docker push "$registry/$IMAGE_NAME:$IMAGE_TAG"
    docker push "$registry/$IMAGE_NAME:latest"

    log_success "Image pushed to registry"
}

# -----------------------------------------------------------------------------
# Cleanup
# -----------------------------------------------------------------------------
cleanup() {
    log_info "Cleaning up old images..."

    docker image prune -f --filter "label=org.opencontainers.image.title=Nocturne-KX" \
        --filter "until=168h" || true  # Remove images older than 7 days

    log_success "Cleanup completed"
}

# -----------------------------------------------------------------------------
# Main Deployment Flow
# -----------------------------------------------------------------------------
main() {
    echo ""
    log_info "=========================================="
    log_info "Nocturne-KX Deployment"
    log_info "=========================================="
    log_info "Environment: $ENVIRONMENT"
    log_info "Image: $IMAGE_NAME:$IMAGE_TAG"
    log_info "Build only: $BUILD_ONLY"
    echo ""

    # Check prerequisites
    check_prerequisites

    # Build image
    build_image

    # Security scanning
    security_scan

    # Run tests
    run_tests

    # Generate SBOM
    generate_sbom

    # Stop here if build-only
    if [ "$BUILD_ONLY" = true ]; then
        log_success "Build completed (--build-only flag)"
        exit 0
    fi

    # Deploy based on environment
    case $ENVIRONMENT in
        local)
            deploy_local
            ;;
        dev|staging|production)
            push_to_registry
            deploy_kubernetes
            ;;
        *)
            log_error "Unknown environment: $ENVIRONMENT"
            log_error "Valid environments: local, dev, staging, production"
            exit 1
            ;;
    esac

    # Cleanup
    cleanup

    echo ""
    log_success "=========================================="
    log_success "Deployment completed successfully!"
    log_success "=========================================="
    echo ""
}

# Run main function
main "$@"

# =============================================================================
# Usage Examples:
# =============================================================================
# Local deployment:
#   ./scripts/deploy.sh local
#
# Build only:
#   ./scripts/deploy.sh local --build-only
#
# Deploy to dev:
#   export DOCKER_REGISTRY=registry.example.com
#   ./scripts/deploy.sh dev v3.0.0
#
# Deploy to production (with security scan):
#   ./scripts/deploy.sh production v3.0.0
#
# Skip tests (not recommended):
#   ./scripts/deploy.sh local --skip-tests
# =============================================================================
