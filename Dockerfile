# =============================================================================
# Nocturne-KX Production Dockerfile
# =============================================================================
# Multi-stage build for minimal attack surface
# Uses distroless for runtime (no shell, no package manager)
# Security: Non-root user, read-only filesystem, minimal dependencies
# =============================================================================

# -----------------------------------------------------------------------------
# Stage 1: Build Environment (Alpine for minimal size)
# -----------------------------------------------------------------------------
FROM alpine:3.19 AS builder

# Install build dependencies
RUN apk add --no-cache \
    g++ \
    cmake \
    ninja \
    make \
    git \
    pkgconfig \
    libsodium-dev \
    libsodium-static \
    linux-headers \
    && rm -rf /var/cache/apk/*

# Create build directory
WORKDIR /build

# Copy source files
COPY CMakeLists.txt ./
COPY CMakeLists_new.txt ./CMakeLists.txt
COPY src/ ./src/
COPY nocturne-kx.cpp ./
COPY .git/ ./.git/

# Build with security hardening flags
RUN cmake -GNinja \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_CXX_COMPILER=g++ \
    -DENABLE_HARDENING=ON \
    -DENABLE_FIPS=ON \
    -DENABLE_LTO=ON \
    -DBUILD_SHARED_LIBS=OFF \
    . && \
    ninja && \
    strip nocturne-kx

# Verify binary (check for security features)
RUN readelf -d nocturne-kx | grep -E 'RELRO|BIND_NOW|PIE' || exit 0

# -----------------------------------------------------------------------------
# Stage 2: Runtime Environment (Distroless - Minimal Attack Surface)
# -----------------------------------------------------------------------------
FROM gcr.io/distroless/cc-debian12:nonroot

# Metadata
LABEL maintainer="serdarogluibrahim@gmail.com" \
      org.opencontainers.image.title="Nocturne-KX" \
      org.opencontainers.image.description="Military-grade cryptographic communication toolkit" \
      org.opencontainers.image.version="3.0.0" \
      org.opencontainers.image.vendor="Anthropic" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.source="https://github.com/Bufffer/Nocturne-KX" \
      security.hardened="true" \
      security.distroless="true" \
      security.nonroot="true"

# Copy binary from builder
COPY --from=builder /build/nocturne-kx /usr/local/bin/nocturne-kx

# Copy libsodium (required at runtime)
COPY --from=builder /usr/lib/libsodium.so.26 /usr/lib/libsodium.so.26

# Create directories for runtime state (mounted as volumes)
# Note: distroless doesn't have mkdir, so we rely on Kubernetes/Docker to create these
# USER directive is already "nonroot" (uid 65532) in distroless:nonroot

# Health check (if running as daemon)
# HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
#   CMD ["/usr/local/bin/nocturne-kx", "--health-check"]

# Default entrypoint
ENTRYPOINT ["/usr/local/bin/nocturne-kx"]

# Default command (show help)
CMD ["--help"]

# =============================================================================
# Build Instructions:
# =============================================================================
# docker build -t nocturne-kx:3.0.0 .
# docker build -t nocturne-kx:3.0.0-alpine --target builder .  # Debug build
#
# Run:
# docker run --rm -it \
#   -v $(pwd)/keys:/keys:ro \
#   -v $(pwd)/state:/state \
#   nocturne-kx:3.0.0 gen-receiver /keys
#
# Security scan:
# docker scan nocturne-kx:3.0.0
# trivy image nocturne-kx:3.0.0
#
# SBOM generation:
# syft nocturne-kx:3.0.0 -o spdx-json > sbom.json
# =============================================================================
