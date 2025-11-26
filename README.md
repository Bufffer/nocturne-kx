# Nocturne-KX

<div align="center">
  <img src="548946a1-d4e7-451b-8294-6ccfa51c8364.png" alt="Nocturne-KX Logo" width="200"/>

  <strong>Modern end-to-end cryptographic communication toolkit</strong>

  <br/>
  <img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License: MIT"/>
  <img src="https://img.shields.io/badge/C%2B%2B-23-blue" alt="C++23"/>
  <img src="https://img.shields.io/badge/libsodium-1.0.18%2B-green" alt="libsodium 1.0.18+"/>
  <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey" alt="Platforms"/>
  <img src="https://img.shields.io/badge/Status-Alpha-yellow" alt="Status: Alpha"/>
</div>

---

## Overview

Nocturne-KX is a security-focused framework for building secure messaging and communication systems. It combines authenticated key exchange, forward secrecy, and a Double Ratchet core with practical operational features including replay protection, rate limiting, audit logging, and HSM-backed key storage.

**Key design goals:**
- Clear security boundaries and conservative defaults
- Strict use of modern cryptographic primitives from libsodium
- Production-oriented operational features (audit, rotation, monitoring)
- Transparent, well-documented behavior

**Current Status:** Alpha/Prototype - suitable for research, demos, and experimentation. **Not production-ready** without comprehensive security audit and additional hardening.

---

## Features

### Core Cryptography
- **X25519 ECDH** for key agreement
- **XChaCha20-Poly1305 AEAD** for authenticated encryption
- **Ed25519** for identity signatures
- **BLAKE2b** for transcript hashing
- **Argon2** for passphrase-based key protection

### Protocol Capabilities
- **Authenticated SIGMA-style handshake** with transcript binding and Ed25519 identity signatures
- **Double Ratchet core** with DH ratchet, send/receive chains, skipped key storage, out-of-order message handling, and state serialization
- **Transport layer** supporting NEGOTIATE/DATA/ACK/NAK/CLOSE frames, sequence numbers, retry queues, and feature negotiation
- **In-memory adapter** included for testing and development

### Operational Security
- **ReplayDB:** Composite keys (receiver/sender/session), encrypted metadata, atomic writes with MAC protection, anti-rollback version counter, TPM counter support
- **Rate Limiter:** Token-bucket algorithm with JSONL persistence, exponential backoff, configurable burst limits
- **Audit Logger:** Hash-chained tamper-evident logging, Ed25519 digital signatures, WORM storage, SIEM integration support (Syslog, CEF, Splunk, ELK, Kafka)
- **Key Rotation Manager:** Time/count/volume-based rotation triggers, dual-control approval workflow, HSM-backed key storage, comprehensive audit trail
- **HSM Integration:** Abstract HSM interface, PKCS#11 wrapper, FileHSM with passphrase-encrypted keys

### Side-Channel Protection
- Constant-time comparisons (`sodium_memcmp`)
- Secure memory zeroing (`sodium_memzero`)
- SecureAllocator with memory locking, guard pages, and scrubbing
- Branchless constant-time helpers
- Optional random delay (configurable/disableable)
- Cache line flushing and memory barriers

---

## Architecture

```
Application
  │
  ├─ Handshake (SIGMA-style, Ed25519 identities, X25519 ephemeral)
  │     └─ Transcript hashing, two-way KDF
  │
  ├─ Double Ratchet (DH ratchet, chains, skipped keys)
  │
  └─ Transport (negotiate, seq/ACK/NAK, retry) ── In-memory adapter
        │
        ├─ ReplayDB (encrypted metadata, rollback protection)
        ├─ RateLimiter (persistent, token-bucket)
        ├─ AuditLogger (hash-chained, signed, WORM)
        ├─ KeyRotationManager (dual-control, HSM-backed)
        └─ HSM Interface (FileHSM, PKCS#11)
```

---

## Quick Start

### Prerequisites
- **C++23 compiler:** GCC 12+, Clang 15+, or MSVC 2022
- **CMake** 3.20+
- **libsodium** 1.0.18+
- **Catch2** 3.x (optional, for tests)

### Installation

#### Ubuntu/Debian
```bash
sudo apt-get update
sudo apt-get install -y libsodium-dev pkg-config cmake build-essential
```

#### macOS
```bash
brew install libsodium pkg-config cmake
```

#### Windows (vcpkg)
```bash
vcpkg install libsodium:x64-windows
```

### Build

```bash
# Clone repository
git clone https://github.com/Bufffer/Nocturne-KX.git
cd Nocturne-KX

# Configure and build
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build . -j

# Run tests (optional)
ctest --output-on-failure
```

**Windows-specific build:**
```bash
cmake .. -DCMAKE_TOOLCHAIN_FILE=[path-to-vcpkg]/scripts/buildsystems/vcpkg.cmake
```

---

## Usage

### Key Management

```bash
# Generate receiver key pair (X25519)
./nocturne-kx gen-receiver keys/

# Generate signer key pair (Ed25519)
./nocturne-kx gen-signer keys/

# Generate signer key with passphrase-encrypted storage (FileHSM)
./nocturne-kx gen-signer keys/ --hsm-pass "your-secure-passphrase"
```

### Protocol Demos

```bash
# Handshake demo
./nocturne-kx hs-demo
# Demonstrates: authenticated handshake, identity signatures,
# transcript hashing, key derivation

# Double Ratchet demo
./nocturne-kx dr-demo
# Demonstrates: DH ratchet, message keys, out-of-order handling,
# state serialization
```

### Encrypt / Decrypt

```bash
# Basic encryption
./nocturne-kx encrypt \
  --rx-pk keys/receiver_x25519_pk.bin \
  --in message.txt \
  --out encrypted.bin

# Decryption with replay protection
./nocturne-kx decrypt \
  --rx-pk keys/receiver_x25519_pk.bin \
  --rx-sk keys/receiver_x25519_sk.bin \
  --replay-db /path/to/replay.db \
  --mac-key /path/to/mac.key \
  --in encrypted.bin \
  --out decrypted.txt
```

### Advanced Features

#### Digital Signatures (FileHSM)
```bash
./nocturne-kx encrypt \
  --rx-pk keys/receiver_x25519_pk.bin \
  --sign-hsm-uri file://keys/sender_ed25519_sk.bin \
  --in message.txt \
  --out encrypted_signed.bin
```

#### Rate Limiting
```bash
./nocturne-kx encrypt \
  --rx-pk keys/receiver_x25519_pk.bin \
  --rate-limit-store /path/to/rate_limits.jsonl \
  --in message.txt \
  --out encrypted.bin
```

#### Audit Logging (Signed and Hash-Chained)
```bash
# Enable audit log with Ed25519 signing and WORM output
./nocturne-kx encrypt \
  --rx-pk keys/receiver_x25519_pk.bin \
  --audit-log logs/audit.jsonl \
  --audit-sign-key keys/audit_ed25519_sk.bin \
  --audit-worm-dir logs/worm \
  --in message.txt \
  --out encrypted.bin

# With external timestamp anchor (RFC 3161 TSA token)
./nocturne-kx encrypt \
  --rx-pk keys/receiver_x25519_pk.bin \
  --audit-log logs/audit.jsonl \
  --audit-sign-key keys/audit_ed25519_sk.bin \
  --audit-anchor anchors/tsa_token.bin \
  --in message.txt \
  --out encrypted.bin
```

#### ReplayDB with TPM Counter
```bash
# Use ReplayDB with external monotonic counter for rollback detection
./nocturne-kx encrypt \
  --rx-pk keys/receiver_x25519_pk.bin \
  --replay-db state/replay.bin \
  --mac-key state/replay.mac \
  --tpm-counter state/tpm_counter.bin \
  --in message.txt \
  --out encrypted.bin
```

### Global CLI Flags
- `--rate-limit-store <path>`: Persist token-bucket state
- `--audit-log <path>`: JSONL audit log path
- `--audit-sign-key <path>`: Ed25519 secret key for signing audit entries
- `--audit-anchor <path>`: External timestamp anchor blob
- `--audit-worm-dir <dir>`: Write-once-read-many directory
- `--tpm-counter <path>`: External monotonic counter (8-byte LE)
- `--hsm-pass <passphrase>`: Passphrase for FileHSM-encrypted keys

---

## Deployment

### Docker

```bash
# Build image
docker build -t nocturne-kx:3.0.0 .

# Run container
docker run --rm -it \
  -v $(pwd)/keys:/keys:ro \
  -v $(pwd)/state:/state \
  nocturne-kx:3.0.0 gen-receiver /keys

# Security scan
trivy image nocturne-kx:3.0.0

# SBOM generation
syft nocturne-kx:3.0.0 -o spdx-json > sbom.json
```

### Docker Compose

```bash
docker-compose up -d
```

### Kubernetes

```bash
# Deploy
kubectl apply -f k8s/deployment.yaml

# Check status
kubectl get pods -l app=nocturne-kx

# View logs
kubectl logs -f deployment/nocturne-kx
```

---

## Documentation

- **Security Guide:** [`docs/SECURITY.md`](docs/SECURITY.md)
  - Cryptographic primitives documentation
  - Threat model analysis
  - Security limitations and best practices
  - Deployment considerations

- **Operations Guide:** [`docs/OPERATIONS.md`](docs/OPERATIONS.md)
  - Installation and configuration
  - Deployment guides (Systemd, Docker, Kubernetes)
  - Monitoring setup (Prometheus, Grafana)
  - Maintenance procedures and troubleshooting
  - Compliance considerations (FIPS, GDPR, ISO 27001)

---

## Status & Roadmap

### Current Status
- **Alpha/Prototype:** Suitable for research, demos, and experimentation
- **Not production-hardened:** Subject to change without formal security review

### Known Limitations
- Real transport adapters (TCP/QUIC) not yet implemented - currently in-memory only
- PKCS#11 HSM integration is stubbed - requires production implementation
- SIEM connectors are framework only - actual implementations needed
- No formal security audit or penetration testing conducted
- No quantum-resistant cryptography (acknowledged design limitation)

### Roadmap
- [ ] Complete transport layer implementations (TCP, QUIC, WebSocket)
- [ ] Production PKCS#11 HSM integration
- [ ] SIEM connector implementations (Splunk HEC, Elasticsearch, Kafka)
- [ ] Comprehensive integration and load testing
- [ ] Performance optimization and benchmarking
- [ ] Metrics and observability (Prometheus, OpenTelemetry)
- [ ] Enhanced operational tooling (health checks, automated rotation)
- [ ] Formal security audit and penetration testing
- [ ] FIPS 140-2/3 certification path
- [ ] Noise protocol integration
- [ ] Post-quantum cryptography exploration

---

## Security Notice

⚠️ **IMPORTANT:** This software is provided as an alpha/prototype. It has **not undergone formal security review or audit**.

**Do NOT deploy in production** without:
- Comprehensive independent security audit
- Penetration testing
- Appropriate compliance processes (SOC 2, ISO 27001, etc.)
- Formal security validation for your specific use case

**For production deployments:**
- Use real HSMs (PKCS#11) - FileHSM is for development only
- Implement proper key management and backup procedures
- Enable comprehensive audit logging and monitoring
- Follow NIST SP 800-57 key management guidelines
- Conduct regular security assessments

**Reporting Security Issues:**
If you discover a security vulnerability, please email: **serdarogluibrahim@gmail.com**

Do not open public GitHub issues for security vulnerabilities.

---

## Testing

### Unit Tests
```bash
# Build with tests
cmake .. -DENABLE_TESTING=ON
cmake --build . -j

# Run tests
ctest --output-on-failure

# Run with verbose output
ctest -V
```

### CI/CD Pipeline
The project includes comprehensive CI/CD workflows:
- **Build jobs:** Release + Debug builds with sanitizers (ASAN, UBSAN, MSAN)
- **Security scans:** CodeQL, Trivy, cppcheck, Scorecard
- **SBOM generation:** syft (SPDX, CycloneDX)
- **Dependency scanning:** Grype
- **Secret scanning:** Gitleaks, TruffleHog

See [`.github/workflows/`](.github/workflows/) for details.

---

## Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Make your changes with clear commit messages
4. Add tests for new functionality
5. Ensure all tests pass and security scans are clean
6. Submit a pull request

**Before contributing:**
- Review [`docs/SECURITY.md`](docs/SECURITY.md)
- Follow C++23 best practices
- Use libsodium for all cryptographic operations
- Add appropriate error handling and input validation
- Include documentation for new features

---

## License

MIT License - see [`LICENSE`](LICENSE) file for details.

---

## Contact

**Email:** serdarogluibrahim@gmail.com

For general questions, feature requests, or bug reports (non-security), please open a GitHub issue.

---

## Acknowledgments

Built with:
- [libsodium](https://libsodium.org/) - Modern cryptographic library
- [Catch2](https://github.com/catchorg/Catch2) - Testing framework
- [CMake](https://cmake.org/) - Build system

Inspired by:
- Signal Protocol's Double Ratchet
- Noise Protocol Framework
- SIGMA key exchange protocols
- NIST cryptographic standards

---

<div align="center">
  <sub>Built with ❤️ for secure communications</sub>
</div>
