# Security Policy

## Supported Versions

| Version | Support Status | Security Updates |
|---------|----------------|------------------|
| 4.0.x   | ✅ Active      | Yes              |
| < 4.0   | ❌ Deprecated  | No               |

## Security Features

Nocturne-KX implements multiple layers of security:

### Post-Quantum Cryptography
- **ML-KEM-1024** (NIST FIPS 203) - Quantum-resistant key encapsulation
- **Hybrid KEM** - X25519 + ML-KEM-1024 for defense-in-depth
- Compliant with NIST PQC standardization

### Side-Channel Protection
- Constant-time cryptographic operations
- Random timing delays to prevent timing attacks
- Cache line flushing for sensitive operations
- Memory barriers to prevent speculative execution leaks

### Key Management
- Hardware Security Module (HSM) support via PKCS#11
- Secure key zeroization using `sodium_memzero()`
- Session pooling for high-throughput HSM operations
- Audit logging for compliance

### Protocol Security
- Forward secrecy via Double Ratchet protocol
- Replay attack protection with nonce tracking
- Rate limiting to prevent DoS attacks
- Authenticated encryption with XChaCha20-Poly1305

## Reporting a Vulnerability

**Please DO NOT open public GitHub issues for security vulnerabilities.**

### How to Report

Send vulnerability reports to: **[Your Security Email]**

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact assessment
- Proof-of-concept (if available)

### Response Timeline

- **Initial Response**: Within 48 hours
- **Severity Assessment**: Within 7 days
- **Fix Development**: Based on severity (Critical: 14 days, High: 30 days)
- **Disclosure**: Coordinated disclosure after fix is available

### Severity Classification

- **Critical**: Remote code execution, authentication bypass
- **High**: Cryptographic weaknesses, key compromise
- **Medium**: DoS vulnerabilities, information disclosure
- **Low**: Non-exploitable bugs, documentation issues

## Security Audit Status

### Latest Audit: 2025 (In Progress)

**Scope:**
- ✅ Memory safety analysis (ASan, UBSan, Valgrind)
- ✅ Static analysis (cppcheck, clang-tidy)
- ✅ Cryptographic implementation review
- ✅ Fuzz testing
- ✅ Dependency vulnerability scanning

**Results:** See [AUDIT_REPORT.md](AUDIT_REPORT.md)

## Security Best Practices

### For Users

1. **Keep Dependencies Updated**
   - Use latest libsodium (≥1.0.18)
   - Use latest liboqs (≥0.12.0)

2. **HSM Configuration**
   - Use hardware-backed HSMs in production
   - Enable FIPS mode if required
   - Regularly rotate HSM keys

3. **Deployment**
   - Enable all compiler security flags
   - Run with minimal privileges
   - Use SELinux/AppArmor policies

### For Developers

1. **Code Review**
   - All cryptographic code requires 2+ reviewers
   - Use static analysis tools before commit
   - Run fuzzer on new parsing code

2. **Testing**
   - Maintain >80% test coverage
   - Run sanitizers in CI/CD
   - Test with different HSM vendors

3. **Dependencies**
   - Pin dependency versions
   - Monitor security advisories
   - Audit new dependencies

## Known Limitations

- **Quantum Computing**: Secure against known quantum algorithms (Shor, Grover)
- **Side-Channels**: Protected against timing, cache attacks; physical attacks require additional measures
- **HSM Dependency**: Security level depends on HSM implementation quality

## Cryptographic Algorithms

### Approved Algorithms

| Purpose | Algorithm | Key Size | Status |
|---------|-----------|----------|--------|
| KEM | ML-KEM-1024 | 1024-bit | NIST FIPS 203 |
| KEM | X25519 | 256-bit | RFC 7748 |
| AEAD | XChaCha20-Poly1305 | 256-bit | RFC 8439 |
| Hash | BLAKE2b | 512-bit | RFC 7693 |
| Signature | Ed25519 | 256-bit | RFC 8032 |

### Deprecated Algorithms

- ❌ Pure X25519 (without PQC) - Use Hybrid KEM instead

## Compliance

- **NIST FIPS 203** - ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism)
- **NIST SP 800-90A** - Random number generation (via libsodium)
- **PKCS#11 v2.40** - HSM interface standard

## Security Contacts

- **Security Issues**: [Your Email]
- **General Inquiries**: [General Email]

## Acknowledgments

We appreciate responsible disclosure and will acknowledge security researchers who report valid vulnerabilities.

---

Last Updated: 2025-01-30
