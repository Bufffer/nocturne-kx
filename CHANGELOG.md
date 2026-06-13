# Changelog

All notable changes to Nocturne-KX are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning: [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Error code integer values (src/core/error.hpp) are a SIEM-stable contract and are never renumbered within a major version.

---

## [1.0.0-alpha] - 2026-06-13

First tagged release. The codebase is feature-complete for the hybrid PQC use case. **No independent security audit has been conducted.** This release is suitable for research, evaluation, and prototyping. Do not deploy in production without a formal security review.

### Added

**Post-quantum cryptography**
- ML-KEM-1024 KEM wrapper over liboqs (NIST FIPS 203). Three modes: `x25519`, `hybrid` (X25519 + ML-KEM-1024), `mlkem1024`.
- ML-DSA-87 signature wrapper over liboqs (NIST FIPS 204). Three modes: `ed25519`, `hybrid` (Ed25519 + ML-DSA-87), `mldsa`.
- Hybrid KEM combiner following NIST SP 800-56C R2 HKDF-SHA-256. `NOCTURNE_PROTOCOL_VERSION=4` is the domain separator; bumping the combiner increments this constant without touching the wire format version.
- `KEMInterface` / `KEMFactory` / `SignatureScheme` / `SignatureFactory` — polymorphic PQC interfaces. All methods `[[nodiscard]]`, all return `Result<T>`.
- `FLAG_HAS_PQC_KEM` (0x04) and `FLAG_HAS_PQC_SIG` (0x08) wire flags. Receiver auto-detects mode from the flags byte.

**Replay protection**
- `ReplayDB`: per-session monotonic counter database. On-disk format: `[8B version|MSB=encryption-flag][24B nonce][4B ct_len][AEAD ct]`. AAD = plaintext version prevents downgrade. Writes go to `.tmp` then `rename(2)` for atomicity.
- Bidirectional counter separation: sender→receiver and receiver→sender counters are independent key-spaces inside the same DB file. An attacker cannot exhaust one side by replaying the other.
- Optional TPM-backed monotonic counter binding for rollback-resistant deployments.

**HSM integration**
- `nocturne::hsm::HSMInterface` — enterprise HSM abstract interface with `generate_key`, `rotate_key`, `delete_key`, `get_audit_trail`, key policy, FIPS reporting.
- `nocturne::hsm::PKCS11HSM` — full OASIS PKCS#11 v2.40 implementation. `CK_FUNCTION_LIST` has the correct `CK_VERSION` prefix + 68 function pointer slots in spec order (P7.1). Validated in CI against SoftHSM2.
- `nocturne::hsm::FileHSM` — dev HSM storing Ed25519 keys in `NCHSM2`-encrypted files (Argon2id-derived XChaCha20-Poly1305, passphrase via `NOCTURNE_HSM_PASSPHRASE`).
- Inline CLI adapter (`PKCS11HSM` in `nocturne-kx.cpp`) forwards to the production `nocturne::hsm::PKCS11HSM` via `PKCS11_LIB` + `NOCTURNE_HSM_PIN` env vars.

**Protocol and transport**
- v3 wire format with v4 KDF combiner. Packet: version byte, flags byte, KEM ciphertext, AEAD ciphertext, optional PQ signature. All length fields little-endian u32.
- `encrypt_packet` / `decrypt_packet` and their `*_kem` siblings in `src/protocol/messaging.hpp`. Single point of policy; every step returns `Result<T>`.
- SIGMA 3-message handshake with Ed25519 identity and X25519 ephemeral, BLAKE2b transcript binding. `TrustStore` for peer pinning.
- Signal-style Double Ratchet: DH ratchet, send/receive chains, skipped-key cache capped at 128, `MAX_GAP=10000`, deterministic nonce.
- Frame transport: `NEGOTIATE/DATA/ACK/NAK/CLOSE`, sequence numbers, retry queue, `MemoryTransport` loopback.
- TLS 1.3 transport (`TlsAcceptor` + `TcpTlsTransport`): OpenSSL, mTLS, SNI, 4-byte BE length prefix. CLI subcommands `tls-send` / `tls-recv`.

**Audit and observability**
- `AuditLogger`: JSONL records chained by BLAKE2b-256. Optional per-record Ed25519 signature. Optional WORM directory mirror.
- `audit-verify` CLI subcommand: walks the entire log, recomputes every hash, verifies signatures, reports chain-break sequence number.
- `SIEMConnector`: wired sinks for SYSLOG_UDP (RFC 5424), SYSLOG_TCP (RFC 6587), SYSLOG_TLS (RFC 5425, TLS 1.3), CEF, LEEF. HTTP sinks (Splunk HEC, Elasticsearch, Kafka) are stubbed pending libcurl / librdkafka dependency decision.
- `KeyRotationManager`: dual-control rotation with `generate_initial_key` / `rotate`; drives `HSMInterface::generate_key`.

**Side-channel mitigations**
- `sodium_memcmp` for all secret comparisons, `sodium_memzero` on key material.
- Branchless `ct_select`, random 100–500 µs delay on authentication failure, `clflush` + memory barrier.
- `SecureAllocator` with `sodium_mlock` and guard pages.

**Error handling**
- `Result<T>` = `std::expected<T, Error>` throughout the entire call stack. Exceptions reserved for system faults (sodium_init failure, bad_alloc).
- 14 typed `ErrorCode` values with stable integers (SIEM contract). See `src/core/error.hpp`.

**Documentation**
- VitePress 1.5 documentation site deployed to GitHub Pages: guide, architecture, wire format, CLI reference, PQC reference, operations guide, security reference.
- Doxygen API reference auto-generated from `src/` on every push, served at `/doxygen/`.
- Lighthouse CI post-deploy: performance, accessibility, best-practices, SEO audits.

**CI**
- Four workflows: `cmake.yml` (sanitizers ASAN/UBSAN/MSAN + libFuzzer + cppcheck), `comprehensive-test.yml` (16 integration tests including hybrid PQC over localhost TLS), `security-audit.yml` (CodeQL, Trivy, Gitleaks), `docs.yml` (VitePress + Doxygen + Lighthouse).
- SoftHSM PKCS#11 integration: must-pass step generates a key in SoftHSM2, signs with it, verifies against the returned public key.

### Fixed

- Hybrid KDF version mismatch (`9b5c00b`): `HybridKEM::combine_secrets` bound the shared secret to `NOCTURNE_PROTOCOL_VERSION=4`, but `decrypt_packet_kem` was using the outer packet version (3). Sender and receiver derived different combined secrets; AEAD authentication failed silently. Fixed by importing `pqc_config.hpp` and using the constant on both sides. Caught by a live end-to-end demo, not CI.
- PKCS#11 struct misalignment (`c8f9767`): hand-rolled `CK_FUNCTION_LIST` was missing the `CK_VERSION` prefix and 51 of 68 function slots, causing a SIGSEGV inside SoftHSM2's dispatcher on first call.
- CLI prescan bug (`1811676`): `--audit-worm-dir` was silently routed into the `--audit-anchor` slot.

### Security

All cryptographic operations use libsodium or liboqs. No hand-rolled cipher, hash, or constant-time comparison exists in `src/`. If a code review surfaces one, open an issue immediately.

---

## [Pre-release history]

Development history prior to v1.0.0-alpha is preserved in git log. Key milestones: P1 (PKCS#11 fix, DR impl), P2 (TLS, SIEM, audit verify, PQC KEM CLI), P3 (cleanup), P4 (PQ signatures), P5 (modularization), P6 (code quality, Result<T>), P7 (HSM CI, NOTICE, docs).
