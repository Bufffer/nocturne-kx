# Nocturne-KX — Notes for Claude

C++23 cryptographic communication toolkit. libsodium + optional liboqs (ML-KEM-1024). Author: Halil İbrahim Serdaroğlu. Patent-pending hybrid PQC KEM. Trademark Nocturne-KX™.

## Module map
- `nocturne-kx.cpp` — CLI + inline `rate_limiting`, `audit_log`, `memory_protection::SecureAllocator`, `ReplayDB`, `FileHSM`, `PKCS11HSM`, `encrypt_packet`/`decrypt_packet`
- `src/handshake.hpp` — SIGMA 3-msg, Ed25519 ID + X25519 ephemeral, BLAKE2b transcript, `TrustStore`
- `src/double_ratchet.hpp` — header-only DR (DH ratchet, chains, skipped keys cap=128, deterministic nonce, MAX_GAP=10000)
- `src/transport.hpp` — Frame protocol (NEGOTIATE/DATA/ACK/NAK/CLOSE) + `MemoryTransport` loopback
- `src/hsm/{hsm_interface,pkcs11_hsm,hsm_errors}.hpp` — production HSM hierarchy
- `src/pkcs11_wrapper.{hpp,cpp}` — legacy stub HSM (to be removed in P3)
- `src/security/{audit_logger,key_rotation,siem_connector}.hpp` — hash-chained signed audit, dual-control rotation, SIEM formatters
- `src/pqc/pqc_config.hpp`, `src/pqc/kem/{kem_interface,kem_factory,mlkem_wrapper,hybrid_kem}` — ML-KEM-1024 + X25519 hybrid KEM (NIST SP 800-56Cr2 combiner)
- `src/core/side_channel.{hpp,cpp}` — sodium_memcmp/memzero, 100-500µs random delay, clflush, branchless ct_select

## Build
- Active: `CMakeLists.txt` (v4.0.0, ENABLE_PQC=ON default, BUILD_TESTS=OFF, FetchContent liboqs 0.12.0 fallback)
- Hardened (Dockerfile): `CMakeLists_new.txt` (FIPS, RELRO, CET, LTO, layered targets)
- Tests: `-DBUILD_TESTS=ON`, gated on Catch2 v3
- 4 GH workflows: cmake.yml (sanitizers + fuzz + cppcheck), comprehensive-test, security-{audit,scan}

## Conventions
- All cryptographic ops via libsodium (or liboqs for PQC). Never hand-roll.
- Sensitive memory: `nocturne::side_channel::secure_zero_memory` + `flush_cache_line` + `memory_barrier`.
- Constant-time comparison: `nocturne::side_channel::constant_time_compare`.
- File-encrypted Ed25519 SK: `NCHSM2` magic header + Argon2id-derived AEAD; passphrase via `NOCTURNE_HSM_PASSPHRASE` env var.
- Audit log: JSONL, BLAKE2b-256 hash chain in `<logfile>.chain`, optional Ed25519 sig per record, optional WORM directory.
- ReplayDB on-disk format: `[8B version|MSB=encryption-flag][24B nonce][4B ct_len][AEAD ct]`. AAD = plaintext version.

## Active roadmap
See `~/.claude/projects/.../memory/roadmap.md` for the full P1/P2/P3 plan. Currently working P1.

## Quick commands
```bash
# Configure + build
cmake -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTS=ON
cmake --build build -j

# Run unit tests
cd build && ctest --output-on-failure

# CLI smoke
./build/nocturne-kx self-test
./build/nocturne-kx hs-demo
./build/nocturne-kx dr-demo
```

## Gotchas
- Two `HSMInterface` definitions exist (inline in `nocturne-kx.cpp` and `nocturne::hsm::HSMInterface` in `src/hsm/`). Don't conflate.
- Two `PKCS11HSM` classes too. CLI uses the inline one — wiring to production class is P1#4.
- `tests/pqc/CMakeLists.txt` has hardcoded Windows paths from a different developer's machine.
- `CMakeLists_new.txt` ≠ `CMakeLists.txt` — Dockerfile copies the former over the latter at build time.
