# Nocturne-KX

[![CI](https://github.com/Bufffer/nocturne-kx/actions/workflows/cmake.yml/badge.svg)](https://github.com/Bufffer/nocturne-kx/actions/workflows/cmake.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![C++23](https://img.shields.io/badge/C%2B%2B-23-blue)](#build)

Nocturne-KX is a C++23 cryptographic communication toolkit built around a hybrid post-quantum KEM. It combines classical X25519 ECDH with ML-KEM-1024 (CRYSTALS-Kyber, NIST FIPS 203) and Ed25519 signatures with ML-DSA-87 (CRYSTALS-Dilithium, NIST FIPS 204) through SP 800-56C R2 combiners, so an attacker has to break both the classical and post-quantum layers to recover plaintext. All cryptographic operations go through libsodium or liboqs — no hand-rolled primitives anywhere in the codebase.

The library ships as a single static binary with no runtime dependencies beyond libsodium.


## What it provides

**Hybrid PQC key exchange.** Three KEM modes: classical X25519, hybrid X25519 + ML-KEM-1024, and pure ML-KEM-1024. The receiver auto-detects the mode from the packet header; no out-of-band negotiation needed.

**Bidirectional replay protection.** Per-session monotonic counters stored in an on-disk encrypted database. The counter file is AEAD-authenticated and written atomically via `rename(2)`, so a crash mid-write doesn't silently roll back replay state. A second decrypt of the same packet returns `ReplayDetected` and exits 2.

**Hash-chained audit log.** Every encrypt and decrypt writes a JSONL record whose BLAKE2b-256 hash is chained to the previous entry. Records can be Ed25519-signed per-entry. `audit-verify` checks the entire chain in a single pass.

**SIGMA-style handshake and Double Ratchet.** For long-lived sessions, the optional handshake layer runs a 3-message SIGMA exchange (Ed25519 identity, X25519 ephemeral, BLAKE2b transcript) and hands off to a Signal-style double ratchet with DH ratchet, send/receive chains, and skipped-key cache capped at 128 entries.

**PKCS#11 HSM integration.** A full OASIS PKCS#11 v2.40 adapter validated in CI against SoftHSM2. The CLI also ships a `FileHSM` for development: Ed25519 keys encrypted at rest with Argon2id-derived XChaCha20-Poly1305, passphrase via `NOCTURNE_HSM_PASSPHRASE` env var.

**TLS 1.3 transport.** Optional OpenSSL transport layer with mTLS support and 4-byte big-endian length-prefixed framing. Mirrors the in-memory `MemoryTransport` used in tests.

**Side-channel mitigations.** `sodium_memcmp` for all secret comparisons, `sodium_memzero` on key material, branchless `ct_select`, random 100–500 µs delay on authentication failure, and explicit cache-line flushes.


## Build

**Dependencies**

| Tool | Version | Notes |
|---|---|---|
| CMake | >= 3.20 | |
| GCC or Clang | C++23 | `std::expected`, `std::span` |
| libsodium | >= 1.0.18 | |
| liboqs | 0.12.0 | Auto-fetched via FetchContent if not installed |
| OpenSSL | >= 3.0 | Optional, required for `ENABLE_TLS_TRANSPORT=ON` |
| Catch2 | v3 | Optional, required for `BUILD_TESTS=ON` |

```bash
# Debian / Ubuntu
sudo apt-get install -y build-essential cmake git pkg-config \
  libsodium-dev libssl-dev ninja-build

# macOS
brew install cmake libsodium openssl@3
```

```bash
git clone https://github.com/Bufffer/nocturne-kx.git
cd nocturne-kx

cmake -B build \
  -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_TESTS=ON \
  -DENABLE_PQC=ON \
  -DENABLE_TLS_TRANSPORT=ON

cmake --build build -j
```

The binary lands at `build/nocturne-kx`. Run `./build/nocturne-kx self-test` before doing anything else — it checks that libsodium and liboqs both initialise correctly.


## CLI quickstart

**Generate keys**

```bash
# Hybrid PQC receiver keypair (X25519 + ML-KEM-1024)
./build/nocturne-kx gen-receiver ./keys --kem hybrid
# -> receiver_hybrid_pk.bin (1600 B public), receiver_hybrid_sk.bin (3200 B secret)

# Hybrid PQC signer keypair (Ed25519 + ML-DSA-87)
./build/nocturne-kx gen-signer ./keys --sig-type hybrid
# -> sender_hybrid_sig_pk.bin (2624 B), sender_hybrid_sig_sk.bin (4960 B)
```

**Encrypt**

```bash
echo "meet at midnight" | ./build/nocturne-kx encrypt \
  --rx-pk   ./keys/receiver_hybrid_pk.bin \
  --kem     hybrid \
  --pqc-sign-key  ./keys/sender_hybrid_sig_sk.bin \
  --pqc-sig-type  hybrid \
  --aad     "session-7f3a" \
  --replay-db ./replay.db \
  --in /dev/stdin --out msg.pkt
# ok: 4859 bytes written
```

The packet carries a 78-byte header, 1600 B KEM ciphertext, the AEAD-encrypted payload, and a 4691 B hybrid signature. Every field is length-prefixed and little-endian.

**Decrypt**

```bash
./build/nocturne-kx decrypt \
  --rx-pk ./keys/receiver_hybrid_pk.bin \
  --rx-sk ./keys/receiver_hybrid_sk.bin \
  --expect-pqc-signer ./keys/sender_hybrid_sig_pk.bin \
  --pqc-sig-type hybrid \
  --replay-db ./replay.db \
  --in msg.pkt --out plaintext

cat plaintext
# meet at midnight
```

**Replay rejection**

```bash
./build/nocturne-kx decrypt \
  --rx-pk ./keys/receiver_hybrid_pk.bin \
  --rx-sk ./keys/receiver_hybrid_sk.bin \
  --replay-db ./replay.db \
  --in msg.pkt --out /dev/null
# ReplayDetected: counter 1 <= last seen 1
# exit 2
```

**Audit chain verification**

```bash
./build/nocturne-kx audit-verify ./audit.log \
  --expect-signer ./keys/auditor_pk.bin
# ok: 247 records verified
# chain head: 7f3a...c4d2
```


## KEM modes

| Mode | Flag | Ciphertext | Shared secret | Post-quantum |
|---|---|---|---|---|
| `x25519` | `--kem x25519` | 32 B | 32 B | No |
| `hybrid` | `--kem hybrid` | 1600 B | 32 B (combined) | Yes |
| `mlkem1024` | `--kem mlkem1024` | 1568 B | 32 B | Yes (only) |

Hybrid mode feeds both shared secrets through the SP 800-56C R2 KDF with `NOCTURNE_PROTOCOL_VERSION=4` as domain separator. This is the default and recommended mode.


## HSM integration

For production key storage, point the signer at a PKCS#11 URI:

```bash
./build/nocturne-kx encrypt \
  --rx-pk ./keys/receiver_hybrid_pk.bin \
  --sign-hsm-uri "pkcs11:token=NocturneToken;object=sender-key" \
  --in message.txt --out msg.pkt
```

Environment variables:

| Variable | Purpose |
|---|---|
| `PKCS11_LIB` | Path to the PKCS#11 shared library |
| `NOCTURNE_HSM_PIN` | HSM user PIN |
| `NOCTURNE_HSM_FIPS` | Set to `1` to enforce FIPS-only mechanisms |
| `NOCTURNE_HSM_PASSPHRASE` | Passphrase for FileHSM-encrypted keys (dev only) |

The CI pipeline runs the PKCS#11 adapter against SoftHSM2. See [`.github/workflows/cmake.yml`](.github/workflows/cmake.yml) for the "SoftHSM PKCS#11 integration" step.


## TLS transport

```bash
# Start receiver
./build/nocturne-kx tls-recv \
  --cert server.pem --key server-key.pem \
  --rx-pk ./keys/receiver_hybrid_pk.bin \
  --rx-sk ./keys/receiver_hybrid_sk.bin \
  --port 9443

# Send from another terminal
./build/nocturne-kx tls-send \
  --host 127.0.0.1 --port 9443 \
  --rx-pk ./keys/receiver_hybrid_pk.bin \
  --kem hybrid \
  --in message.txt
```

The TLS layer requires `ENABLE_TLS_TRANSPORT=ON` at build time and OpenSSL >= 3.0.


## Documentation

Full documentation is at **[bufffer.github.io/nocturne-kx](https://bufffer.github.io/nocturne-kx/)**, including:

- Architecture and module map
- Wire format (every byte, in order)
- KEM and signature mode reference
- HSM setup with SoftHSM2 and Thales Luna
- Audit log internals
- Replay protection internals
- Full CLI reference


## Tests

```bash
cmake -B build -DBUILD_TESTS=ON
cmake --build build -j
cd build && ctest --output-on-failure
```

CI runs four workflows on every push: sanitizer build (ASAN + UBSAN + MSAN), comprehensive integration tests including SoftHSM PKCS#11, fuzzing with libFuzzer, and a security audit (CodeQL, Trivy, cppcheck, Gitleaks).


## Security

All cryptographic operations are either libsodium calls, liboqs calls, or combinations through an OASIS/NIST-published combiner. If you find a hand-rolled cipher, hash, or constant-time comparison anywhere in `src/`, treat it as a bug.

To report a vulnerability, email **serdarogluibrahim@gmail.com**. Do not open a public issue.


## Intellectual property

Copyright 2025-2026 Halil Ibrahim Serdaroglu. All rights reserved.

- Nocturne-KX is a trademark of Halil Ibrahim Serdaroglu

Source code is available under the [MIT License](LICENSE). Patent rights are reserved for the innovations described above.
