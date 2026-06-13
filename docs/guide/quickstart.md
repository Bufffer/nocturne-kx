---
title: Quickstart
description: Build Nocturne-KX from source, generate a hybrid PQC keypair, and run an encrypt → decrypt roundtrip in under five minutes.
---

# Quickstart

This walks you from `git clone` to a working hybrid post-quantum encrypt /
decrypt roundtrip. Tested on Ubuntu 24.04, macOS 14, and GitHub Codespaces.
Windows builds via WSL2 follow the same recipe.

::: tip Time budget
Five minutes if libsodium is already installed; ten if you need
`liboqs` to fetch-and-build via CMake's `FetchContent` fallback.
:::

## Prerequisites

| Tool        | Version | Why                                                    |
|-------------|---------|--------------------------------------------------------|
| CMake       | ≥ 3.20  | Single canonical `CMakeLists.txt` (v4.0.0)             |
| GCC or Clang| C++23   | `std::expected`, `std::span`, designated initialisers  |
| libsodium   | ≥ 1.0.18| Every classical primitive                              |
| liboqs      | 0.12.0  | Auto-fetched if not system-installed (ML-KEM, ML-DSA)  |
| OpenSSL     | ≥ 3.0   | Optional — only if `ENABLE_TLS_TRANSPORT=ON`           |

```bash
# Debian / Ubuntu
sudo apt-get update
sudo apt-get install -y \
  build-essential cmake git pkg-config \
  libsodium-dev libssl-dev catch2 ninja-build
```

```bash
# macOS (Homebrew)
brew install cmake libsodium openssl@3 catch2
```

## Build

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

The resulting binary lives at `build/nocturne-kx`. Sanity check:

```bash
./build/nocturne-kx self-test
```

If `self-test` reports any failure, **stop** and open an issue —
the binary's other subcommands assume libsodium and ML-KEM both initialise
cleanly.

## Generate hybrid PQC keys

Hybrid mode runs X25519 *and* ML-KEM-1024 in parallel, combining the
shared secrets via NIST SP 800-56C R2. An attacker has to break both.

```bash
./build/nocturne-kx gen-receiver ./keys --kem hybrid
# → receiver_hybrid_pk.bin (1600 B), receiver_hybrid_sk.bin (3200 B)

./build/nocturne-kx gen-signer ./keys --sig-type hybrid
# → sender_hybrid_sig_pk.bin (2624 B), sender_hybrid_sig_sk.bin (4960 B)
```

::: warning Key hygiene
The secret keys end up as raw bytes on disk. For production, point
`--sign-hsm-uri` at a `file://` (dev) or `hsm://token:label` URI
(PKCS#11). The [HSM guide](./hsm) walks through SoftHSM2 and Thales
Luna setups.
:::

## Encrypt

```bash
echo "meet at midnight" | ./build/nocturne-kx encrypt \
  --rx-pk ./keys/receiver_hybrid_pk.bin \
  --kem hybrid \
  --pqc-sign-key ./keys/sender_hybrid_sig_sk.bin \
  --pqc-sig-type hybrid \
  --aad "session-7f3a" \
  --replay-db ./replay.db \
  --in /dev/stdin --out ./msg.pkt

# msg.pkt is ~4.9 KiB: 78-byte header + 1600 B KEM ct + 16 B aad + 32 B
# AEAD payload + 4691 B hybrid signature.
```

What just happened, in plain English:

1. The CLI loaded the receiver's hybrid public key (1600 B).
2. It ran `pqc::HybridKEM::encapsulate` to produce a 1600 B ciphertext
   and a 32 B combined shared secret, mixing X25519 ECDH and
   ML-KEM-1024 encapsulation outputs through SP 800-56C R2 with
   `NOCTURNE_PROTOCOL_VERSION=4` as domain separator.
3. The combined secret keyed an XChaCha20-Poly1305 AEAD over the
   plaintext + `--aad`.
4. A hybrid Ed25519 ⊕ ML-DSA-87 signature was computed over the
   serialised packet head (everything before the signature block).
5. A monotonic counter was written to `./replay.db` for the
   `(receiver, session)` tuple.

## Decrypt

The receiver auto-detects the KEM mode from the flags byte — no
`--kem` needed.

```bash
./build/nocturne-kx decrypt \
  --rx-pk ./keys/receiver_hybrid_pk.bin \
  --rx-sk ./keys/receiver_hybrid_sk.bin \
  --expect-pqc-signer ./keys/sender_hybrid_sig_pk.bin \
  --pqc-sig-type hybrid \
  --replay-db ./replay.db \
  --in ./msg.pkt --out ./plaintext

cat ./plaintext
# meet at midnight
```

## Prove replay protection

The patent-pending bidirectional replay defence rejects a second
decrypt of the same packet:

```bash
./build/nocturne-kx decrypt \
  --rx-pk ./keys/receiver_hybrid_pk.bin \
  --rx-sk ./keys/receiver_hybrid_sk.bin \
  --replay-db ./replay.db \
  --in ./msg.pkt --out ./stolen.txt
# ReplayDetected: counter 1 ≤ last seen 1
# exit 2
```

You've now exercised the full hybrid PQC path end-to-end. Next stops:

- [Architecture](../architecture) — modules, threading model, libsodium boundary.
- [HSM integration](./hsm) — moving keys off disk into a PKCS#11 token.
- [Wire format](./wire-format) — every byte explained.
- [CLI reference](../cli/) — every subcommand and flag.
