---
title: KEM modes
description: X25519: hybrid X25519+ML-KEM-1024, pure ML-KEM-1024, wire IDs, sizes, and how to pick.
---

# KEM modes

The `--kem` flag picks one of three key-encapsulation paths. The
wire format is symmetric across all three; only the size of the
`kem_ct` block changes (and is zero for the classical path).

## Choosing

| Setting | When to use |
|--------|-------------|
| `x25519` | Constrained devices where 1.6 KiB of KEM ciphertext is too much; legacy interop. |
| `hybrid` (default) | Production. Defends against both classical and quantum attackers. |
| `mlkem` | Pure-PQ deployments where you've accepted the classical attack surface as out of scope, or you're constrained by classical key compromise (e.g. archived X25519 keys). |

## API

```cpp
#include "src/pqc/kem/kem_factory.hpp"

auto kem = nocturne::pqc::KEMFactory{}.create(
    nocturne::pqc::KEMType::HYBRID_X25519_MLKEM1024
);

// Sender
auto kp = kem->generate_keypair();
auto [ct, ss_sender] = kem->encapsulate(kp.public_key);

// Receiver
auto ss_receiver = kem->decapsulate(ct, kp.secret_key);

assert(ss_sender.secret == ss_receiver.secret);
```

`encapsulate` / `decapsulate` are `[[nodiscard]]`; ignoring the
return value is a build error after P6.5.

## Hybrid combiner

```
combined_ss = HKDF-SHA-256(
    salt = "NOCTURNE/KEM/v4/combine",
    ikm  = x25519_ss || mlkem_ss,
    info = "AEAD-key/32",
    L    = 32
)
```

NIST SP 800-56C R2 calls this the "two-step" combiner with a
domain-separated salt. The combined secret is then bound to
`NOCTURNE_PROTOCOL_VERSION` so a future combiner change is a
signalled break, not a silent one.

## Sizes at a glance

| Operation              | Classical | Hybrid | Pure ML-KEM |
|------------------------|-----------|--------|-------------|
| Public key             | 32 B      | 1600 B | 1568 B      |
| Secret key             | 32 B      | 3200 B | 3168 B      |
| Encapsulated ciphertext| 32 B      | 1600 B | 1568 B      |
| Shared secret (combined) | 32 B    | 32 B   | 32 B        |

The 32 B combined-secret size is constant, every mode keys the same
XChaCha20-Poly1305 AEAD. Code downstream of the combiner is
mode-agnostic.

## Performance ballpark

Measured on an AMD Ryzen 5950X, single-threaded, Release build:

| Operation                  | Classical | Hybrid | Pure ML-KEM |
|----------------------------|-----------|--------|-------------|
| `generate_keypair`         | ≈ 50 µs   | ≈ 110 µs | ≈ 80 µs   |
| `encapsulate`              | ≈ 75 µs   | ≈ 140 µs | ≈ 95 µs   |
| `decapsulate`              | ≈ 75 µs   | ≈ 140 µs | ≈ 95 µs   |

Hybrid is roughly the sum of X25519 and ML-KEM-1024, there's no
clever batching. Both halves run sequentially in the current
implementation; that's a measurable optimisation we haven't taken
because it would complicate the constant-time analysis.

## Failure modes

| Error                  | Cause |
|------------------------|-------|
| `KemTypeUnknown`       | Requested wire ID is not compiled in. Adversarial type byte from a malformed packet. |
| `KemSizeMismatch`      | `receiver_pk` size doesn't match the declared KEM type. |
| `KemEncapsulateFailed` | libsodium / liboqs internal failure (extremely rare; usually a build issue). |
| `KemDecapsulateFailed` | Ciphertext doesn't decapsulate against this secret key. Either a wrong key or active tampering. |

All are typed `Error` values, no exceptions on the hot path.
