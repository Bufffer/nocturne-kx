---
title: Signature modes
description: Ed25519, hybrid Ed25519+ML-DSA-87, pure ML-DSA-87 — what each binds to and where to use it.
---

# Signature modes

A Nocturne packet can carry:

- A **classical** Ed25519 detached signature (`FLAG_HAS_SIG`, fixed 64 B).
- A **post-quantum** variable-length signature (`FLAG_HAS_PQC_SIG`).

The two are *orthogonal* — both can be set together for a
hybrid-signed packet that an Ed25519-only verifier still trusts.

## Choosing

| `--pqc-sig-type` | When to use                                                              |
|------------------|--------------------------------------------------------------------------|
| `ed25519`        | Compatibility with legacy verifiers; 64 B signature.                    |
| `hybrid`         | Production. Defends both classical and quantum signer-impersonation.    |
| `mldsa`          | Pure-PQ deployments. 4627 B signature.                                  |

For an HSM-backed signer (`--sign-hsm-uri`), the classical Ed25519
signature is computed inside the HSM via CKM_EDDSA. The PQ signer is
software-only (no ML-DSA HSM hardware shipping at scale yet).

## API

```cpp
#include "src/pqc/sig/sig_factory.hpp"

auto scheme = nocturne::pqc::SignatureFactory{}.create(
    nocturne::pqc::SigType::HYBRID_ED25519_MLDSA87
);

// Sender
auto kp = scheme->generate_keypair();
auto sig = scheme->sign(message, kp.secret_key);

// Receiver
const bool ok = scheme->verify(message, sig, kp.public_key);
```

`sign` and `verify` are `[[nodiscard]]`; the build refuses to compile
a discarded result.

## Sizes

| Operation               | Ed25519 | Hybrid | Pure ML-DSA-87 |
|-------------------------|---------|--------|----------------|
| Public key              | 32 B    | 2624 B | 2592 B         |
| Secret key              | 64 B    | 4960 B | 4896 B         |
| Signature               | 64 B    | 4691 B | 4627 B         |

Hybrid is exactly `Ed25519 || ML-DSA-87` — concatenated raw, no length
prefix between them (the fixed sizes are pinned at compile time by
`static_assert` in `pqc_config.hpp` so a future ML-DSA-87 size
revision triggers a build break).

Verification is logical AND — both halves must check independently.
A forged Ed25519 signature paired with a valid ML-DSA-87 still
rejects.

## What gets signed

```
canonical_bytes =
    [ver][flags][rotation_id][eph_pk OR zeros][nonce][counter]
    [optional ratchet_pk]
    [optional kem block]
    [aad_len][ct_len][aad][ct]
```

Everything *before* the signature block. The KEM block (when present)
is signed so an attacker can't swap a different ML-KEM ciphertext in
without invalidating the signature.

## Failure modes

| Error                       | Cause |
|-----------------------------|-------|
| `SignatureMissing`          | `--expect-signer` or `--expect-pqc-signer` was set but the packet didn't carry the corresponding flag. |
| `SignatureVerifyFailed`     | Signature failed to verify against the pinned PK. |
| `SignatureTypeMismatch`     | Pinned signer expects one SigType; packet carries another. |
| `SignatureBackendFailure`   | liboqs internal failure (extremely rare). |

## HSM-backed Ed25519

When `--sign-hsm-uri` is set, the CLI delegates the Ed25519 sign step
to the HSM. The HSM never returns the secret key — every signature is
computed on-device via `CKM_EDDSA`. See the [HSM guide](../guide/hsm).

The PQ signer path (`--pqc-sign-key`) is a separate code path —
no HSM support yet, since ML-DSA-aware HSMs are still rare. When
ML-DSA hardware lands, the `SignatureScheme` interface absorbs it
without protocol changes; just add a new factory backend.
