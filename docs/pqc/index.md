---
title: Post-quantum cryptography
description: How Nocturne-KX integrates NIST FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA), and why hybrid modes are the default.
---

# Post-quantum cryptography

Nocturne-KX uses post-quantum cryptography in two places:

- **Key encapsulation (KEM)** for confidentiality of the AEAD key.
- **Digital signatures** for authenticity of the entire packet.

Both surfaces ship in **hybrid mode by default**: a classical
primitive runs in parallel with a NIST-standardised lattice scheme,
combined through a domain-separated KDF. An attacker has to break
both halves to compromise a packet.

## Algorithm picker


## Available algorithms

### KEMs (key encapsulation)

| `KEMType`                  | Algorithm                       | Wire ID | Pk / Sk / Ct |
|----------------------------|---------------------------------|---------|--------------|
| `CLASSIC_X25519`           | X25519 ECDH                     | 0       | 32 / 32 / 32 B |
| `HYBRID_X25519_MLKEM1024`  | X25519 ⊕ ML-KEM-1024 (default)  | 1       | 1600 / 3200 / 1600 B |
| `PURE_MLKEM1024`           | ML-KEM-1024 (NIST FIPS 203 L5)  | 2       | 1568 / 3168 / 1568 B |

[KEM modes →](./kem)

### Signatures

| `SigType`                    | Algorithm                          | Wire ID | Pk / Sk / Sig |
|------------------------------|------------------------------------|---------|---------------|
| `CLASSIC_ED25519`            | Ed25519 (RFC 8032)                 | 0       | 32 / 64 / 64 B |
| `HYBRID_ED25519_MLDSA87`     | Ed25519 ⊕ ML-DSA-87 (default)      | 1       | 2624 / 4960 / 4691 B |
| `PURE_MLDSA87`               | ML-DSA-87 (NIST FIPS 204 L5)       | 2       | 2592 / 4896 / 4627 B |

[Signature modes →](./signatures)

Wire IDs are stable; never renumber. The numbers are part of the
audit / SIEM contract.

## Why hybrid by default

Three reasons:

1. **No catastrophic single point of failure.** ML-KEM is brand new
   in the wild. Hybrid mode means a future Module-LWE break only
   downgrades us to classical X25519 security, still ~128-bit
   classical.
2. **Audit trail compatibility.** The hybrid signature embeds the
   Ed25519 half, so legacy verifiers that pin a classical PK keep
   working during the transition.
3. **Combined secret is at least as strong as the strongest input.**
   The NIST SP 800-56C R2 combiner is proven to inherit the security
   of the strongest contributor, so even if X25519 is broken
   classically and ML-KEM holds, we're still secure.

## Why ML-KEM-1024 and ML-DSA-87 specifically

Both are the **largest** NIST Level 5 variants. Smaller parameter
sets (ML-KEM-768 / ML-DSA-65) save kilobytes per packet but pin
NIST Level 3 (≈ AES-192). Level 5 ≈ AES-256, which matches our
existing symmetric primitive (XChaCha20-Poly1305 ≈ 256-bit) and
leaves no symmetric/asymmetric mismatch for an attacker to exploit.

## Domain separation

The combiner is `NIST SP 800-56C Revision 2 KDF` with explicit
domain separation:

```
combined_secret = KDF(
    classical_ss || pqc_ss,
    label = "NOCTURNE/KEM/v" + PROTOCOL_VERSION + "/combine"
)
```

`PROTOCOL_VERSION` is **not** the same as the packet `ver` byte.
[the wire-format page](../guide/wire-format#version-policy) explains
the split. Conflating the two was the bug fixed by commit `9b5c00b`.

[Domain separation deep dive →](./domain-separation)

## What's not used

- **NTRU**, **NTRU-Prime**, **HQC**, alternates from NIST round 4
  that didn't make the standard. Not in liboqs's default profile.
- **SLH-DSA (SPHINCS+)**, hash-based signature with multi-second
  sign times. Excellent for offline root signing; not a fit for a
  per-packet signer.
- **Classic McEliece**, large public keys (≈ 1 MiB) make it
  impractical for our wire format.
- **Falcon**, competitive ML-DSA alternative, but its constant-time
  Gaussian sampler implementation in liboqs is not currently
  side-channel reviewed to our standard.

If your threat model requires one of these, the `KEMInterface` /
`SignatureScheme` are designed for it, add a new factory entry and
a wire ID and the rest of the protocol stays unchanged.
