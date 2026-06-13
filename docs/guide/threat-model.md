---
title: Threat model
description: What Nocturne-KX defends against, what it does not, and where its assumptions break.
---

# Threat model

A cryptographic tool without an explicit threat model is just a kit of
parts. This page enumerates what Nocturne-KX is designed to resist,
what it assumes is already solved, and where its assumptions fail.

## Adversary map


Each leaf is a specific mitigation in code. Branches Nocturne-KX does
not defend ("network metadata", "endpoint compromise") are absent on
purpose, they live in the [Out of scope](#out-of-scope-explicitly-not-defended)
section below.

## In scope: defended

### "Harvest now, decrypt later" by a future quantum adversary

A nation-state collects ciphertexts today and runs Shor against them
in 2032. With hybrid X25519 ⊕ ML-KEM-1024 plus hybrid Ed25519 ⊕ ML-DSA-87,
both the symmetric key and the signature stay confidential / unforgeable
even when the classical layer falls, and vice versa.

**Mitigation:** Hybrid KEM + hybrid signature modes, on by default in
the docs' quickstart. NIST Level 5 post-quantum security parameter
(ML-KEM-1024, ML-DSA-87), the largest standard variants.

### Replay of a captured ciphertext

Mallory captures a packet from a previous session and re-sends it
hoping the receiver will accept and act on it.

**Mitigation:** `ReplayDB` stores a monotonic counter per
`(receiver, session)` tuple in a MAC-protected, atomically-written file.
Any counter `≤ last seen` is rejected with `ErrorCode::ReplayDetected`
*before* AEAD decryption is attempted. The prefix-based counter separation means independent sessions can run
in parallel without sharing a single linear counter that an attacker
could exhaust.

### Pinned-signer impersonation

Mallory swaps in their own key pair and tries to sign packets that
appear to come from Alice.

**Mitigation:** `--expect-signer` and `--expect-pqc-signer` pin a
specific public key on the receiver. A signature from any other key
is `ErrorCode::SignatureVerifyFailed`; a packet missing a signature
when one is expected is `ErrorCode::SignatureMissing`.

### Stale key rotation

A long-lived adversary tries to keep using a rotated-out key after the
operator has moved on.

**Mitigation:** `rotation_id` is bound into the AAD and checked against
`DecryptOptions::min_rotation_id`. Anything below the floor is
`ErrorCode::RotationStale`.

### Wire-format tampering

Mallory flips a single bit anywhere in the packet body, the AEAD tag,
the signature, or any length field.

**Mitigation:** XChaCha20-Poly1305 authenticates the ciphertext + AAD;
the detached signature covers the canonical bytes of everything that
precedes it; libsodium's `crypto_aead_xchacha20poly1305_ietf_decrypt`
fails closed in constant time on any tag mismatch.

### Side-channel observation

A co-resident process on the same host (or a malicious admin) watches
cache timings or branch behaviour during a `sign` or `decrypt`.

**Mitigation:** All comparisons go through `sodium_memcmp` /
`constant_time_compare`. Secret memory is `sodium_memzero`'d on
destructor + `clflush`'d + `memory_barrier`'d. A 100–500 µs uniform
random delay is added after each sign to flatten timing distributions.

### Audit-log tampering

An insider deletes or rewrites the last 10 lines of `audit.log` to
hide a transaction.

**Mitigation:** Every record carries a BLAKE2b hash of the previous
record's canonical bytes. `audit-verify` walks the file and reports
the first chained hash that doesn't match, single-line tampering
breaks the chain at exactly that record. With `--audit-sign-key`,
each record is also Ed25519-signed; the auditor's pinned PK pins the
signer too.

## In scope: partially defended

### Compromised HSM PIN

If the operator's PIN is leaked, an attacker can use the HSM to sign.

**Mitigation:** PINs are zeroed immediately after `C_Login` via
`sodium_memzero`. `KeyRotationManager` enforces dual-control rotation
behind `RotationPolicy::require_dual_approval=true`. Beyond that, you
need your HSM vendor's anti-tamper hardware to refuse extraction.

### Side-channel on the HSM device itself

If your HSM has a known DPA / EMA / fault-injection vulnerability,
Nocturne can't help, it never sees the secret key material.

**Mitigation:** Use a FIPS 140-3 Level 3+ device with documented
side-channel resistance. The `PKCS11HSM::get_status()` reports
`fips_mode` so policy code can refuse to start against a non-FIPS
provider.

## Out of scope: explicitly NOT defended

### Network-level metadata

Nocturne encrypts *payloads*. If the network observer can see *who*
talks to *whom* and *when*, that fact alone may be enough to
compromise the operation. Pair with Tor, a private overlay, or a
real point-to-point link, Nocturne-KX is not an anonymity tool.

### Endpoint compromise

If the attacker has root on the sender's box, they can replace the
plaintext before encryption, exfiltrate keys from memory, or
manipulate the replay DB. Use a hardened OS, mandatory access
control (SELinux / AppArmor), and a TPM-attested boot to push back
on this, Nocturne does not.

### Denial of service

A flooded `ReplayDB` write path, a malformed packet sized to exhaust
memory, or a continuous stream of valid packets all degrade
availability. `RateLimiter` and `MAX_PACKET_SIZE` cap the worst cases
but the protocol assumes a fundamentally cooperative network.

### Insider with the right CLA-signed commit

Nocturne is open source. A malicious commit that lands on `main` and
ships in a release ships. The defence is the [CONTRIBUTING](https://github.com/Bufffer/nocturne-kx/blob/main/CONTRIBUTORS.md)
process plus code review, not a runtime check.

### Quantum adversaries who have already broken ML-KEM-1024

If somebody publishes a polynomial-time algorithm for Module-LWE in
2027, ML-KEM-1024 is dead. The hybrid mode buys time, the X25519
half is still classically secure, but a sufficiently large quantum
computer in the hands of the same adversary breaks everything.
That's the limit; nothing in our gift fixes it.

## Cryptographic assumptions, named

| Assumption | What we rely on it for |
|------------|------------------------|
| DLP in `Curve25519` is hard | X25519 ECDH confidentiality, Ed25519 unforgeability |
| Module-LWE is hard           | ML-KEM-1024, ML-DSA-87, NIST Level 5 parameter |
| XChaCha20 keystream is PRF   | Symmetric encryption secrecy |
| Poly1305 is a universal MAC  | AEAD integrity |
| BLAKE2b is collision-resistant | Audit chain integrity, transcript binding |
| libsodium's RNG is unpredictable | Every nonce / ephemeral / key |

If any of these falls in isolation, hybrid mode buys time. If two fall
simultaneously, Nocturne-KX (and almost every other tool) is in trouble.

## What to read next

- [Architecture](../architecture), the module map and packet flow.
- [Quickstart](./quickstart), prove the defences run on your laptop.
- [Wire format](./wire-format), every byte and what authenticates it.
