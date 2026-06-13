---
title: Domain separation
description: Why every KDF in Nocturne-KX is labelled, and how the protocol version stays distinct from the wire version.
---

# Domain separation

A subtle but important property of Nocturne's combiner: every KDF
output is bound to an explicit context label, so two different
operations never accidentally derive the same key from the same input.

## The bug, visualised

Commit `9b5c00b` fixed the kind of regression this entire system is
designed to prevent. The sender bound to one version, the receiver
bound to another, and the AEAD silently failed at decryption time
without the receiver ever knowing why.


After the fix, both sides bind to `NOCTURNE_PROTOCOL_VERSION` (currently
4), distinct from the packet `ver` byte (currently 3). See
[wire-format version policy](../guide/wire-format#version-policy).

## The labels

| Context | Label string |
|---------|--------------|
| Hybrid KEM combiner | `"NOCTURNE/KEM/v" + PROTOCOL_VERSION + "/combine"` |
| AEAD key derivation | `"NOCTURNE/AEAD/v" + PROTOCOL_VERSION + "/key"` |
| DH ratchet root | `"NOCTURNE/RATCHET/v" + PROTOCOL_VERSION + "/root"` |
| ReplayDB encryption key | `"NOCTURNE/REPLAY/v1/macsk"` |

`PROTOCOL_VERSION` is the **logical** protocol version (currently 4),
distinct from the packet `ver` byte (currently 3), see
[wire format / version policy](../guide/wire-format#version-policy).

## Why this matters

Without explicit domain separation, two correctly-implemented KDFs
that happen to take the same input would produce the same output.
That sounds benign until you realise:

- An attacker who captures a packet and watches a subsequent ratchet
  step could correlate ciphertexts in ways the protocol didn't
  intend.
- A future protocol revision that reuses the combiner under a new
  context (say, audit log encryption) would silently key the same
  bytes as the KEM combiner, a related-key attack waiting to happen.

By labelling every KDF call, the protocol promises that **the only
way two outputs are equal is if both inputs and labels are equal**.
Future revisions that change the combiner must change the label too,
making the break loud rather than silent.

## The bug this almost caused

Commit `9b5c00b` fixed a domain-separation regression: `HybridKEM::combine_secrets`
bound to `NOCTURNE_PROTOCOL_VERSION` (4), but `decrypt_packet_kem`
was passing the outer packet `ver` byte (3). Sender and receiver
derived different combined secrets, AEAD auth fail.

The user found it running `./demo.sh` on a GitHub Codespace, five
minutes of end-to-end work caught what a CI matrix of compile and
sanitizer jobs couldn't. The lesson is now permanent:

> When a KDF takes a "version" input, both encapsulator and
> decapsulator MUST agree on the value. Don't conflate "outer
> protocol version" with "KEM combiner version", they evolve on
> different axes.

## When you'd revise this

Bump `PROTOCOL_VERSION` when:

- The combiner construction changes (e.g. SP 800-56C R2 → R3).
- The combiner inputs change (e.g. adding HQC alongside ML-KEM).
- The AEAD key derivation function changes.

Bump the packet `ver` byte when:

- The wire layout changes (new mandatory field).
- A flag's meaning changes.
- A field's encoding (LE → BE, fixed → varint) changes.

The two are independent; both can land in the same release without
collision.

## Verifying domain separation

The audit log records the negotiated `PROTOCOL_VERSION` per
operation. If you ever see two records with the same plaintext,
same key, and different ciphertexts, the labels are doing their job.
If you see the same ciphertext under two different contexts, file an
issue, that's a domain-separation regression and we want to know
immediately.
