---
title: decrypt
description: Decrypt a Nocturne-KX packet. KEM mode is auto-detected from the flags byte; signature pinning is opt-in.
---

# `decrypt`

The receiver-side counterpart to [`encrypt`](./encrypt). Auto-detects
the KEM mode from the packet header, runs replay + rotation checks,
and verifies any pinned signatures before returning plaintext.

## Synopsis

```
nocturne-kx decrypt \
  --rx-pk <file> --rx-sk <file>
  [--expect-signer <pk-file>]
  [--min-rotation <u32>]
  [--expect-pqc-signer <pk-file> --pqc-sig-type ed25519|hybrid|mldsa]
  --in <packet> --out <plaintext>
  [--replay-db <path>]
  [--mac-key <file>]
```

## Required flags

| Flag       | Description |
|------------|-------------|
| `--rx-pk`  | Receiver KEM public key (used as authenticated context). |
| `--rx-sk`  | Receiver KEM secret key. |
| `--in`     | Packet to decrypt. |
| `--out`    | Destination for plaintext. |

The CLI checks `--rx-pk` / `--rx-sk` sizes against the detected KEM
mode and rejects mismatches with `KemSizeMismatch` before attempting
decapsulation.

## Optional flags

| Flag                    | Effect |
|-------------------------|--------|
| `--expect-signer`       | Pin an Ed25519 public key. Missing or wrong-signer packets fail. |
| `--min-rotation`        | Reject packets with `rotation_id` below this floor. |
| `--expect-pqc-signer`   | Pin a PQ signer PK. Pairs with `--pqc-sig-type`. |
| `--pqc-sig-type`        | Required when `--expect-pqc-signer` is set. |
| `--replay-db`           | Reject packets whose counter ≤ last seen for `(receiver, session)`. |
| `--mac-key`             | MAC key for `--replay-db`. |

## Examples

### Hybrid PQC + pinned hybrid signer + replay DB

```bash
nocturne-kx decrypt \
  --rx-pk ./keys/receiver_hybrid_pk.bin \
  --rx-sk ./keys/receiver_hybrid_sk.bin \
  --expect-pqc-signer ./keys/sender_hybrid_sig_pk.bin \
  --pqc-sig-type hybrid \
  --replay-db ./replay.db \
  --mac-key ./keys/replay.macsk \
  --in msg.pkt --out note.txt
```

### Classical X25519, no signature pinning (development only)

```bash
nocturne-kx decrypt \
  --rx-pk ./keys/receiver_x25519_pk.bin \
  --rx-sk ./keys/receiver_x25519_sk.bin \
  --in msg.pkt --out note.txt
```

## Error semantics

All failures exit with code 2 and a typed error name in stderr:

| Error                         | Cause |
|-------------------------------|-------|
| `PacketTruncated`             | Input shorter than the wire format requires. |
| `PacketFieldOversized`        | A length field exceeds `MAX_PQC_*_SIZE` or `MAX_PACKET_SIZE`. |
| `KemTypeUnknown`              | `kem_type` byte isn't compiled in. |
| `KemSizeMismatch`             | `--rx-pk`/`--rx-sk` size doesn't match the packet's mode. |
| `KemDecapsulateFailed`        | Wrong secret key or tampered KEM ct. |
| `AeadAuthFailed`              | Tampered ciphertext, AAD, or wrong AEAD key (= wrong combined secret). |
| `SignatureMissing`            | `--expect-signer` set but packet lacks the flag. |
| `SignatureVerifyFailed`       | Pinned signer doesn't match packet. |
| `RotationStale`               | `rotation_id` below `--min-rotation`. |
| `ReplayDetected`              | Counter ≤ last seen, bidirectional replay defence. |
| `RateLimited`                 | Receiver bucket exhausted. |

The error string `"replay"` appears verbatim on `ReplayDetected`.
CI suites grep for it.

## Exit codes

| Code | Meaning |
|------|---------|
| 0    | Plaintext written successfully. |
| 1    | Usage error (missing file, bad flag). |
| 2    | Cryptographic / policy failure (see above). |
