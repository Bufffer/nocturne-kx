---
title: encrypt
description: Encrypt a file into a Nocturne-KX packet: classical, hybrid, or pure PQC. Optional classical and/or PQ signatures.
---

# `encrypt`

The main sender-side subcommand. Reads plaintext from `--in`, writes
a Nocturne packet to `--out`. Mode is picked by `--kem`; both
classical Ed25519 and PQ signatures are independently configurable.

## Synopsis

```
nocturne-kx encrypt \
  --rx-pk <file>
  [--kem x25519|hybrid|mlkem]
  [--sign-hsm-uri file://<skfile> | hsm://<token_id>:<key_label>]
  [--aad <string>]
  [--rotation-id <u32>]
  [--ratchet]
  [--pqc-sign-key <file> --pqc-sig-type ed25519|hybrid|mldsa]
  --in <plaintext> --out <packet>
  [--replay-db <path>]
  [--mac-key <file>]
```

## Required flags

| Flag       | Description |
|------------|-------------|
| `--rx-pk`  | Receiver's KEM public key file. Size must match `--kem`. |
| `--in`     | Plaintext file. Use `/dev/stdin` to read from stdin. |
| `--out`    | Destination for the serialised packet. |

## Optional flags

| Flag                  | Default | Description |
|-----------------------|---------|-------------|
| `--kem`               | `x25519`| KEM algorithm. See [KEM modes](../pqc/kem). |
| `--sign-hsm-uri`      | unset   | URI selecting an Ed25519 signer. `file://` reads a raw or `NCHSM2` SK file; `hsm://` drives `PKCS11HSM`. |
| `--aad`               | empty   | Associated authenticated data, covered by the AEAD tag. |
| `--rotation-id`       | `0`     | Key-rotation counter. Receiver enforces `--min-rotation` floor. |
| `--ratchet`           | off     | Mix an ephemeral DH share into the AEAD key for forward secrecy. |
| `--pqc-sign-key`      | unset   | Path to a PQ signer SK file (matches `--pqc-sig-type`'s SK size). |
| `--pqc-sig-type`      | unset   | PQ signature algorithm. Required if `--pqc-sign-key` is set. |
| `--replay-db`         | unset   | On-disk replay database. Counter increments per packet. |
| `--mac-key`           | unset   | MAC key file for `--replay-db`. Recommended in production. |

## Examples

### Minimal hybrid PQC

```bash
nocturne-kx encrypt \
  --rx-pk ./keys/receiver_hybrid_pk.bin \
  --kem hybrid \
  --in note.txt --out msg.pkt
```

### Hybrid PQC + hybrid signature + replay DB

```bash
nocturne-kx encrypt \
  --rx-pk ./keys/receiver_hybrid_pk.bin \
  --kem hybrid \
  --pqc-sign-key ./keys/sender_hybrid_sig_sk.bin \
  --pqc-sig-type hybrid \
  --aad "session-7f3a" \
  --replay-db ./replay.db \
  --mac-key ./keys/replay.macsk \
  --in note.txt --out msg.pkt
```

### HSM-backed Ed25519 over X25519

```bash
nocturne-kx encrypt \
  --rx-pk ./keys/receiver_x25519_pk.bin \
  --sign-hsm-uri "hsm://prod-token:rsa-key-01" \
  --in note.txt --out msg.pkt
```

## What gets written

A serialised v3 packet, see [wire format](../guide/wire-format) for
the field-by-field breakdown. Size is deterministic from the flags:

| Mode | Approximate size |
|------|------------------|
| Classical, unsigned | header + plaintext + 16 B tag (78 + n bytes) |
| Hybrid, unsigned    | header + 1600 B KEM ct + plaintext + 16 B tag (~1.7 KiB + n) |
| Hybrid, hybrid sig  | hybrid + 4691 B signature (~6.4 KiB + n) |

## Exit codes

| Code | Meaning |
|------|---------|
| 0    | Packet written successfully.                            |
| 1    | Bad flag value, missing file, or HSM URI error.         |
| 2    | Cryptographic failure (KEM, AEAD, or HSM-side).         |
