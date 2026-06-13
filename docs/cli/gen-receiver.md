---
title: gen-receiver
description: Generate a Nocturne-KX receiver KEM keypair (X25519, hybrid, or pure ML-KEM-1024).
---

# `gen-receiver`

Generate the keypair the *receiver* of a Nocturne packet needs. The
public key is what the sender pins via `--rx-pk`; the secret key
must stay on the receiver's box (or in an HSM).

## Synopsis

```
nocturne-kx gen-receiver <outdir> [--kem x25519|hybrid|mlkem]
```

## Arguments

| Argument | Default  | Description |
|----------|----------|-------------|
| `&lt;outdir&gt;` | required | Directory the key files are written to. Created if missing. |
| `--kem`    | `x25519` | KEM algorithm. See [KEM modes](../pqc/kem). |

## Output files

| `--kem` value | Files written                                          | Sizes              |
|---------------|--------------------------------------------------------|--------------------|
| `x25519`      | `receiver_x25519_pk.bin`, `receiver_x25519_sk.bin`     | 32 B / 32 B         |
| `hybrid`      | `receiver_hybrid_pk.bin`, `receiver_hybrid_sk.bin`     | 1600 B / 3200 B     |
| `mlkem`       | `receiver_mlkem_pk.bin`, `receiver_mlkem_sk.bin`       | 1568 B / 3168 B     |

All files are raw bytes — no PEM, no length prefix. The CLI verifies
sizes on read.

## Examples

```bash
# Default classical X25519
nocturne-kx gen-receiver ./keys

# Hybrid PQC (recommended for production)
nocturne-kx gen-receiver ./keys --kem hybrid

# Pure ML-KEM-1024
nocturne-kx gen-receiver ./keys --kem mlkem
```

## Security notes

- The secret key is written with `0600` permissions where the
  filesystem honours them. `security-check` reports world-readable
  permissions as a warning.
- For production, generate the keypair on the eventual receiver box
  and never transfer the secret key — or generate inside an HSM and
  export only the public key.
- The `NCHSM2` format wraps a secret key under an Argon2id-derived
  AEAD; pass the passphrase via `NOCTURNE_HSM_PASSPHRASE` to use it.

## Exit codes

| Code | Meaning |
|------|---------|
| 0    | Both files written.                                   |
| 1    | Bad `--kem` value, missing `&lt;outdir&gt;`, or filesystem error. |
