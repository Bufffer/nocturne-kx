---
title: gen-signer
description: Generate a Nocturne-KX signer keypair (Ed25519: hybrid Ed25519+ML-DSA-87, or pure ML-DSA-87).
---

# `gen-signer`

Generate the signing keypair the sender uses to authenticate packets.
The public key is what the receiver pins via `--expect-signer` or
`--expect-pqc-signer`.

## Synopsis

```
nocturne-kx gen-signer <outdir> [--sig-type ed25519|hybrid|mldsa]
```

## Arguments

| Argument     | Default   | Description |
|--------------|-----------|-------------|
| `&lt;outdir&gt;`   | required  | Directory the key files are written to. Created if missing. |
| `--sig-type` | `ed25519` | Signature algorithm. See [Signature modes](../pqc/signatures). |

## Output files

| `--sig-type` value | Files written                                            | Sizes              |
|--------------------|----------------------------------------------------------|--------------------|
| `ed25519`          | `sender_ed25519_pk.bin`, `sender_ed25519_sk.bin`         | 32 B / 64 B         |
| `hybrid`           | `sender_hybrid_sig_pk.bin`, `sender_hybrid_sig_sk.bin`   | 2624 B / 4960 B     |
| `mldsa`            | `sender_mldsa87_pk.bin`, `sender_mldsa87_sk.bin`         | 2592 B / 4896 B     |

## Examples

```bash
# Default Ed25519 (also HSM-compatible via CKM_EDDSA)
nocturne-kx gen-signer ./keys

# Hybrid Ed25519 + ML-DSA-87 (recommended for new deployments)
nocturne-kx gen-signer ./keys --sig-type hybrid
```

## HSM-backed signing

`gen-signer` produces software-resident keys. For HSM-backed Ed25519,
use the HSM's own key-generation interface (e.g. `pkcs11-tool` or
`KeyRotationManager::generate_initial_key`) and reference the result
via `hsm://token:label` in `encrypt --sign-hsm-uri`.

PQ signatures (`--pqc-sig-type hybrid|mldsa`) are software-only, no
HSM hardware ships ML-DSA-87 at scale yet.

## Exit codes

| Code | Meaning |
|------|---------|
| 0    | Both files written.                                   |
| 1    | Bad `--sig-type` value, missing `&lt;outdir&gt;`, or filesystem error. |
