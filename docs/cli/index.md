---
title: CLI reference
description: Every Nocturne-KX subcommand, flag, and exit code. Stable across the 4.x line.
---

# CLI reference

`nocturne-kx` is a single static binary. Every subcommand is
hand-written; there's no plugin loader, no dynamic dispatch, no
runtime configuration file. All state lives in the flags.

## Synopsis

```
nocturne-kx <subcommand> [<args>...] [<global-options>...]
```

Global options can appear anywhere on the line; they're filtered out
in a prescan before subcommand dispatch.

## Subcommands

| Subcommand          | Purpose                                                              |
|---------------------|----------------------------------------------------------------------|
| [`gen-receiver`](./gen-receiver) | Generate a receiver KEM keypair.                          |
| [`gen-signer`](./gen-signer)     | Generate a signer keypair (Ed25519 / hybrid / ML-DSA-87).|
| [`encrypt`](./encrypt)           | Encrypt a file into a Nocturne packet.                   |
| [`decrypt`](./decrypt)           | Decrypt a Nocturne packet back to plaintext.             |
| [`tls-send` / `tls-recv`](./tls) | Carry one packet over TLS 1.3.                            |
| [`audit-verify`](./audit-verify) | Verify the BLAKE2b chain of an audit log.                |
| `self-test`         | Run libsodium + KEM + signer sanity checks.                          |
| `security-check`    | Inspect file permissions, env vars, entropy.                          |
| `audit-log`         | Print the audit log header + last N records.                         |
| `rate-limit-status` | Inspect a rate-limit bucket.                                          |
| `rate-limit-reset`  | Reset a rate-limit bucket (auditable).                               |
| `memory-stats`      | Print secure-memory allocator statistics.                            |
| `hs-demo`           | SIGMA handshake demo over `MemoryTransport`.                          |
| `dr-demo`           | Double-ratchet encrypt/decrypt over `MemoryTransport`.               |

## Global options

| Flag                       | Effect                                                  |
|----------------------------|---------------------------------------------------------|
| `--rate-limit-store <path>`| Override the rate-limit DB path (default: `~/.nocturne/rl.db`). |
| `--audit-log <path>`       | Append every CLI action to this JSONL audit log.        |
| `--audit-sign-key <path>`  | Ed25519 SK file used to sign each audit record.         |
| `--audit-anchor <path>`    | External anchor blob (e.g. TSA token) per record.       |
| `--audit-worm-dir <dir>`   | Mirror each record to `<dir>/<seq>.json` (WORM).        |
| `--tpm-counter <path>`     | Bind the replay DB counter to a TPM-backed counter.     |
| `--hsm-pass <string>`      | Passphrase for `NCHSM2`-encrypted FileHSM secret keys.  |

The prescan also routes `--audit-worm-dir` into its own option slot
(P6.6 bug fix); prior versions silently aliased it onto `--audit-anchor`.

## Exit codes

| Code | Meaning                                                       |
|------|---------------------------------------------------------------|
| 0    | Success.                                                      |
| 1    | Usage error (bad flag, missing file).                          |
| 2    | Typed cryptographic / policy failure (auth fail, replay, etc.).|

The "replay" string in `stderr` is grep-stable for CI assertions. The
`[pqc]` and `[hsm]` CI suites both rely on it.

## Environment variables

| Variable                | Purpose |
|-------------------------|---------|
| `PKCS11_LIB`            | Path to the PKCS#11 provider shared library.            |
| `SOFTHSM2_CONF`         | SoftHSM2's config file (when using SoftHSM as provider).|
| `NOCTURNE_HSM_PIN`      | PIN for the PKCS#11 token.                              |
| `NOCTURNE_HSM_FIPS`     | `1` → refuse non-FIPS slots.                            |
| `NOCTURNE_HSM_PASSPHRASE` | Passphrase for `NCHSM2` FileHSM secret keys.          |
| `NOCTURNE_DISABLE_RANDOM_DELAY` | `1` → skip the 100-500 µs constant-time delay (testing only). |

## Stability promise

- Subcommand names: stable across the 4.x line.
- Flag names: additive — new flags may appear; existing flags don't
  change meaning.
- Wire format: governed by the packet `ver` byte, not the CLI version.
- Error codes (`src/core/error.hpp` integer values): never renumbered;
  the SIEM contract depends on them.

Anything *not* on that list (output text, progress messages, internal
JSON shapes) is best-effort.
