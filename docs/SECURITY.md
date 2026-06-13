---
title: Security reference
description: Cryptographic assumptions, hardening checklist, and what Nocturne-KX does and does not protect against.
---

# Security reference

For the full adversary model and in-scope/out-of-scope decisions, read the [threat model](./guide/threat-model). This document covers what you need to verify in a deployment.

## Cryptographic assumptions

Nocturne-KX's security rests on these hardness assumptions holding simultaneously:

| Layer | Primitive | Assumption |
|---|---|---|
| Classical KEM | X25519 | CDH in Curve25519 |
| PQ KEM | ML-KEM-1024 (NIST FIPS 203) | Module-LWE |
| KEM combiner | SP 800-56C R2 HKDF-SHA-256 | Hybrid-safe: one component breaking does not break the combined secret |
| AEAD | XChaCha20-Poly1305 | Indistinguishable under chosen ciphertext, 256-bit key, 192-bit nonce |
| Classical signatures | Ed25519 (RFC 8032, deterministic) | ECDLP in Edwards25519 |
| PQ signatures | ML-DSA-87 (NIST FIPS 204) | Module-LWE, security level 5 |
| Hash / MAC | BLAKE2b-256 | Collision resistance |
| KDF | HKDF-SHA-256 | PRF security of HMAC-SHA-256 |

Every operation goes through libsodium or liboqs. No hand-rolled primitive exists anywhere in `src/`. If a code review surfaces one, open an issue immediately.

## Production hardening checklist

**Key material**
- [ ] Secret keys stored at mode 0600, owned by the nocturne service account.
- [ ] Production keys provisioned inside an HSM; never exported to disk. See [HSM guide](./guide/hsm).
- [ ] `NOCTURNE_HSM_PASSPHRASE` set via `EnvironmentFile`, not on the command line (it would appear in `ps` output).
- [ ] Audit signing key kept offline or in a separate HSM slot; only the verifier's public key lives on the server.

**Replay database**
- [ ] `replay.db.macsk` at mode 0600, separate directory from the DB file.
- [ ] DB backed up daily; recovery procedure tested.
- [ ] Single-writer enforced: no two processes share the same DB path.

**Audit log**
- [ ] Append-only filesystem mount or S3 Object Lock for `/var/log/nocturne/`.
- [ ] `audit-verify` run nightly via cron; alert on non-zero exit.
- [ ] SIEM forwarding enabled for `ReplayDetected` and `AeadAuthFailed` events.

**Process isolation**
- [ ] `NoNewPrivileges=true`, `PrivateTmp=true`, `ProtectSystem=strict` in the systemd unit.
- [ ] `NOCTURNE_DISABLE_RANDOM_DELAY` must be unset in production.

**Network**
- [ ] TLS 1.3 enforced for all `tls-send` / `tls-recv` sessions; `ENABLE_TLS_TRANSPORT=ON` at build time.
- [ ] mTLS (`--require-client-cert`) for service-to-service communication.

## What Nocturne-KX does not protect against

- **Endpoint compromise.** If the process's memory is readable by an attacker, session keys are exposed. Secure enclaves (SGX, TrustZone) are out of scope.
- **Network metadata.** Packet sizes and timing are observable. Traffic analysis is not addressed.
- **Denial of service.** A rate-limit token bucket is wired in, but a determined attacker can exhaust it or flood below the threshold.
- **Compromised HSM PIN.** If an attacker obtains the HSM PIN and physical/network access to the token, they can sign arbitrary messages. Dual-control rotation requires two operators, which raises the bar but does not eliminate the risk.
- **Quantum breaks on classical components.** In hybrid mode, breaking ML-KEM-1024 alone does not recover the combined secret, but the classical X25519 component is not quantum-safe. Pure `--kem mlkem1024` mode removes the classical dependency at the cost of interoperability with non-PQC peers.

## Reporting vulnerabilities

Email **serdarogluibrahim@gmail.com** with a description and reproduction steps. Do not open a public GitHub issue. You will receive a response within 72 hours. Credit will be given in CHANGELOG.md upon fix.
