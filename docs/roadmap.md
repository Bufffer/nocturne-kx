---
title: Roadmap
description: What's shipped, what's in flight, and what's deferred for Nocturne-KX.
---

# Roadmap

A condensed view of the project plan. The authoritative source is
in `memory/roadmap.md`; this page summarises what's reached `main`.

## Shipped

### P1: Blockers (May 2026)

- PKCS#11 mechanism rewire (`CKM_ECDSA` → `CKM_EDDSA`).
- Full `RatchetSessionManager` + `RatchetProtocol` in
  `src/double_ratchet.hpp` (~483 LOC). `DRS1` persistence header.
- Inline `PKCS11HSM` rewritten as adapter to the enterprise
  `nocturne::hsm::PKCS11HSM` via env vars.
- CI compile fixes for mutable mutexes, missing CK_TRUE, dlopen.
- Fuzzer ABI fix (drop `-stdlib=libc++`, libFuzzer is libstdc++ on Ubuntu).

### P2: Production wiring (May 2026)

- **P2.5** TCP/TLS transport (`TlsAcceptor` + `TcpTlsTransport`)
  with TLS 1.3 only, optional mTLS, 4-byte BE length framing.
- **P2.6** SIEM real-network sends, UDP / TCP / CEF / LEEF.
- **P2.7** `AuditLogger::verify_chain()`, full implementation,
  ~337 LOC; minimal hand-rolled JSON parser tailored to the writer.
- **P2.8** PQC KEM in CLI, `FLAG_HAS_PQC_KEM = 0x04`, `--kem`
  flag, auto-detect on decrypt.

### P3: Cleanup (May 2026)

- Strip hard-coded `C:/Users/Maxval/...` paths; portable
  `LIBOQS_ROOT` discovery.
- PQC encrypt+decrypt roundtrip CI gate.
- Delete legacy `src/pkcs11_wrapper.{hpp,cpp}` (−363 lines).
- Merge `CMakeLists_new.txt` into the canonical one.
- `audit_log::verify_chain()` (the inline-CLI flavour) + `audit-verify`.
- `src/hsm/file_hsm.hpp` + `KeyRotationManager` wired.
- SIEM `SYSLOG_TLS` via OpenSSL.

### P4: Post-quantum signatures (May 2026)

- ML-DSA-87 (NIST FIPS 204 Level 5) + hybrid Ed25519+ML-DSA-87.
- `FLAG_HAS_PQC_SIG = 0x08`, `--pqc-sign-key` / `--pqc-sig-type`.
- Must-pass `[pqc-sig]` CI gate.

### P5: Modularisation (June 2026)

Wire format, KDF, AEAD, signing, KEM, HSM, audit, replay all
extracted to `src/protocol/`, `src/pqc/`, `src/hsm/`,
`src/security/` modules. `Result&lt;T&gt;` / `BytesView` foundations
introduced.

### P6: Code-quality series (June 2026)

- **P6.1a/b** `Result&lt;T&gt;` migration across protocol + messaging.
- **P6.2** `inline constexpr` instead of macros.
- **P6.3** `BytesView` everywhere ptr+size used to live.
- **P6.4** Compile-time wire invariants (`static_assert`).
- **P6.5** `[[nodiscard]]` sweep across all 4 polymorphic interfaces.
- **P6.6** CLI arg-parsing DRY helpers; `@pre`/`@post` docs.

### P7: v1.0 closure (June 2026)

- **P7.0** SoftHSM CI integration test wired.
- **P7.1** Full OASIS PKCS#11 v2.40 `CK_FUNCTION_LIST` layout.
  Fixed the bug P7.0 caught.
- **P7.2** NOTICE refresh: OpenSSL + SoftHSM2 attributions; copyright
  span widened to 2025–2026.

## In flight

### P7.3: API documentation site (this site)

You're reading it. Phase A delivered the foundation: hero, feature
grid, quickstart, threat model, architecture, wire format with
interactive viewer, HSM / replay / audit / TLS guides, PQC overview
plus per-mode pages, CLI reference for every subcommand. Phase B
will add Doxygen-backed C++ API ref and deeper how-to content.

## Deferred

### P7.4: SIEM HTTP transports

Splunk HEC, Elasticsearch, generic webhook (requires libcurl), and
Kafka (requires librdkafka). Currently throw clean "not yet wired"
runtime errors so the build stays light. Likely a v1.1 decision.

## Live demos (not in repo)

Two end-to-end demos run on the maintainer's GitHub Codespace:

- **`demo.sh`**, "İki Ajan, Bir Sır": three encryption modes
  (X25519, hybrid, hybrid + Ed25519 sig); three attacks rejected
  (wrong signer, wrong key type, tampered ciphertext).
- **`test2.sh`**, "Mallory's Replay Attack": `ReplayDB` rejects a
  re-sent packet; bidirectional replay protection works in practice.

These live on the Codespace, not the repo. They've caught at least
one bug a CI matrix couldn't (commit `9b5c00b`).
