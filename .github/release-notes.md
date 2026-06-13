## Nocturne-KX v1.0.0-alpha

First tagged release of Nocturne-KX, a C++23 hybrid post-quantum cryptographic toolkit built on libsodium and liboqs.

> **This is an alpha release. No independent security audit has been conducted. Do not deploy in production without a formal security review.**

### What's included

- **Hybrid PQC KEM** — X25519 + ML-KEM-1024 (NIST FIPS 203) via SP 800-56C R2 combiner. Also supports classical-only and pure ML-KEM modes.
- **Hybrid PQC signatures** — Ed25519 + ML-DSA-87 (NIST FIPS 204). Both halves must verify.
- **Bidirectional replay protection** — per-session monotonic counters, AEAD-encrypted and MAC-authenticated on disk, atomic `rename(2)` writes.
- **PKCS#11 HSM integration** — full OASIS v2.40 `CK_FUNCTION_LIST`, validated against SoftHSM2 in CI. Compatible with Thales Luna, Utimaco, YubiHSM2, AWS CloudHSM.
- **BLAKE2b hash-chained audit log** — optional per-record Ed25519 signatures, WORM directory mirroring, `audit-verify` CLI command.
- **TLS 1.3 transport** — `tls-send` / `tls-recv` CLI subcommands, optional mTLS, SNI.
- **SIGMA handshake + Double Ratchet** — for long-lived bidirectional sessions.
- **Complete documentation site** — [bufffer.github.io/nocturne-kx](https://bufffer.github.io/nocturne-kx/)

### Linux binary

The attached `nocturne-kx-linux-x86_64` is built on Ubuntu 24.04 with `-DENABLE_HARDENING=ON -DENABLE_LTO=ON`. Runtime dependencies: `libsodium`, `libssl`, `libcrypto`. liboqs is statically linked via FetchContent.

Verify the download:
```bash
sha256sum -c nocturne-kx-linux-x86_64.sha256
```

Smoke test:
```bash
chmod +x nocturne-kx-linux-x86_64
./nocturne-kx-linux-x86_64 self-test
```

### Build from source

See the [Quickstart guide](https://bufffer.github.io/nocturne-kx/guide/quickstart) for full instructions.

```bash
git clone https://github.com/Bufffer/nocturne-kx.git
cd nocturne-kx
cmake -B build -DCMAKE_BUILD_TYPE=Release -DENABLE_PQC=ON -DENABLE_TLS_TRANSPORT=ON
cmake --build build -j
./build/nocturne-kx self-test
```

### Security notice

This software has **not undergone independent security audit or penetration testing**. It is provided for research, evaluation, and prototyping. All cryptographic operations go through libsodium or liboqs — no hand-rolled primitives exist in `src/`.

To report a vulnerability: **serdarogluibrahim@gmail.com**. Do not open a public issue.

### What's next (v1.1)

- SIEM HTTP transports (Splunk HEC, Elasticsearch, Kafka)
- Independent security audit
- macOS and Windows pre-built binaries

---

Full changelog: [CHANGELOG.md](https://github.com/Bufffer/nocturne-kx/blob/main/CHANGELOG.md)
Documentation: [bufffer.github.io/nocturne-kx](https://bufffer.github.io/nocturne-kx/)
Author: Halil Ibrahim Serdaroglu
