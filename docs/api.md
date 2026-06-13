---
title: C++ API reference
description: Auto-generated Doxygen reference for all public headers in Nocturne-KX.
---

# C++ API reference

The full API reference is generated from source headers by Doxygen on every push to `main`. It covers all public interfaces in `src/`: `KEMInterface`, `SignatureScheme`, `HSMInterface`, `ReplayDB`, `AuditLogger`, `Session`, `TrustStore`, and the protocol primitives.

<a href="/nocturne-kx/doxygen/index.html" target="_blank" rel="noopener" class="nx-api-link">
  Browse C++ API reference
</a>

## Key namespaces

| Namespace | Contents |
|---|---|
| `nocturne::pqc` | `KEMInterface`, `KEMFactory`, `HybridKEM`, `MLKEMWrapper`, `SignatureScheme`, `SignatureFactory`, `HybridSig`, `MLDSAWrapper` |
| `nocturne::hsm` | `HSMInterface`, `PKCS11HSM`, `FileHSM`, `HSMError`, `KeyPolicy`, `KeyRotationManager` |
| `nocturne::security` | `AuditLogger`, `SIEMConnector`, `KeyRotationManager` |
| `nocturne::protocol` | `Packet`, `encrypt_packet`, `decrypt_packet`, `EncryptOptions`, `DecryptOptions` |
| `nocturne::side_channel` | `secure_zero_memory`, `constant_time_compare`, `ct_select`, `flush_cache_line` |
| `nocturne` (root) | `Result<T>`, `Error`, `ErrorCode`, `BytesView`, `MutableBytesView`, `Session`, `TrustStore` |

## Important types

**`Result<T>`** (`src/core/result.hpp`) — every fallible operation returns this. It is an alias for `std::expected<T, Error>`. The `Error` struct carries an `ErrorCode` (stable integer for SIEM), a human-readable message, and an optional nested cause.

**`BytesView` / `MutableBytesView`** (`src/core/byte_span.hpp`) — non-owning byte spans used across all interfaces instead of raw pointer + size pairs.

**`KEMInterface`** (`src/pqc/kem/kem_interface.hpp`) — abstract KEM. `encapsulate(pk)` returns ciphertext + shared secret; `decapsulate(sk, ct)` returns the shared secret. All methods are `[[nodiscard]]`.

**`SignatureScheme`** (`src/pqc/sig/sig_interface.hpp`) — abstract signer. `sign(sk, message)` returns a signature; `verify(pk, message, sig)` returns `Result<bool>`.

**`HSMInterface`** (both `src/hsm/hsm_interface.hpp` enterprise and `src/hsm/inline/hsm_interface.hpp` CLI) — abstract key store. The enterprise version adds rotation, audit trail, and policy; the CLI version is the subset the binary actually calls.

**`ReplayDB`** (`src/security/inline/replay_db.hpp`) — AEAD-encrypted, MAC-authenticated, atomically-written on-disk counter store. `has_seen` + `record` are the two entry points.

<style scoped>
.nx-api-link {
  display: inline-block;
  margin: 24px 0;
  padding: 12px 24px;
  background: var(--vp-c-brand-soft);
  border: 1px solid var(--vp-c-brand-2);
  border-radius: 8px;
  color: var(--vp-c-brand-1);
  font-weight: 600;
  text-decoration: none;
  transition: background 150ms, border-color 150ms;
}
.nx-api-link:hover {
  background: var(--vp-c-brand-soft);
  border-color: var(--vp-c-brand-1);
}
</style>
