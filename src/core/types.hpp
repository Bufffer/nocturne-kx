/// @file types.hpp
/// @brief Core value types shared across the Nocturne-KX library:
///        classical key-pair structs (X25519 / Ed25519), the project's
///        exception hierarchy, and the libsodium initializer.
///
/// **Scope discipline.** This header is the foundation for the
/// `protocol` and `cli` layers. It deliberately depends only on
/// libsodium + standard library — no third-party crypto, no audit
/// logger, no CLI parsing. New value types added here must keep that
/// invariant.
///
/// @version 1.0.0

#pragma once

#include "byte_span.hpp"

#include <array>
#include <cstddef>
#include <stdexcept>
#include <string>
#include <utility>

#include <sodium.h>

namespace nocturne {

// -----------------------------------------------------------------------
// Classical key pairs
// -----------------------------------------------------------------------

/// @brief X25519 (Curve25519 ECDH) key pair, 32-byte pk / 32-byte sk.
///
/// Backing storage is `std::array` so the size is encoded in the type
/// and `sizeof(X25519KeyPair)` is a compile-time constant. Fields are
/// public for ergonomic structured-binding access; treat the type as a
/// value-semantic record. Secret keys are NOT auto-zeroed on
/// destruction — call sites that hold long-lived sks must wrap them in
/// `memory_protection::SecureMemory` or call
/// `side_channel::secure_zero_memory` explicitly before drop.
struct X25519KeyPair {
    std::array<std::uint8_t, crypto_kx_PUBLICKEYBYTES> pk{};
    std::array<std::uint8_t, crypto_kx_SECRETKEYBYTES> sk{};
};

/// @brief Ed25519 (signature) key pair, 32-byte pk / 64-byte sk.
///
/// libsodium's Ed25519 SK is 64 bytes because it includes the public
/// key concatenated to the seed half — keeping that layout because
/// `crypto_sign_detached` expects it.
struct Ed25519KeyPair {
    std::array<std::uint8_t, crypto_sign_PUBLICKEYBYTES> pk{};
    std::array<std::uint8_t, crypto_sign_SECRETKEYBYTES> sk{};
};

// -----------------------------------------------------------------------
// Exception hierarchy
// -----------------------------------------------------------------------

/// @brief Root exception type for system-fault paths.
///
/// `Result<T>` carries recoverable failures; this hierarchy carries the
/// remaining "should never happen at steady state" conditions: libsodium
/// init failure, file-system I/O at startup, std::bad_alloc paths that
/// callers can't recover from.
///
/// Catch this type at the CLI's top-level handler and convert to an
/// audit-log entry + non-zero process exit.
class NocturneError : public std::runtime_error {
  public:
    explicit NocturneError(const std::string& msg)
        : std::runtime_error{msg} {}
};

/// @brief HSM-specific system fault — token unreachable, library load
///        failed, PKCS#11 device error.
class HSMError : public NocturneError {
  public:
    explicit HSMError(const std::string& m) : NocturneError{m} {}
};

/// @brief Cryptographic-primitive system fault — libsodium reported a
///        non-zero return from a primitive that should never fail given
///        valid inputs.
class CryptoError : public NocturneError {
  public:
    explicit CryptoError(const std::string& m) : NocturneError{m} {}
};

/// @brief File-system / stream I/O system fault.
class IOError : public NocturneError {
  public:
    explicit IOError(const std::string& m) : NocturneError{m} {}
};

// -----------------------------------------------------------------------
// libsodium initialization
// -----------------------------------------------------------------------

/// @brief Ensure libsodium has been initialized. Idempotent.
///
/// libsodium's `sodium_init()` is internally re-entrant but the
/// project's convention is to call this helper at every public-API
/// entry point so initialization order is never load-bearing.
///
/// @par Thread safety: Safe to call concurrently (libsodium's sodium_init
///                     handles concurrent first-call internally).
/// @par Exception safety: Throws @ref NocturneError on init failure. No
///                        partial state — sodium_init either succeeds
///                        globally or it doesn't.
inline void check_sodium() {
    if (sodium_init() < 0) {
        throw NocturneError{"sodium_init failed"};
    }
}

}  // namespace nocturne
