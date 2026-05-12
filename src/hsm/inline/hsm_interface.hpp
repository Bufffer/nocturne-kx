/// @file hsm_interface.hpp
/// @brief Inline (CLI-facing) HSM abstract base class.
///
/// **Scope.** This is the *thin* HSMInterface that the CLI consumes
/// via `--sign-hsm-uri`. It is **NOT** the same type as
/// `nocturne::hsm::HSMInterface` declared in
/// `src/hsm/hsm_interface.hpp` — that is the enterprise variant with
/// rotation, audit-trail, and key-policy machinery. The two
/// hierarchies coexist; the inline one wraps the enterprise one when
/// the CLI is configured for PKCS#11 (see @ref pkcs11_adapter.hpp).
///
/// Concrete subclasses: @ref FileHSM (file-backed Ed25519 SK) and
/// @ref PKCS11HSM (PKCS#11 token adapter).
///
/// @par Thread safety
///   The abstract base imposes no contract; concrete subclasses
///   document their own thread-safety guarantees.
/// @par Exception safety
///   sign() throws @ref nocturne::HSMError if the underlying HSM is in
///   a bad state. Other methods are noexcept on the happy path; they
///   return false / nullopt on failure rather than throwing.

#pragma once

#include "../../core/types.hpp"

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include <sodium.h>

/// @brief Inline HSMInterface — global namespace for backward compat
///        with the CLI's existing call sites. (The enterprise variant
///        lives in @c nocturne::hsm::HSMInterface.)
struct HSMInterface {
    /// @brief Sign @p data with this HSM's Ed25519 key.
    /// @return 64-byte detached signature.
    virtual std::array<std::uint8_t, crypto_sign_BYTES>
        sign(const std::uint8_t* data, std::size_t len) = 0;

    /// @brief Fetch the HSM's Ed25519 public key. nullopt if unavailable.
    [[nodiscard]] virtual std::optional<std::array<std::uint8_t, crypto_sign_PUBLICKEYBYTES>>
        get_public_key() = 0;

    /// @brief Whether the HSM holds a key under @p label.
    [[nodiscard]] virtual bool has_key(const std::string& label) = 0;

    /// @brief HSM-provided random bytes. Falls back to libsodium if the
    ///        underlying device cannot serve the request.
    [[nodiscard]] virtual std::vector<std::uint8_t>
        generate_random(std::size_t length) = 0;

    /// @brief Liveness probe — quick check that the HSM is reachable
    ///        and the key cache is valid.
    [[nodiscard]] virtual bool is_healthy() = 0;

    virtual ~HSMInterface() = default;
};
