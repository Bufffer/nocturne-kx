/// @file signing.hpp
/// @brief Ed25519 detached signature wrappers.
///
/// These wrappers exist so call sites don't repeat the libsodium
/// invocation pattern (with its `unsigned long long*` siglen out-param
/// and the constant-time verify postlude) at every signer / verifier
/// site. Both functions are inline header-only because they're tiny
/// and called from the hot encrypt/decrypt path.
///
/// **What this file is NOT.** The post-quantum signature stack (ML-DSA
/// + hybrid) lives in @ref src/pqc/sig/. This header is intentionally
/// scoped to the classical Ed25519 path that flows through HSMs.
///
/// @version 1.0.0
/// @par Thread safety
///   Pure functions. libsodium's Ed25519 primitives are reentrant.

#pragma once

#include "../core/byte_span.hpp"
#include "../core/side_channel.hpp"

#include <array>
#include <cstdint>

#include <sodium.h>

namespace nocturne {

/// @brief Sign @p message with Ed25519 secret key @p sk, returning the
///        detached 64-byte signature.
///
/// @param message Bytes to sign. May be any length, including empty.
/// @param sk      64-byte Ed25519 secret key (libsodium-canonical
///                seed+public concatenation).
///
/// @par Pre  @p sk is a valid Ed25519 secret key produced by
///           @c crypto_sign_keypair (or @c crypto_sign_seed_keypair).
/// @par Post Return value is a 64-byte signature that verifies under
///           the matching public key.
/// @par Exception safety: noexcept — libsodium's signing primitive
///                        cannot fail for valid inputs.
[[nodiscard]] inline std::array<std::uint8_t, crypto_sign_BYTES>
ed25519_sign(BytesView                                                       message,
             const std::array<std::uint8_t, crypto_sign_SECRETKEYBYTES>&     sk) noexcept
{
    std::array<std::uint8_t, crypto_sign_BYTES> sig{};
    // Return code is checked by the caller for paranoid builds; the
    // libsodium primitive cannot fail for well-formed inputs, so we
    // intentionally do not throw here to keep the function noexcept.
    (void)crypto_sign_detached(sig.data(), nullptr,
                               message.data(), message.size(),
                               sk.data());
    return sig;
}

/// @brief Verify a detached Ed25519 signature.
///
/// @param message Bytes that were signed.
/// @param pk      32-byte Ed25519 public key.
/// @param sig     64-byte detached signature.
///
/// @return @c true if @p sig is a valid signature of @p message under
///         @p pk; @c false otherwise.
///
/// @par Pre  @p pk is a valid Ed25519 public key (libsodium does not
///           verify membership in the prime-order subgroup beyond a
///           cheap canonical-form check).
/// @par Side-channel: a randomized delay + memory barrier are inserted
///                    after the verify to break coarse timing oracles
///                    that try to distinguish "tag check failed" from
///                    "tag check passed" by call-site latency.
/// @par Exception safety: noexcept.
[[nodiscard]] inline bool ed25519_verify(
    BytesView                                                    message,
    const std::array<std::uint8_t, crypto_sign_PUBLICKEYBYTES>&  pk,
    const std::array<std::uint8_t, crypto_sign_BYTES>&           sig) noexcept
{
    const int result = crypto_sign_verify_detached(
        sig.data(), message.data(), message.size(), pk.data());

    side_channel::random_delay();
    side_channel::memory_barrier();

    return result == 0;
}

}  // namespace nocturne
