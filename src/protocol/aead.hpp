/// @file aead.hpp
/// @brief XChaCha20-Poly1305 AEAD encrypt / decrypt wrappers.
///
/// libsodium's `crypto_aead_xchacha20poly1305_ietf_*` family is the
/// project's authenticated-encryption primitive. These helpers wrap the
/// libsodium calls in:
///   - std::span input/output (no raw ptr+size pairs at the API).
///   - Strong exception safety: either the function returns a valid
///     buffer or it throws and leaves the caller's state untouched.
///   - Explicit "ciphertext too short" / "auth tag failed" diagnostics
///     so audit logs and SIEM events can distinguish length-validation
///     rejects from cryptographic rejects.
///
/// **Nonce policy.** XChaCha20-Poly1305 has a 192-bit nonce — large
/// enough to allow random generation per packet without a birthday
/// collision risk under realistic message volumes. Nocturne always
/// generates the nonce with `randombytes_buf` immediately before
/// encryption. The caller passes the nonce in explicitly here so this
/// header doesn't depend on the RNG strategy.
///
/// @version 1.0.0
/// @par Thread safety
///   Pure functions. Safe to call concurrently with disjoint inputs.
///   The libsodium primitives themselves are reentrant.

#pragma once

#include "../core/byte_span.hpp"

#include <array>
#include <cstdint>
#include <stdexcept>

#include <sodium.h>

namespace nocturne {

/// @brief AEAD nonce — 24 bytes for XChaCha20-Poly1305.
using AeadNonce = std::array<std::uint8_t, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES>;

/// @brief Encrypt @p plaintext under @p key + @p nonce with @p aad
///        authenticated alongside.
///
/// @return Ciphertext including the trailing 16-byte Poly1305 tag.
///
/// @param key       32-byte AEAD key. Must be unpredictable to the
///                  adversary.
/// @param nonce     24-byte nonce. MUST be unique per @p key — reuse
///                  trivially breaks confidentiality.
/// @param aad       Additional authenticated data. Authenticated but
///                  not encrypted; recipients see plaintext.
/// @param plaintext Plaintext bytes to encrypt.
///
/// @par Pre  @p key has been freshly derived (not reused with a stale
///           nonce).
/// @par Post Returned buffer has size `plaintext.size() + 16`.
/// @par Exception safety: Strong. Throws @c std::runtime_error on
///                        libsodium failure (should never happen for
///                        valid inputs).
[[nodiscard]] inline Bytes aead_encrypt_xchacha(
    const std::array<std::uint8_t, crypto_aead_xchacha20poly1305_ietf_KEYBYTES>& key,
    const AeadNonce&                                                              nonce,
    BytesView                                                                     aad,
    BytesView                                                                     plaintext)
{
    Bytes ct(plaintext.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES);
    unsigned long long ct_len = 0;

    if (crypto_aead_xchacha20poly1305_ietf_encrypt(
            ct.data(), &ct_len,
            plaintext.data(), plaintext.size(),
            aad.empty() ? nullptr : aad.data(), aad.size(),
            nullptr,
            nonce.data(), key.data()) != 0) {
        throw std::runtime_error{"aead encrypt failed"};
    }

    ct.resize(static_cast<std::size_t>(ct_len));
    return ct;
}

/// @brief Decrypt @p ciphertext under @p key + @p nonce, authenticating
///        @p aad.
///
/// @return Plaintext bytes (size = ct.size() - 16).
///
/// @par Pre  @p ciphertext is at least @c crypto_aead_xchacha20poly1305_ietf_ABYTES
///           bytes (the Poly1305 tag length).
/// @par Post Returned buffer has size `ciphertext.size() - 16` when
///           the tag verifies.
/// @par Exception safety: Strong. Throws @c std::runtime_error on:
///                          - too-short ciphertext (no room for the tag),
///                          - authentication failure (tampering / wrong
///                            key / wrong nonce / wrong AAD).
[[nodiscard]] inline Bytes aead_decrypt_xchacha(
    const std::array<std::uint8_t, crypto_aead_xchacha20poly1305_ietf_KEYBYTES>& key,
    const AeadNonce&                                                              nonce,
    BytesView                                                                     aad,
    BytesView                                                                     ciphertext)
{
    if (ciphertext.size() < crypto_aead_xchacha20poly1305_ietf_ABYTES) {
        throw std::runtime_error{"ciphertext too short"};
    }

    Bytes pt(ciphertext.size() - crypto_aead_xchacha20poly1305_ietf_ABYTES);
    unsigned long long pt_len = 0;

    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            pt.data(), &pt_len,
            nullptr,
            ciphertext.data(), ciphertext.size(),
            aad.empty() ? nullptr : aad.data(), aad.size(),
            nonce.data(), key.data()) != 0) {
        throw std::runtime_error{"aead decrypt failed (auth)"};
    }

    pt.resize(static_cast<std::size_t>(pt_len));
    return pt;
}

}  // namespace nocturne
