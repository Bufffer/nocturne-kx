/// @file aead.hpp
/// @brief XChaCha20-Poly1305 AEAD encrypt / decrypt wrappers.
///
/// libsodium's `crypto_aead_xchacha20poly1305_ietf_*` family is the
/// project's authenticated-encryption primitive. These helpers wrap the
/// libsodium calls in:
///   - std::span input/output (no raw ptr+size pairs at the API).
///   - Typed `Result<Bytes>` failures (no exceptions on the protocol
///     path — see @ref result.hpp for the throw-vs-Result contract).
///   - Distinct @ref ErrorCode values so audit logs and SIEM events can
///     distinguish length-validation rejects from cryptographic rejects.
///
/// **Nonce policy.** XChaCha20-Poly1305 has a 192-bit nonce — large
/// enough to allow random generation per packet without a birthday
/// collision risk under realistic message volumes. Nocturne always
/// generates the nonce with `randombytes_buf` immediately before
/// encryption. The caller passes the nonce in explicitly here so this
/// header doesn't depend on the RNG strategy.
///
/// @version 2.0.0 (P6.1a: throws → Result<Bytes>)
/// @par Thread safety
///   Pure functions. Safe to call concurrently with disjoint inputs.
///   The libsodium primitives themselves are reentrant.

#pragma once

#include "../core/byte_span.hpp"
#include "../core/result.hpp"

#include <array>
#include <cstdint>

#include <sodium.h>

namespace nocturne {

/// @brief AEAD nonce — 24 bytes for XChaCha20-Poly1305.
using AeadNonce = std::array<std::uint8_t, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES>;

/// @brief Encrypt @p plaintext under @p key + @p nonce with @p aad
///        authenticated alongside.
///
/// @return Ciphertext including the trailing 16-byte Poly1305 tag, or
///         @c ErrorCode::Internal if libsodium reports a primitive
///         failure (should never happen for valid inputs).
///
/// @param key       32-byte AEAD key. Must be unpredictable to the
///                  adversary.
/// @param nonce     24-byte nonce. MUST be unique per @p key — reuse
///                  trivially breaks confidentiality.
/// @param aad       Additional authenticated data. Authenticated but
///                  not encrypted; recipients see plaintext.
/// @param plaintext Plaintext bytes to encrypt.
///
/// @pre  @p key has been freshly derived (not reused with a stale
///       nonce).
/// @post On success the returned buffer has size
///       `plaintext.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES`.
/// @par Exception safety
///   No-throw on the protocol path — all failures are reported through
///   the Result. Only `std::bad_alloc` from the output-buffer
///   allocation can propagate (system fault, per the project contract).
[[nodiscard]] inline Result<Bytes> aead_encrypt_xchacha(
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
        return err(ErrorCode::Internal, "aead encrypt failed");
    }

    ct.resize(static_cast<std::size_t>(ct_len));
    return ct;
}

/// @brief Decrypt @p ciphertext under @p key + @p nonce, authenticating
///        @p aad.
///
/// @return Plaintext bytes (size = ct.size() - 16), or:
///         - @c ErrorCode::PacketTruncated — @p ciphertext shorter than
///           the Poly1305 tag (length-validation reject),
///         - @c ErrorCode::AeadAuthFailed — tag verification failed
///           (tampering / wrong key / wrong nonce / wrong AAD).
///
/// @pre  None — adversarial input is an expected, typed outcome.
/// @post On success the returned buffer has size
///       `ciphertext.size() - crypto_aead_xchacha20poly1305_ietf_ABYTES`.
/// @par Exception safety
///   No-throw on the protocol path; only `std::bad_alloc` from the
///   output-buffer allocation can propagate.
[[nodiscard]] inline Result<Bytes> aead_decrypt_xchacha(
    const std::array<std::uint8_t, crypto_aead_xchacha20poly1305_ietf_KEYBYTES>& key,
    const AeadNonce&                                                              nonce,
    BytesView                                                                     aad,
    BytesView                                                                     ciphertext)
{
    if (ciphertext.size() < crypto_aead_xchacha20poly1305_ietf_ABYTES) {
        return err(ErrorCode::PacketTruncated, "ciphertext too short");
    }

    Bytes pt(ciphertext.size() - crypto_aead_xchacha20poly1305_ietf_ABYTES);
    unsigned long long pt_len = 0;

    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            pt.data(), &pt_len,
            nullptr,
            ciphertext.data(), ciphertext.size(),
            aad.empty() ? nullptr : aad.data(), aad.size(),
            nonce.data(), key.data()) != 0) {
        return err(ErrorCode::AeadAuthFailed, "aead decrypt failed (auth)");
    }

    pt.resize(static_cast<std::size_t>(pt_len));
    return pt;
}

}  // namespace nocturne
