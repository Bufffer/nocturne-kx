/// @file kdf.hpp
/// @brief Key-derivation primitives used by the Nocturne-KX protocol:
///        session-key derivation from X25519 ECDH, ratchet mixing, and
///        the BLAKE2b-based "session bytes → AEAD key" KDF that bridges
///        them.
///
/// **Why header-only.** Each function is a thin wrapper over libsodium
/// (1–3 libsodium calls + zeroization), called from a handful of sites
/// on the hot encrypt/decrypt path. Inlining gives the compiler a
/// chance to merge the libsodium call sequence with the surrounding
/// AEAD bookkeeping without an extra TU boundary.
///
/// **Error contract.** All functions return `Result<AeadKey>`; libsodium
/// primitive failures map to @ref ErrorCode::AeadKeyDerivationFailed
/// (hash/KDF stage) or @ref ErrorCode::KeyAgreementFailed (X25519
/// session stage). No exceptions on the protocol path.
///
/// **Domain separation.** Every KDF here uses a literal info string
/// (`"nocturne-tx-v3"`, `"nocturne-ratchet-v3"`, `"nocturne-kem-tx-v4"`)
/// bound into the BLAKE2b key argument. The strings are part of the
/// wire contract — changing one breaks compatibility with peers using
/// the old derivation. Tag new strings with the protocol version they
/// land in.
///
/// @version 2.0.0 (P6.1a: throws → Result<AeadKey>)
/// @par Thread safety
///   All functions are pure (no shared mutable state). Concurrent calls
///   with disjoint inputs are safe.

#pragma once

#include "../core/byte_span.hpp"
#include "../core/result.hpp"
#include "../core/side_channel.hpp"

#include <array>
#include <cstdint>
#include <string_view>

#include <sodium.h>

namespace nocturne {

/// @brief AEAD key (XChaCha20-Poly1305) — 32 bytes.
using AeadKey = std::array<std::uint8_t, crypto_aead_xchacha20poly1305_ietf_KEYBYTES>;

// -----------------------------------------------------------------------
// BLAKE2b session-bytes → AEAD key
// -----------------------------------------------------------------------

/// @brief Derive an AEAD key from arbitrary "session bytes" via BLAKE2b.
///
/// Used to fold libsodium's `crypto_kx_*_session_keys` output (or any
/// shared-secret bytes) into the AEAD key schedule with a domain-
/// separator @p info string. The info string is part of the wire
/// contract — both sides MUST agree.
///
/// @param session  Read-only view over the raw shared-secret bytes.
/// @param info     Domain separator. Treated as raw bytes (no NUL).
///
/// @pre  @p session is non-empty.
/// @post On success the value is the 32-byte BLAKE2b digest keyed by
///       @p session over @p info.
/// @return @c ErrorCode::AeadKeyDerivationFailed if libsodium returns
///         non-zero (cryptographic primitive failure — should never
///         happen for valid inputs).
/// @par Exception safety
///   No-throw on the protocol path; only allocation of the error
///   message string on the failure branch could throw `std::bad_alloc`.
[[nodiscard]] inline Result<AeadKey>
derive_aead_key_from_session(BytesView session, std::string_view info) {
    AeadKey k{};
    if (crypto_generichash(k.data(), k.size(),
                           session.data(), session.size(),
                           reinterpret_cast<const std::uint8_t*>(info.data()),
                           info.size()) != 0) {
        return err(ErrorCode::AeadKeyDerivationFailed, "key derivation failed");
    }
    return k;
}

// -----------------------------------------------------------------------
// X25519 → AEAD session keys
// -----------------------------------------------------------------------
//
// `derive_tx_key_client` and `derive_rx_key_server` are the symmetric
// pair: client (sender) derives a TX key with its ephemeral keypair +
// receiver pk; server (receiver) derives the matching RX key with its
// long-term keypair + sender ephemeral pk. By libsodium contract:
//   client_tx == server_rx  iff  (eph_pk, eph_sk) is a valid keypair
//                          and  (recv_pk, recv_sk) is too.
//
// Side-channel hooks: each call flushes the cache line holding the
// caller's secret key and inserts a random delay before zeroizing the
// intermediate `tx`/`rx` arrays. The delays are not constant-time per
// se — they're noise injected to defeat coarse timing oracles.
// -----------------------------------------------------------------------

using X25519PublicKey = std::array<std::uint8_t, crypto_kx_PUBLICKEYBYTES>;
using X25519SecretKey = std::array<std::uint8_t, crypto_kx_SECRETKEYBYTES>;

/// @brief Client-side: derive the sender's TX AEAD key.
///
/// @param pk_eph      Sender's ephemeral public key.
/// @param sk_eph      Sender's ephemeral secret key.
/// @param pk_receiver Receiver's long-term public key.
///
/// @pre  All three inputs are valid X25519 keypair material. Caller
///       is responsible for keypair validation; libsodium's session-
///       keys helper does basic sanity but not certificate-style
///       ownership proof.
/// @return @c ErrorCode::KeyAgreementFailed if libsodium rejects the
///         session-key computation; otherwise propagates the BLAKE2b
///         stage's result.
/// @par Exception safety
///   No-throw on the protocol path. Intermediate session keys are
///   zeroized on every exit path, success or failure.
/// @par Side-channel
///   flush_cache_line + random_delay + secure_zero on intermediates.
[[nodiscard]] inline Result<AeadKey> derive_tx_key_client(
    const X25519PublicKey& pk_eph,
    const X25519SecretKey& sk_eph,
    const X25519PublicKey& pk_receiver)
{
    std::array<std::uint8_t, crypto_kx_SESSIONKEYBYTES> rx{}, tx{};
    if (crypto_kx_client_session_keys(rx.data(), tx.data(),
                                      pk_eph.data(), sk_eph.data(),
                                      pk_receiver.data()) != 0) {
        return err(ErrorCode::KeyAgreementFailed, "kx client session failed");
    }

    side_channel::flush_cache_line(sk_eph.data());
    side_channel::random_delay();

    auto k = derive_aead_key_from_session(BytesView{tx.data(), tx.size()},
                                          std::string_view{"nocturne-tx-v3"});

    side_channel::secure_zero_memory(rx.data(), rx.size());
    side_channel::secure_zero_memory(tx.data(), tx.size());
    side_channel::flush_cache_line(rx.data());
    side_channel::flush_cache_line(tx.data());

    return k;
}

/// @brief Server-side: derive the receiver's RX AEAD key.
///
/// Uses the *same* domain-separator string as @ref derive_tx_key_client
/// so the resulting keys are equal — that's the entire point of the
/// session-keys protocol. Error contract and side-channel behavior
/// mirror @ref derive_tx_key_client.
[[nodiscard]] inline Result<AeadKey> derive_rx_key_server(
    const X25519PublicKey& pk_sender_eph,
    const X25519PublicKey& pk_receiver,
    const X25519SecretKey& sk_receiver)
{
    std::array<std::uint8_t, crypto_kx_SESSIONKEYBYTES> rx{}, tx{};
    if (crypto_kx_server_session_keys(rx.data(), tx.data(),
                                      pk_receiver.data(), sk_receiver.data(),
                                      pk_sender_eph.data()) != 0) {
        return err(ErrorCode::KeyAgreementFailed, "kx server session failed");
    }

    side_channel::flush_cache_line(sk_receiver.data());
    side_channel::random_delay();

    auto k = derive_aead_key_from_session(BytesView{rx.data(), rx.size()},
                                          std::string_view{"nocturne-tx-v3"});

    side_channel::secure_zero_memory(rx.data(), rx.size());
    side_channel::secure_zero_memory(tx.data(), tx.size());
    side_channel::flush_cache_line(rx.data());
    side_channel::flush_cache_line(tx.data());

    return k;
}

// -----------------------------------------------------------------------
// KEM shared secret → AEAD key
// -----------------------------------------------------------------------

/// @brief Fold a 32-byte KEM shared secret into an AEAD key.
///
/// Used by the encrypt_packet_kem / decrypt_packet_kem path: the KEM
/// produces a 32-byte secret, which we hash with a domain separator
/// (typically `"nocturne-kem-tx-v4"`) into the AEAD key. The extra hash
/// step gives us domain separation against future protocol revisions
/// that reuse the same KEM secret for different purposes.
///
/// @pre  @p kem_secret has the libsodium-canonical 32-byte length
///       (enforced by the type).
/// @return Propagates @ref derive_aead_key_from_session's result.
[[nodiscard]] inline Result<AeadKey> derive_aead_key_from_kem_secret(
    const std::array<std::uint8_t, 32>& kem_secret,
    std::string_view info)
{
    return derive_aead_key_from_session(
        BytesView{kem_secret.data(), kem_secret.size()}, info);
}

// -----------------------------------------------------------------------
// Ratchet mix
// -----------------------------------------------------------------------

/// @brief Mix a fresh DH-shared secret into an existing AEAD key.
///
/// Implements one symmetric ratchet step:
///   `new_key = BLAKE2b(prev_key || dh_shared, key = "nocturne-ratchet-v3")`
///
/// The previous key is invalidated after the call; callers should zero
/// it explicitly if they hold no more references.
///
/// @param prev_key  Current AEAD key.
/// @param dh_shared View over the freshly-computed DH-shared bytes.
///
/// @pre  @p dh_shared is non-empty.
/// @return @c ErrorCode::AeadKeyDerivationFailed on libsodium failure.
/// @par Exception safety
///   No-throw on the protocol path; the seed buffer allocation may
///   throw `std::bad_alloc` (system fault).
/// @par Side-channel
///   Zeroes the intermediate buffer holding `prev_key || dh_shared`
///   on every exit path before returning.
[[nodiscard]] inline Result<AeadKey> ratchet_mix(const AeadKey& prev_key,
                                                 BytesView      dh_shared)
{
    Bytes seed;
    seed.reserve(prev_key.size() + dh_shared.size());
    seed.insert(seed.end(), prev_key.begin(), prev_key.end());
    seed.insert(seed.end(), dh_shared.begin(), dh_shared.end());

    AeadKey new_key{};
    static constexpr char kInfo[] = "nocturne-ratchet-v3";
    const int rc = crypto_generichash(
        new_key.data(), new_key.size(),
        seed.data(), seed.size(),
        reinterpret_cast<const std::uint8_t*>(kInfo),
        sizeof(kInfo) - 1);

    side_channel::secure_zero_memory(seed.data(), seed.size());
    side_channel::flush_cache_line(seed.data());

    if (rc != 0) {
        return err(ErrorCode::AeadKeyDerivationFailed, "ratchet kdf failed");
    }
    return new_key;
}

}  // namespace nocturne
