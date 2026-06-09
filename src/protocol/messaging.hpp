/// @file messaging.hpp
/// @brief High-level encrypt/decrypt entry points for Nocturne packets.
///
/// Bridges the wire format in @c packet.hpp with the crypto primitives in
/// @c kdf.hpp / @c aead.hpp / @c signing.hpp into a single one-call API
/// that handles AEAD key derivation, optional ratchet mixing, optional
/// classical and/or PQC signatures, optional replay-DB counter tracking,
/// and rate limiting.
///
/// Two pairs:
///   - @ref encrypt_packet / @ref decrypt_packet for the classical
///     X25519 ECDH path.
///   - @ref encrypt_packet_kem / @ref decrypt_packet_kem for the KEM
///     path (hybrid X25519+ML-KEM-1024 or pure ML-KEM-1024).
///
/// Caller-supplied options live in @ref EncryptOptions and
/// @ref DecryptOptions aggregates so callers pick what they need by
/// designated initializer instead of relying on positional defaults.
///
/// @par Thread safety
///   The functions hold no global state of their own; thread safety
///   is delegated to whatever @c ReplayDB / @c HSMInterface instance
///   the caller passes through @c EncryptOptions::replay_db /
///   @c EncryptOptions::signer.
/// @par Exception safety
///   Strong on the happy path. AEAD authentication failures, signature
///   mismatches, replay-counter regressions, and rate-limit overruns all
///   throw @c std::runtime_error with a human-readable message.

#pragma once

#include "packet.hpp"
#include "../core/types.hpp"
#include "../hsm/inline/hsm_interface.hpp"
#include "../pqc/kem/kem_interface.hpp"
#include "../security/inline/replay_db.hpp"

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include <sodium.h>

namespace nocturne {

/// @brief Optional knobs for @ref encrypt_packet and @ref encrypt_packet_kem.
///
/// All fields are optional; the default-constructed value produces an
/// unsigned, untracked packet with no AAD and rotation_id 0.
struct EncryptOptions {
    /// Associated data forwarded to the AEAD; receiver must supply the
    /// same bytes via the packet to authenticate decryption.
    Bytes aad;

    /// Key-rotation counter, opaque to the protocol but checked against
    /// @c DecryptOptions::min_rotation_id on the receive side.
    std::uint32_t rotation_id{0};

    /// Mix an ephemeral DH share into the AEAD key for forward secrecy.
    /// Honored by @ref encrypt_packet; ignored by @ref encrypt_packet_kem
    /// (the KEM already supplies the ephemeral half).
    bool use_ratchet{false};

    /// Optional classical Ed25519 signer. When set, the packet carries
    /// @c FLAG_HAS_SIG and the receiver can pin the signer via
    /// @c DecryptOptions::expected_signer_ed25519_pk.
    HSMInterface* signer{nullptr};

    /// Optional on-disk counter tracker. When set, the sender consumes
    /// a monotonic counter per (receiver, session) tuple and writes it
    /// into the packet.
    ReplayDB* replay_db{nullptr};

    /// Discriminator used for rate-limit bucketing and signature
    /// transcripts; opaque to the protocol.
    std::string session_id;

    /// Optional PQ signature config. When set, the packet additionally
    /// carries @c FLAG_HAS_PQC_SIG. Orthogonal to @c signer — both can
    /// be set together for a hybrid-signed packet.
    const PqcSignerConfig* pqc_signer{nullptr};
};

/// @brief Optional knobs for @ref decrypt_packet and @ref decrypt_packet_kem.
///
/// All fields are optional; the default-constructed value verifies the
/// AEAD tag and nothing else.
struct DecryptOptions {
    /// When set, require the packet to carry a classical Ed25519
    /// signature and verify it against this public key. An unsigned
    /// packet against a pinned signer is rejected.
    std::optional<std::array<std::uint8_t, crypto_sign_PUBLICKEYBYTES>>
        expected_signer_ed25519_pk;

    /// Optional on-disk counter tracker. When set, packets with a
    /// counter ≤ the stored value are rejected as replays.
    ReplayDB* replay_db{nullptr};

    /// Reject packets whose @c rotation_id is below this floor.
    std::optional<std::uint32_t> min_rotation_id;

    /// Discriminator used for rate-limit bucketing and signature
    /// transcripts; opaque to the protocol.
    std::string session_id;

    /// Optional PQ signature verifier. When set, require and verify
    /// @c FLAG_HAS_PQC_SIG. Orthogonal to @c expected_signer_ed25519_pk.
    const PqcVerifierConfig* pqc_verifier{nullptr};
};

/// @brief Encrypt @p plaintext to @p receiver_x25519_pk using classical
///        X25519 ECDH.
///
/// @returns Serialized wire-format packet ready to transmit.
[[nodiscard]] Bytes encrypt_packet(
    const std::array<std::uint8_t, crypto_kx_PUBLICKEYBYTES>& receiver_x25519_pk,
    const Bytes& plaintext,
    const EncryptOptions& opts = {});

/// @brief Decrypt a packet previously produced by @ref encrypt_packet.
[[nodiscard]] Bytes decrypt_packet(
    const std::array<std::uint8_t, crypto_kx_PUBLICKEYBYTES>& receiver_x25519_pk,
    const std::array<std::uint8_t, crypto_kx_SECRETKEYBYTES>& receiver_x25519_sk,
    const Bytes& packet_bytes,
    const DecryptOptions& opts = {});

/// @brief Encrypt @p plaintext using the post-quantum KEM path.
///
/// @param kem_type Must be a non-classical type
///                 (@c pqc::KEMType::HYBRID_X25519_MLKEM1024 or
///                 @c pqc::KEMType::PURE_MLKEM1024). Passing
///                 @c CLASSIC_X25519 throws — use @ref encrypt_packet
///                 instead.
[[nodiscard]] Bytes encrypt_packet_kem(
    pqc::KEMType kem_type,
    const std::vector<std::uint8_t>& receiver_pk,
    const Bytes& plaintext,
    const EncryptOptions& opts = {});

/// @brief Decrypt a packet previously produced by @ref encrypt_packet_kem.
///        The KEM type is recovered from the packet header.
[[nodiscard]] Bytes decrypt_packet_kem(
    const std::vector<std::uint8_t>& receiver_pk,
    const std::vector<std::uint8_t>& receiver_sk,
    const Bytes& packet_bytes,
    const DecryptOptions& opts = {});

}  // namespace nocturne
