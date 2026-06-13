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
/// @par Error contract (P6.1b)
///   All four entry points return `Result<Bytes>`. Every adversarial or
///   recoverable failure is a typed @ref Error — AEAD auth failure,
///   signature mismatch, replay regression, stale rotation, rate-limit
///   overrun, malformed wire bytes, KEM type/size mismatch. Exceptions
///   are reserved for system faults: `sodium_init` failure
///   (@c check_sodium throws), HSM key-file I/O, `std::bad_alloc`.

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
/// @pre `sodium_init()` succeeded (guaranteed by @ref check_sodium at startup).
/// @pre `receiver_x25519_pk` is a valid 32-byte X25519 public key (all-zero
///      is rejected by libsodium's key-exchange step at runtime).
/// @pre If `opts.signer` is non-null it must be healthy (`is_healthy()` true)
///      and must have an active key loaded.
/// @pre If `opts.replay_db` is non-null the counter file is readable/writable.
/// @return Serialized wire-format packet ready to transmit, or:
///         - @c ErrorCode::RateLimited — per-receiver bucket exhausted,
///         - @c ErrorCode::KeyAgreementFailed — X25519 stage rejected,
///         - @c ErrorCode::HsmUnhealthy — @c opts.signer unhealthy,
///         - KDF / AEAD / serialize errors propagated from the
///           primitives (1xx / 2xx).
[[nodiscard]] Result<Bytes> encrypt_packet(
    const std::array<std::uint8_t, crypto_kx_PUBLICKEYBYTES>& receiver_x25519_pk,
    const Bytes& plaintext,
    const EncryptOptions& opts = {});

/// @brief Decrypt a packet previously produced by @ref encrypt_packet.
///
/// @pre `receiver_x25519_pk` / `receiver_x25519_sk` form a matching X25519
///      keypair (mismatched pairs produce @c AeadAuthFailed, not UB).
/// @pre `packet_bytes` must NOT have @c FLAG_HAS_PQC_KEM set; use
///      @ref decrypt_packet_kem for KEM packets.
/// @return Plaintext, or:
///         - @c ErrorCode::RateLimited,
///         - wire-format errors (2xx) from @ref deserialize,
///         - @c ErrorCode::SignatureMissing / @c SignatureVerifyFailed /
///           @c SignatureTypeMismatch — pinned-signer checks,
///         - @c ErrorCode::RotationStale — @c rotation_id below
///           @c opts.min_rotation_id,
///         - @c ErrorCode::ReplayDetected — counter ≤ last seen,
///         - @c ErrorCode::AeadAuthFailed — tag rejected.
[[nodiscard]] Result<Bytes> decrypt_packet(
    const std::array<std::uint8_t, crypto_kx_PUBLICKEYBYTES>& receiver_x25519_pk,
    const std::array<std::uint8_t, crypto_kx_SECRETKEYBYTES>& receiver_x25519_sk,
    const Bytes& packet_bytes,
    const DecryptOptions& opts = {});

/// @brief Encrypt @p plaintext using the post-quantum KEM path.
///
/// @pre `kem_type != KEMType::CLASSIC_X25519` — use @ref encrypt_packet for
///      X25519; this function returns @c KemTypeUnknown for that value.
/// @pre `receiver_pk` size must match `kem_type`'s public key size (1600 B
///      for hybrid, 1568 B for pure ML-KEM-1024); mismatch → @c KemSizeMismatch.
/// @param kem_type Must be a non-classical type
///                 (@c pqc::KEMType::HYBRID_X25519_MLKEM1024 or
///                 @c pqc::KEMType::PURE_MLKEM1024). Passing
///                 @c CLASSIC_X25519 yields @c ErrorCode::KemTypeUnknown
///                 — use @ref encrypt_packet instead.
/// @return Serialized packet, or @c KemTypeUnknown / @c KemSizeMismatch /
///         @c KemEncapsulateFailed / @c RateLimited plus the same
///         primitive errors as @ref encrypt_packet.
[[nodiscard]] Result<Bytes> encrypt_packet_kem(
    pqc::KEMType kem_type,
    const std::vector<std::uint8_t>& receiver_pk,
    const Bytes& plaintext,
    const EncryptOptions& opts = {});

/// @brief Decrypt a packet previously produced by @ref encrypt_packet_kem.
///        The KEM type is recovered from the packet header.
///
/// @pre `packet_bytes` must have @c FLAG_HAS_PQC_KEM set; use
///      @ref decrypt_packet for classical X25519 packets.
/// @pre `receiver_pk` / `receiver_sk` must match the KEM type encoded in the
///      packet header (size mismatch → @c KemSizeMismatch, not UB).
///
/// @return Plaintext, or @c PacketFlagInconsistent (not a KEM packet /
///         X25519 mislabeled as PQC), @c KemTypeUnknown (adversarial
///         type byte not compiled in), @c KemSizeMismatch,
///         @c KemDecapsulateFailed, plus the same signature / replay /
///         rotation / AEAD errors as @ref decrypt_packet.
[[nodiscard]] Result<Bytes> decrypt_packet_kem(
    const std::vector<std::uint8_t>& receiver_pk,
    const std::vector<std::uint8_t>& receiver_sk,
    const Bytes& packet_bytes,
    const DecryptOptions& opts = {});

}  // namespace nocturne
