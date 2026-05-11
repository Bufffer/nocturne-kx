/// @file packet.hpp
/// @brief Nocturne-KX packet wire format: data types and serialize /
///        deserialize free functions.
///
/// The on-wire layout (current @c VERSION = 0x03):
///
/// @code
///   +------------------------------------------------------------+
///   | 1B version                                                 |
///   | 1B flags (bitmask of nocturne::Flag)                       |
///   | 4B LE rotation_id                                          |
///   | 32B eph_pk         (zeroed when FLAG_HAS_PQC_KEM is set)   |
///   | 24B nonce          (XChaCha20-Poly1305 NPUBBYTES)          |
///   | 8B  LE counter     (monotonic per-sender)                  |
///   |                                                            |
///   | if FLAG_HAS_RATCHET:                                       |
///   |   32B ratchet_pk                                           |
///   |                                                            |
///   | if FLAG_HAS_PQC_KEM:                                       |
///   |   1B pqc_kem_type                                          |
///   |   4B LE pqc_kem_ct_len                                     |
///   |   N  pqc_kem_ct       (≤ MAX_PQC_KEM_CT_SIZE)              |
///   |                                                            |
///   | 4B LE aad_len                                              |
///   | 4B LE ciphertext_len                                       |
///   | aad_len bytes        (associated data)                     |
///   | ciphertext_len bytes (AEAD ct, includes Poly1305 tag)      |
///   |                                                            |
///   | if FLAG_HAS_PQC_SIG:                                       |
///   |   1B pqc_sig_type                                          |
///   |   4B LE pqc_sig_len                                        |
///   |   N  pqc_sig         (≤ MAX_PQC_SIG_SIZE)                  |
///   |                                                            |
///   | if FLAG_HAS_SIG:                                           |
///   |   64B Ed25519 signature                                    |
///   +------------------------------------------------------------+
/// @endcode
///
/// **Canonical signing region.** When a signer signs the packet, the
/// region under signature is the byte sequence produced by
/// @ref serialize on a copy of the packet with **all** signature flags
/// cleared and the corresponding payload fields zeroed/cleared. This
/// guarantees that adding or removing a signature variant does not
/// invalidate the other.
///
/// **Versioning.** @ref VERSION is bumped only on a backward-
/// incompatible wire change. New optional fields are added via new
/// @ref Flag bits without a version bump; old peers reject unknown bits
/// because the deserializer's trailing-bytes check fails when an
/// unknown flag pulls in bytes the parser doesn't consume.
///
/// @version 1.0.0
/// @par Thread safety
///   Functions in this header are pure (no shared mutable state). The
///   @ref Packet type is a value record; copies and moves are safe
///   across threads.

#pragma once

#include "../core/byte_span.hpp"
#include "../core/flags.hpp"
#include "../core/types.hpp"
#include "../pqc/sig/sig_interface.hpp"

#include <array>
#include <cstdint>
#include <optional>
#include <sodium.h>

namespace nocturne {

/// @brief Packet value record carried over the wire.
///
/// All optional fields are populated only when the corresponding @ref
/// Flag bit is set in @c flags. The structure is a plain aggregate; use
/// designated-initializer construction when building from scratch and
/// reserve the @c serialize / @c deserialize free functions for I/O.
///
/// **Invariants** (enforced by @ref serialize):
///   - @c (flags & HasSig) implies @c signature.has_value().
///   - @c (flags & HasRatchet) implies @c ratchet_pk.has_value().
///   - @c (flags & HasPqcKem) implies @c !pqc_kem_ct.empty() and
///     @c pqc_kem_ct.size() ≤ MAX_PQC_KEM_CT_SIZE.
///   - @c (flags & HasPqcSig) implies @c !pqc_sig.empty() and
///     @c pqc_sig.size() ≤ MAX_PQC_SIG_SIZE.
struct Packet {
    std::uint8_t                                                                 version{VERSION};
    std::uint8_t                                                                 flags{0};
    std::uint32_t                                                                rotation_id{0};
    std::array<std::uint8_t, crypto_kx_PUBLICKEYBYTES>                           eph_pk{};
    std::array<std::uint8_t, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES>       nonce{};
    std::uint64_t                                                                counter{0};
    std::optional<std::array<std::uint8_t, crypto_kx_PUBLICKEYBYTES>>            ratchet_pk;
    /// PQC KEM type code, matching @c nocturne::pqc::KEMType.
    std::uint8_t                                                                 pqc_kem_type{0};
    Bytes                                                                        pqc_kem_ct;
    Bytes                                                                        aad;
    /// AEAD ciphertext, includes the trailing Poly1305 tag.
    Bytes                                                                        ciphertext;
    std::optional<std::array<std::uint8_t, crypto_sign_BYTES>>                   signature;
    /// PQC sig type code, matching @c nocturne::pqc::SigType.
    std::uint8_t                                                                 pqc_sig_type{0};
    Bytes                                                                        pqc_sig;
};

/// @brief Caller-supplied parameters for the FLAG_HAS_PQC_SIG path.
///
/// The HSMInterface is Ed25519-only (returns a fixed 64-byte array), so
/// PQC signing currently bypasses the HSM abstraction and operates on
/// the in-memory secret key. A future revision can add a variable-size
/// @c HSMInterface::sign_pqc and route PQC keys through the same
/// adapter.
struct PqcSignerConfig {
    pqc::SigType type;
    Bytes        secret_key;  ///< Raw bytes; size validated by SignatureFactory.
};

/// @brief Caller-supplied parameters for the verify-side companion.
struct PqcVerifierConfig {
    pqc::SigType type;
    Bytes        public_key;  ///< Raw bytes; size validated by SignatureFactory.
};

// -----------------------------------------------------------------------
// Endian helpers
// -----------------------------------------------------------------------
// LE-encoded integers appear in several places (KEM ciphertext length,
// AAD length, ciphertext length, counter, rotation id, PQC sig length).
// These inline helpers keep the open-coded byte shuffling out of every
// call site.
// -----------------------------------------------------------------------

/// @brief Append @p v to @p out as four little-endian bytes.
inline void write_u32_le(Bytes& out, std::uint32_t v) {
    out.push_back(static_cast<std::uint8_t>(v & 0xff));
    out.push_back(static_cast<std::uint8_t>((v >> 8) & 0xff));
    out.push_back(static_cast<std::uint8_t>((v >> 16) & 0xff));
    out.push_back(static_cast<std::uint8_t>((v >> 24) & 0xff));
}

/// @brief Append @p v to @p out as eight little-endian bytes.
inline void write_u64_le(Bytes& out, std::uint64_t v) {
    for (int i = 0; i < 8; ++i) {
        out.push_back(static_cast<std::uint8_t>((v >> (8 * i)) & 0xff));
    }
}

/// @brief Read four LE bytes from @p p as an unsigned 32-bit integer.
/// @par Pre  @p p points at a buffer of at least 4 readable bytes.
/// @par Post Return value equals @c p[0] | p[1]<<8 | p[2]<<16 | p[3]<<24.
[[nodiscard]] inline std::uint32_t read_u32_le(const std::uint8_t* p) noexcept {
    return static_cast<std::uint32_t>(p[0])
         | (static_cast<std::uint32_t>(p[1]) << 8)
         | (static_cast<std::uint32_t>(p[2]) << 16)
         | (static_cast<std::uint32_t>(p[3]) << 24);
}

/// @brief Read eight LE bytes from @p p as an unsigned 64-bit integer.
[[nodiscard]] inline std::uint64_t read_u64_le(const std::uint8_t* p) noexcept {
    std::uint64_t v = 0;
    for (int i = 0; i < 8; ++i) {
        v |= static_cast<std::uint64_t>(p[i]) << (8 * i);
    }
    return v;
}

// -----------------------------------------------------------------------
// Wire I/O
// -----------------------------------------------------------------------

/// @brief Serialize a Packet to its on-wire byte sequence.
///
/// @param p Packet to serialize. The invariants listed under @ref Packet
///          are checked; any violation throws @c std::runtime_error.
/// @return Owned byte buffer containing the serialized packet.
///
/// @par Pre  Caller has populated @p p such that every flag bit's
///           corresponding payload field is present and within the
///           size caps (@ref MAX_PQC_KEM_CT_SIZE, @ref MAX_PQC_SIG_SIZE).
/// @par Post Returned buffer is consumable by @ref deserialize and the
///           round trip is byte-exact for well-formed inputs.
/// @par Thread safety: Pure function; no shared state.
/// @par Exception safety: Strong. The function either returns a fully
///                        formed buffer or throws and leaves no
///                        observable side effect.
[[nodiscard]] Bytes serialize(const Packet& p);

/// @brief Parse an on-wire byte sequence into a Packet.
///
/// @param in Read-only byte view over the wire bytes.
/// @return Decoded packet.
///
/// @par Pre  None — the deserializer is the trust boundary for adversarial
///           input.
/// @par Post On success, the returned Packet satisfies every invariant
///           under @ref Packet.
/// @par Thread safety: Pure function; no shared state.
/// @par Exception safety: Strong. The function either returns a valid
///                        Packet or throws @c std::runtime_error with a
///                        diagnostic message describing the rejected
///                        condition (truncated, oversized field,
///                        unsupported version, trailing bytes).
[[nodiscard]] Packet deserialize(BytesView in);

}  // namespace nocturne
