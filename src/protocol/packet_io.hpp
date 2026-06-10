/// @file packet_io.hpp
/// @brief Shared helpers used by encrypt_packet / decrypt_packet /
///        encrypt_packet_kem / decrypt_packet_kem to avoid four copies
///        of the signing / verifying / canonical-region code.
///
/// **Why this module exists.** Before P5.6, the canonical-signing-region
/// build (serialize a copy of @c Packet with all signature flags
/// cleared + append session_id), the classical Ed25519 signing
/// dispatch, and the PQC SignatureFactory dispatch each appeared four
/// times — once per encrypt/decrypt entry point. A single bug in any
/// of those paths required three additional fixes elsewhere. Extracting
/// them here collapses the redundancy and makes the entry-point bodies
/// fall through to one canonical implementation.
///
/// **API shape.** All helpers take and return values; they hold no
/// shared state. Callers retain ownership of the @c Packet they pass.
/// Failures throw @c std::runtime_error with concrete diagnostics —
/// the Result<T> migration (P5.8) will replace those throws with typed
/// errors.
///
/// @par Thread safety
///   Pure / value-only helpers; safe to call concurrently with
///   disjoint inputs.
/// @par Exception safety
///   Strong. Helpers either complete their work and return / mutate
///   the output packet, or throw with no observable side effect.

#pragma once

#include "../core/byte_span.hpp"
#include "../core/flags.hpp"
#include "../core/types.hpp"
#include "../hsm/inline/hsm_interface.hpp"
#include "../pqc/sig/sig_factory.hpp"
#include "packet.hpp"

#include <array>
#include <cstdint>
#include <optional>
#include <string>

#include <sodium.h>

namespace nocturne::packet_io {

/// @brief Build the canonical byte sequence under signature.
///
/// The signing region is @c serialize(@p p) with the relevant signature
/// flag bits cleared and the signature payload fields zeroed/empty,
/// optionally followed by an opaque session-id binding.
///
/// @param p                 Packet to derive the signing region from.
///                          Not modified.
/// @param clear_classical   When true, clears @c FLAG_HAS_SIG and the
///                          @c signature field for the purpose of
///                          serialization.
/// @param clear_pqc         When true, clears @c FLAG_HAS_PQC_SIG plus
///                          @c pqc_sig / @c pqc_sig_type.
/// @param session_id        Session-binding string. Appended raw at
///                          the end so peers with different session
///                          ids reject each other's packets.
/// @return Newly-allocated byte buffer.
[[nodiscard]] inline Bytes build_canonical_signing_region(
    const Packet&       p,
    bool                clear_classical,
    bool                clear_pqc,
    const std::string&  session_id)
{
    Packet unsigned_p = p;
    if (clear_classical) {
        unsigned_p.flags &= static_cast<std::uint8_t>(~FLAG_HAS_SIG);
        unsigned_p.signature.reset();
    }
    if (clear_pqc) {
        unsigned_p.flags &= static_cast<std::uint8_t>(~FLAG_HAS_PQC_SIG);
        unsigned_p.pqc_sig.clear();
        unsigned_p.pqc_sig_type = 0;
    }
    Bytes out = serialize(unsigned_p);
    if (!session_id.empty()) {
        out.insert(out.end(), session_id.begin(), session_id.end());
    }
    return out;
}

/// @brief Run the inline HSM's Ed25519 signer over the canonical
///        signing region and stamp the result into @p p.
///
/// @par Pre  @p signer must report @c is_healthy() == true at entry.
///           A failure to do so throws @c std::runtime_error before
///           any cryptographic work runs.
/// @par Post On return, @p p.flags has @c FLAG_HAS_SIG set and
///           @p p.signature populated with the 64-byte detached sig.
inline void attach_classical_signature(
    Packet&             p,
    HSMInterface&       signer,
    const std::string&  session_id)
{
    if (!signer.is_healthy()) {
        throw std::runtime_error{"HSM is not healthy"};
    }
    Bytes region = build_canonical_signing_region(p, /*clear_classical=*/true,
                                                  /*clear_pqc=*/false,
                                                  session_id);
    auto sig = signer.sign(region.data(), region.size());
    p.flags |= FLAG_HAS_SIG;
    p.signature = sig;
}

/// @brief Run the configured PQ signature scheme over the canonical
///        signing region and stamp the variable-length bytes into @p p.
///
/// @par Post @p p.flags has @c FLAG_HAS_PQC_SIG set, @p p.pqc_sig_type
///           equals the scheme enumerator, and @p p.pqc_sig holds the
///           emitted bytes.
inline void attach_pqc_signature(
    Packet&                  p,
    const PqcSignerConfig&   cfg,
    const std::string&       session_id)
{
    Bytes region = build_canonical_signing_region(p,
                                                  /*clear_classical=*/true,
                                                  /*clear_pqc=*/true,
                                                  session_id);
    auto scheme = pqc::SignatureFactory{}.create(cfg.type);
    auto sig    = scheme->sign(region.data(), region.size(), cfg.secret_key);

    p.flags        |= FLAG_HAS_PQC_SIG;
    p.pqc_sig_type  = static_cast<std::uint8_t>(cfg.type);
    p.pqc_sig       = std::move(sig.bytes);
}

/// @brief Verify the classical Ed25519 signature on @p p against
///        @p expected_pk.
///
/// @par Pre  @p p.flags has @c FLAG_HAS_SIG set and @p p.signature is
///           populated; otherwise the function throws "missing
///           required signature".
/// @par Post Returns normally on a valid signature; otherwise throws.
inline void verify_classical_signature(
    const Packet&                                                  p,
    const std::array<std::uint8_t, crypto_sign_PUBLICKEYBYTES>&    expected_pk,
    const std::string&                                              session_id)
{
    if (!(p.flags & FLAG_HAS_SIG) || !p.signature) {
        throw std::runtime_error{"missing required signature"};
    }
    Bytes region = build_canonical_signing_region(p,
                                                  /*clear_classical=*/true,
                                                  /*clear_pqc=*/false,
                                                  session_id);
    // ed25519_verify_detached returns 0 on success.
    if (crypto_sign_verify_detached(p.signature->data(),
                                    region.data(), region.size(),
                                    expected_pk.data()) != 0) {
        throw std::runtime_error{"signature verification failed"};
    }
}

/// @brief Verify the PQC signature on @p p against @p cfg's public key.
inline void verify_pqc_signature(
    const Packet&                p,
    const PqcVerifierConfig&     cfg,
    const std::string&           session_id)
{
    if (!(p.flags & FLAG_HAS_PQC_SIG) || p.pqc_sig.empty()) {
        throw std::runtime_error{"missing required pqc signature"};
    }
    if (p.pqc_sig_type != static_cast<std::uint8_t>(cfg.type)) {
        throw std::runtime_error{"pqc sig type mismatch"};
    }
    Bytes region = build_canonical_signing_region(p,
                                                  /*clear_classical=*/true,
                                                  /*clear_pqc=*/true,
                                                  session_id);
    auto scheme = pqc::SignatureFactory{}.create(cfg.type);
    pqc::Signature sig_in;
    sig_in.type  = cfg.type;
    sig_in.bytes = p.pqc_sig;
    if (!scheme->verify(region.data(), region.size(), sig_in, cfg.public_key)) {
        throw std::runtime_error{"pqc signature verification failed"};
    }
}

}  // namespace nocturne::packet_io
