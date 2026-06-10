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
/// Failures are reported as typed @c Result / @c Status errors (P6.1b);
/// only system faults from the HSM / signature backends (I/O, alloc)
/// still propagate as exceptions.
///
/// @par Thread safety
///   Pure / value-only helpers; safe to call concurrently with
///   disjoint inputs.
/// @par Exception safety
///   No-throw on the protocol path. The HSM's @c sign() and the
///   SignatureFactory backends may throw on system faults
///   (missing key file, allocation failure); adversarial input never
///   reaches those paths without a typed reject first.

#pragma once

#include "../core/byte_span.hpp"
#include "../core/flags.hpp"
#include "../core/result.hpp"
#include "../core/types.hpp"
#include "../hsm/inline/hsm_interface.hpp"
#include "../pqc/sig/sig_factory.hpp"
#include "packet.hpp"

#include <array>
#include <cstdint>
#include <exception>
#include <optional>
#include <string>
#include <utility>

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
/// @return Newly-allocated byte buffer, or the @ref serialize error
///         (@c PacketFlagInconsistent / @c PacketFieldOversized).
[[nodiscard]] inline Result<Bytes> build_canonical_signing_region(
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
    auto out = serialize(unsigned_p);
    if (!out) {
        return std::unexpected{out.error()};
    }
    if (!session_id.empty()) {
        out->insert(out->end(), session_id.begin(), session_id.end());
    }
    return out;
}

/// @brief Run the inline HSM's Ed25519 signer over the canonical
///        signing region and stamp the result into @p p.
///
/// @return @c ErrorCode::HsmUnhealthy when @p signer reports
///         @c is_healthy() == false (checked before any cryptographic
///         work); otherwise propagates the canonical-region build.
/// @post On success, @p p.flags has @c FLAG_HAS_SIG set and
///       @p p.signature populated with the 64-byte detached sig. On
///       error @p p is unmodified.
/// @par Exception safety
///   @p signer's @c sign() may throw on HSM system faults (e.g. key
///   file unreadable); in that case @p p is unmodified.
[[nodiscard]] inline Status attach_classical_signature(
    Packet&             p,
    HSMInterface&       signer,
    const std::string&  session_id)
{
    if (!signer.is_healthy()) {
        return err(ErrorCode::HsmUnhealthy, "HSM is not healthy");
    }
    auto region = build_canonical_signing_region(p, /*clear_classical=*/true,
                                                 /*clear_pqc=*/false,
                                                 session_id);
    if (!region) {
        return std::unexpected{region.error()};
    }
    auto sig = signer.sign(region->data(), region->size());
    p.flags |= FLAG_HAS_SIG;
    p.signature = sig;
    return ok();
}

/// @brief Run the configured PQ signature scheme over the canonical
///        signing region and stamp the variable-length bytes into @p p.
///
/// @return @c ErrorCode::SignatureKeySizeMismatch /
///         @c SignatureVerifyFailed-family errors surfaced by the
///         backend, or the canonical-region build error.
/// @post On success @p p.flags has @c FLAG_HAS_PQC_SIG set,
///       @p p.pqc_sig_type equals the scheme enumerator, and
///       @p p.pqc_sig holds the emitted bytes. On error @p p is
///       unmodified.
[[nodiscard]] inline Status attach_pqc_signature(
    Packet&                  p,
    const PqcSignerConfig&   cfg,
    const std::string&       session_id)
{
    auto region = build_canonical_signing_region(p,
                                                 /*clear_classical=*/true,
                                                 /*clear_pqc=*/true,
                                                 session_id);
    if (!region) {
        return std::unexpected{region.error()};
    }

    pqc::Signature sig;
    try {
        auto scheme = pqc::SignatureFactory{}.create(cfg.type);
        sig = scheme->sign(region->data(), region->size(), cfg.secret_key);
    } catch (const std::exception& e) {
        // Backend rejects (wrong sk size, unavailable scheme) arrive as
        // exceptions from the factory layer; fold them into the typed
        // error contract here.
        return err(ErrorCode::SignatureKeygenFailed, e.what());
    }

    p.flags        |= FLAG_HAS_PQC_SIG;
    p.pqc_sig_type  = static_cast<std::uint8_t>(cfg.type);
    p.pqc_sig       = std::move(sig.bytes);
    return ok();
}

/// @brief Verify the classical Ed25519 signature on @p p against
///        @p expected_pk.
///
/// @return @c ErrorCode::SignatureMissing when @c FLAG_HAS_SIG is unset
///         or the field is empty, @c ErrorCode::SignatureVerifyFailed
///         when the detached verify rejects; @c ok() on success.
[[nodiscard]] inline Status verify_classical_signature(
    const Packet&                                                  p,
    const std::array<std::uint8_t, crypto_sign_PUBLICKEYBYTES>&    expected_pk,
    const std::string&                                              session_id)
{
    if (!(p.flags & FLAG_HAS_SIG) || !p.signature) {
        return err(ErrorCode::SignatureMissing, "missing required signature");
    }
    auto region = build_canonical_signing_region(p,
                                                 /*clear_classical=*/true,
                                                 /*clear_pqc=*/false,
                                                 session_id);
    if (!region) {
        return std::unexpected{region.error()};
    }
    // ed25519_verify_detached returns 0 on success.
    if (crypto_sign_verify_detached(p.signature->data(),
                                    region->data(), region->size(),
                                    expected_pk.data()) != 0) {
        return err(ErrorCode::SignatureVerifyFailed,
                   "signature verification failed");
    }
    return ok();
}

/// @brief Verify the PQC signature on @p p against @p cfg's public key.
///
/// @return @c ErrorCode::SignatureMissing, @c SignatureTypeMismatch
///         (adversarial type byte ≠ pinned verifier type — checked
///         before any cryptographic work), or
///         @c SignatureVerifyFailed; @c ok() on success.
[[nodiscard]] inline Status verify_pqc_signature(
    const Packet&                p,
    const PqcVerifierConfig&     cfg,
    const std::string&           session_id)
{
    if (!(p.flags & FLAG_HAS_PQC_SIG) || p.pqc_sig.empty()) {
        return err(ErrorCode::SignatureMissing, "missing required pqc signature");
    }
    if (p.pqc_sig_type != static_cast<std::uint8_t>(cfg.type)) {
        return err(ErrorCode::SignatureTypeMismatch, "pqc sig type mismatch");
    }
    auto region = build_canonical_signing_region(p,
                                                 /*clear_classical=*/true,
                                                 /*clear_pqc=*/true,
                                                 session_id);
    if (!region) {
        return std::unexpected{region.error()};
    }

    bool valid = false;
    try {
        auto scheme = pqc::SignatureFactory{}.create(cfg.type);
        pqc::Signature sig_in;
        sig_in.type  = cfg.type;
        sig_in.bytes = p.pqc_sig;
        valid = scheme->verify(region->data(), region->size(), sig_in,
                               cfg.public_key);
    } catch (const std::exception& e) {
        // Adversarial sig bytes can trip backend size checks that throw;
        // a reject is a reject — surface it as the typed verify failure.
        return err(ErrorCode::SignatureVerifyFailed, e.what());
    }
    if (!valid) {
        return err(ErrorCode::SignatureVerifyFailed,
                   "pqc signature verification failed");
    }
    return ok();
}

}  // namespace nocturne::packet_io
