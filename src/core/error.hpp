/// @file error.hpp
/// @brief Categorized error codes and structured Error type for the
///        Result<T> = std::expected<T, Error> failure path.
///
/// **Design intent.** Recoverable failures (signature verification failed,
/// replay detected, oversized packet field, rotation expired, rate limited)
/// flow through @c std::expected<T, Error> rather than exceptions. Throws
/// are reserved for **system faults** with no recovery strategy: failed
/// `sodium_init`, std::bad_alloc, missing file at I/O time. This split
/// makes stack-unwinding cost optional on the hot path, lets callers
/// compose with monadic combinators, and gives every failure a stable
/// machine-readable identifier suitable for audit log / SIEM enrichment.
///
/// **Wire identifiers.** ErrorCode values are part of the audit-log /
/// SIEM contract once they appear in logs. Existing entries MUST NOT be
/// renumbered. New entries are appended at the end of their category.
///
/// @version 1.0.0
/// @copyright Patent-pending hybrid PQC KEM — Nocturne-KX™.

#pragma once

#include <cstdint>
#include <source_location>
#include <string>
#include <string_view>
#include <utility>

namespace nocturne {

/// @brief Categorized error codes.
///
/// Numbering scheme:
///   - 1xx  AEAD / KDF / hash primitives
///   - 2xx  Packet wire format
///   - 3xx  Signature
///   - 4xx  KEM
///   - 5xx  Replay / counter
///   - 6xx  Key rotation / policy
///   - 7xx  Rate limiting
///   - 8xx  Audit chain
///   - 9xx  HSM / PKCS#11
///   - 10xx System fault (rarely returned — most paths throw instead)
enum class ErrorCode : std::uint16_t {
    Ok = 0,

    // --- AEAD / KDF / hash primitives ---------------------------------
    AeadAuthFailed              = 100,  ///< Poly1305 tag check failed.
    AeadKeyDerivationFailed     = 101,  ///< BLAKE2b/HMAC KDF returned non-zero.
    KeyAgreementFailed          = 102,  ///< X25519 scalarmult / KEM agreement failed.
    HashFailed                  = 103,  ///< Generic hash primitive returned non-zero.
    InvalidKeySize              = 104,  ///< Caller supplied a key with wrong length.
    InvalidNonce                = 105,  ///< Nonce length / value rejected.

    // --- Packet wire format -------------------------------------------
    PacketTruncated             = 200,  ///< Bytes ran out mid-field.
    PacketUnknownVersion        = 201,  ///< Outer @c version byte not supported.
    PacketFieldOversized        = 202,  ///< Declared field length > MAX_*.
    PacketTrailingBytes         = 203,  ///< Bytes left after last expected field.
    PacketFlagInconsistent      = 204,  ///< Flag bit set without matching payload.

    // --- Signature ----------------------------------------------------
    SignatureMissing            = 300,  ///< Verifier required a sig but none present.
    SignatureVerifyFailed       = 301,  ///< Math failed — wrong key, tampered data.
    SignatureTypeMismatch       = 302,  ///< Packet's SigType ≠ verifier's expected.
    SignatureKeySizeMismatch    = 303,  ///< pk/sk length doesn't match algorithm.
    SignatureKeygenFailed       = 304,  ///< Backend keypair generation failed.

    // --- KEM ----------------------------------------------------------
    KemEncapsulateFailed        = 400,
    KemDecapsulateFailed        = 401,
    KemKeygenFailed             = 402,
    KemSizeMismatch             = 403,  ///< pk/sk/ct length doesn't match algorithm.
    KemTypeUnknown              = 404,  ///< KEMType not compiled into this build.

    // --- Replay / counter ---------------------------------------------
    ReplayDetected              = 500,  ///< Incoming counter ≤ last seen.
    CounterRegression           = 501,  ///< External monotonic counter went backwards.
    CounterGapTooLarge          = 502,  ///< Gap exceeds policy (advisory in most paths).
    ReplayDbCorrupt             = 503,  ///< On-disk DB failed structural validation.
    ReplayMacFailed             = 504,  ///< HMAC over DB contents didn't verify.

    // --- Key rotation / policy ----------------------------------------
    RotationStale               = 600,  ///< Packet's rotation_id < required minimum.
    RotationDualApprovalPending = 601,  ///< Rotation queued, awaiting approvals.
    RotationKeyExpired          = 602,

    // --- Rate limiting ------------------------------------------------
    RateLimited                 = 700,

    // --- Audit chain --------------------------------------------------
    AuditChainBroken            = 800,  ///< prev_hash mismatch with previous record.
    AuditSignatureFailed        = 801,  ///< Per-record Ed25519 sig didn't verify.
    AuditCorrupt                = 802,  ///< Malformed JSON / hex / framing.

    // --- HSM ----------------------------------------------------------
    HsmNotInitialized           = 900,
    HsmUnhealthy                = 901,
    HsmKeyNotFound              = 902,
    HsmAuthenticationFailed     = 903,
    HsmOperationUnsupported     = 904,
    HsmPkcs11Failed             = 905,

    // --- System fault -------------------------------------------------
    // These are usually surfaced via std::runtime_error / std::bad_alloc
    // because there's no recovery; included here for the rare path that
    // wants to convert a thrown exception into a Result.
    IoFailed                    = 1000,
    OutOfMemory                 = 1001,
    SodiumInit                  = 1002,
    Internal                    = 1003,
};

/// @brief Stable, human-readable name for an ErrorCode.
///
/// Used by audit log records, SIEM forwarders, and CLI diagnostics.
/// The return value is a literal (no allocation, no lifetime concern).
///
/// @par Thread safety: Lock-free, pure function.
/// @par Exception safety: Noexcept.
[[nodiscard]] constexpr std::string_view to_string_view(ErrorCode c) noexcept {
    switch (c) {
        case ErrorCode::Ok:                          return "Ok";
        case ErrorCode::AeadAuthFailed:              return "AeadAuthFailed";
        case ErrorCode::AeadKeyDerivationFailed:     return "AeadKeyDerivationFailed";
        case ErrorCode::KeyAgreementFailed:          return "KeyAgreementFailed";
        case ErrorCode::HashFailed:                  return "HashFailed";
        case ErrorCode::InvalidKeySize:              return "InvalidKeySize";
        case ErrorCode::InvalidNonce:                return "InvalidNonce";
        case ErrorCode::PacketTruncated:             return "PacketTruncated";
        case ErrorCode::PacketUnknownVersion:        return "PacketUnknownVersion";
        case ErrorCode::PacketFieldOversized:        return "PacketFieldOversized";
        case ErrorCode::PacketTrailingBytes:         return "PacketTrailingBytes";
        case ErrorCode::PacketFlagInconsistent:      return "PacketFlagInconsistent";
        case ErrorCode::SignatureMissing:            return "SignatureMissing";
        case ErrorCode::SignatureVerifyFailed:       return "SignatureVerifyFailed";
        case ErrorCode::SignatureTypeMismatch:       return "SignatureTypeMismatch";
        case ErrorCode::SignatureKeySizeMismatch:    return "SignatureKeySizeMismatch";
        case ErrorCode::SignatureKeygenFailed:       return "SignatureKeygenFailed";
        case ErrorCode::KemEncapsulateFailed:        return "KemEncapsulateFailed";
        case ErrorCode::KemDecapsulateFailed:        return "KemDecapsulateFailed";
        case ErrorCode::KemKeygenFailed:             return "KemKeygenFailed";
        case ErrorCode::KemSizeMismatch:             return "KemSizeMismatch";
        case ErrorCode::KemTypeUnknown:              return "KemTypeUnknown";
        case ErrorCode::ReplayDetected:              return "ReplayDetected";
        case ErrorCode::CounterRegression:           return "CounterRegression";
        case ErrorCode::CounterGapTooLarge:          return "CounterGapTooLarge";
        case ErrorCode::ReplayDbCorrupt:             return "ReplayDbCorrupt";
        case ErrorCode::ReplayMacFailed:             return "ReplayMacFailed";
        case ErrorCode::RotationStale:               return "RotationStale";
        case ErrorCode::RotationDualApprovalPending: return "RotationDualApprovalPending";
        case ErrorCode::RotationKeyExpired:          return "RotationKeyExpired";
        case ErrorCode::RateLimited:                 return "RateLimited";
        case ErrorCode::AuditChainBroken:            return "AuditChainBroken";
        case ErrorCode::AuditSignatureFailed:        return "AuditSignatureFailed";
        case ErrorCode::AuditCorrupt:                return "AuditCorrupt";
        case ErrorCode::HsmNotInitialized:           return "HsmNotInitialized";
        case ErrorCode::HsmUnhealthy:                return "HsmUnhealthy";
        case ErrorCode::HsmKeyNotFound:              return "HsmKeyNotFound";
        case ErrorCode::HsmAuthenticationFailed:     return "HsmAuthenticationFailed";
        case ErrorCode::HsmOperationUnsupported:     return "HsmOperationUnsupported";
        case ErrorCode::HsmPkcs11Failed:             return "HsmPkcs11Failed";
        case ErrorCode::IoFailed:                    return "IoFailed";
        case ErrorCode::OutOfMemory:                 return "OutOfMemory";
        case ErrorCode::SodiumInit:                  return "SodiumInit";
        case ErrorCode::Internal:                    return "Internal";
    }
    return "Unknown";  // Unreachable for well-formed enum values; defensive.
}

/// @brief Numeric audit category derived from ErrorCode.
///
/// Returns the leading hundreds digit: 1=Crypto, 2=Wire, 3=Sig, 4=KEM,
/// 5=Replay, 6=Rotation, 7=RateLimit, 8=Audit, 9=HSM, 10=System.
/// Useful for SIEM dashboards that aggregate by domain.
///
/// @par Thread safety: Lock-free, pure.
/// @par Exception safety: Noexcept.
[[nodiscard]] constexpr std::uint16_t category(ErrorCode c) noexcept {
    return static_cast<std::uint16_t>(c) / 100u;
}

/// @brief Structured error payload carried by Result<T>.
///
/// Combines a categorized @ref ErrorCode, a human-readable diagnostic
/// message, and an optional @c std::source_location stamped at
/// construction. The source_location lets audit logs / SIEM events name
/// the originating call site without sprinkling string literals
/// throughout the codebase.
///
/// **Invariants.** Once constructed an Error is immutable from the
/// outside (no setters); fields are public for ergonomic field access
/// in structured bindings and pattern-match-like switches.
///
/// @par Thread safety: Value type, immutable post-construction; safe to
///                     copy/move across threads.
/// @par Exception safety: All operations are nothrow (the string move
///                        is noexcept under the C++23 short-string
///                        optimization contract).
struct Error {
    ErrorCode             code{ErrorCode::Internal};
    std::string           message;
    std::source_location  where{std::source_location::current()};

    Error() noexcept = default;

    /// @brief Construct from code + message; stamps current source location.
    /// @param c  Categorized error code.
    /// @param m  Free-form diagnostic. Pass a constructed string; SSO
    ///           keeps small messages allocation-free.
    /// @param loc Defaulted to caller's location via @c consteval; do
    ///            not pass explicitly except when forwarding from a
    ///            wrapper.
    Error(ErrorCode c, std::string m,
          std::source_location loc = std::source_location::current()) noexcept
        : code{c}, message{std::move(m)}, where{loc} {}

    /// @brief Stable identifier — equal to to_string_view(code).
    [[nodiscard]] std::string_view name() const noexcept {
        return to_string_view(code);
    }

    /// @brief Numeric category (1xx → 1, 2xx → 2, etc.). See @ref category.
    [[nodiscard]] std::uint16_t domain() const noexcept {
        return category(code);
    }
};

}  // namespace nocturne
