/**
 * @file sig_interface.hpp
 * @brief Abstract interface for digital-signature schemes.
 *
 * Mirrors the KEM interface in src/pqc/kem/kem_interface.hpp. Provides a
 * unified surface for classical Ed25519, post-quantum ML-DSA-87 (FIPS 204),
 * and the Ed25519+ML-DSA-87 hybrid.
 *
 * @version 4.1.0
 */

#pragma once

#include "../../core/byte_span.hpp"

#include <array>
#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace nocturne {
namespace pqc {

/**
 * @brief Signature algorithm type. Wire identifier — do not renumber.
 */
enum class SigType : uint8_t {
    CLASSIC_ED25519        = 0,  ///< 32B pk, 64B sk, 64B sig — fallback, not PQ-safe
    HYBRID_ED25519_MLDSA87 = 1,  ///< Defense-in-depth: classical AND post-quantum
    PURE_MLDSA87           = 2,  ///< NIST FIPS 204 Level 5 (pure post-quantum)
};

inline const char* sig_type_to_string(SigType t) {
    switch (t) {
        case SigType::CLASSIC_ED25519:        return "Ed25519";
        case SigType::HYBRID_ED25519_MLDSA87: return "Hybrid-Ed25519-ML-DSA-87";
        case SigType::PURE_MLDSA87:           return "ML-DSA-87";
        default:                              return "Unknown";
    }
}

/**
 * @brief Signature keypair. Secret key is auto-wiped on destruction.
 */
struct SigKeyPair {
    std::vector<uint8_t> public_key;
    std::vector<uint8_t> secret_key;
    SigType type = SigType::CLASSIC_ED25519;
    std::chrono::system_clock::time_point created_at;

    ~SigKeyPair();

    SigKeyPair() : created_at(std::chrono::system_clock::now()) {}

    SigKeyPair(const SigKeyPair&)            = delete;
    SigKeyPair& operator=(const SigKeyPair&) = delete;

    SigKeyPair(SigKeyPair&&) noexcept            = default;
    SigKeyPair& operator=(SigKeyPair&&) noexcept = default;
};

/**
 * @brief Produced signature bytes + the type that emitted them. The
 *        size varies wildly: Ed25519 = 64 B, ML-DSA-87 = 4627 B,
 *        hybrid = 64 + 4627 = 4691 B (raw concat, fixed sizes).
 */
struct Signature {
    std::vector<uint8_t> bytes;
    SigType type = SigType::CLASSIC_ED25519;
};

/**
 * @brief Abstract signature scheme.
 *
 * Implementations: ClassicEd25519Sig (libsodium), MLDSAWrapper (liboqs),
 * HybridSig (concat).
 */
class SignatureScheme {
public:
    virtual ~SignatureScheme() = default;

    virtual SigKeyPair  generate_keypair() = 0;

    /// @param message View over the bytes under signature (P6.3: span
    ///        instead of ptr+len — size is bound at construction and
    ///        cannot disagree with the pointer downstream).
    virtual Signature   sign(BytesView message,
                             const std::vector<uint8_t>& secret_key) = 0;

    virtual bool        verify(BytesView message,
                               const Signature& signature,
                               const std::vector<uint8_t>& public_key) = 0;

    virtual SigType     get_type()         const = 0;
    virtual size_t      public_key_size()  const = 0;
    virtual size_t      secret_key_size()  const = 0;
    virtual size_t      signature_size()   const = 0;
    virtual std::string algorithm_name()   const = 0;
};

} // namespace pqc
} // namespace nocturne
