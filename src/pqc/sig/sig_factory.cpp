/**
 * @file sig_factory.cpp
 * @brief Dispatch + classical Ed25519 implementation for the signature factory.
 */

#include "sig_factory.hpp"
#include "../../core/side_channel.hpp"

#include <sodium.h>
#include <cstring>
#include <stdexcept>

#ifdef NOCTURNE_ENABLE_PQC
#include "mldsa_wrapper.hpp"
#include "hybrid_sig.hpp"
#endif

namespace nocturne {
namespace pqc {

// ----------------------------------------------------------------------------
// Classical Ed25519 backend.
//
// Lives in this TU rather than its own header — it's a thin libsodium
// adapter and the factory is its only consumer.
// ----------------------------------------------------------------------------
namespace {

class ClassicEd25519Sig : public SignatureScheme {
public:
    static constexpr size_t PK_SIZE  = crypto_sign_PUBLICKEYBYTES;
    static constexpr size_t SK_SIZE  = crypto_sign_SECRETKEYBYTES;
    static constexpr size_t SIG_SIZE = crypto_sign_BYTES;

    SigKeyPair generate_keypair() override {
        SigKeyPair kp;
        kp.type       = SigType::CLASSIC_ED25519;
        kp.created_at = std::chrono::system_clock::now();
        kp.public_key.resize(PK_SIZE);
        kp.secret_key.resize(SK_SIZE);
        if (crypto_sign_keypair(kp.public_key.data(), kp.secret_key.data()) != 0) {
            side_channel::secure_zero_memory(kp.secret_key.data(), kp.secret_key.size());
            throw std::runtime_error("Ed25519 keypair generation failed");
        }
        return kp;
    }

    Signature sign(BytesView message,
                   const std::vector<uint8_t>& secret_key) override {
        if (secret_key.size() != SK_SIZE) {
            throw std::invalid_argument(
                "Ed25519 secret key wrong size (expected 64, got " +
                std::to_string(secret_key.size()) + ")");
        }
        Signature out;
        out.type = SigType::CLASSIC_ED25519;
        out.bytes.resize(SIG_SIZE);
        unsigned long long sig_len = 0;
        if (crypto_sign_detached(out.bytes.data(), &sig_len,
                                 message.data(), message.size(),
                                 secret_key.data()) != 0 ||
            sig_len != SIG_SIZE) {
            throw std::runtime_error("Ed25519 sign failed");
        }
        return out;
    }

    bool verify(BytesView message,
                const Signature& signature,
                const std::vector<uint8_t>& public_key) override {
        if (signature.type != SigType::CLASSIC_ED25519) return false;
        if (public_key.size() != PK_SIZE)               return false;
        if (signature.bytes.size() != SIG_SIZE)         return false;
        return crypto_sign_verify_detached(
                   signature.bytes.data(),
                   message.data(), message.size(),
                   public_key.data()) == 0;
    }

    SigType     get_type()        const override { return SigType::CLASSIC_ED25519; }
    size_t      public_key_size() const override { return PK_SIZE; }
    size_t      secret_key_size() const override { return SK_SIZE; }
    size_t      signature_size()  const override { return SIG_SIZE; }
    std::string algorithm_name()  const override { return "Ed25519"; }
};

} // namespace

// ----------------------------------------------------------------------------
// Factory dispatch.
// ----------------------------------------------------------------------------
std::unique_ptr<SignatureScheme> SignatureFactory::create(SigType type) {
    switch (type) {
        case SigType::CLASSIC_ED25519:
            return std::make_unique<ClassicEd25519Sig>();

#ifdef NOCTURNE_ENABLE_PQC
        case SigType::PURE_MLDSA87:
            return std::make_unique<MLDSAWrapper>();

        case SigType::HYBRID_ED25519_MLDSA87:
            return std::make_unique<HybridSig>();
#else
        case SigType::PURE_MLDSA87:
        case SigType::HYBRID_ED25519_MLDSA87:
            throw std::runtime_error(
                "Post-quantum signature requested but this build has "
                "NOCTURNE_ENABLE_PQC off (no liboqs).");
#endif
    }
    throw std::invalid_argument(
        "SignatureFactory::create: unknown SigType " +
        std::to_string(static_cast<int>(type)));
}

bool SignatureFactory::is_available(SigType type) {
    switch (type) {
        case SigType::CLASSIC_ED25519:
            return true;
#ifdef NOCTURNE_ENABLE_PQC
        case SigType::PURE_MLDSA87:
        case SigType::HYBRID_ED25519_MLDSA87:
            return true;
#else
        case SigType::PURE_MLDSA87:
        case SigType::HYBRID_ED25519_MLDSA87:
            return false;
#endif
    }
    return false;
}

std::string SignatureFactory::get_description(SigType type) {
    switch (type) {
        case SigType::CLASSIC_ED25519:
            return "Ed25519 (RFC 8032, classical — not post-quantum safe)";
        case SigType::PURE_MLDSA87:
            return "ML-DSA-87 (FIPS 204 Level 5, lattice-based)";
        case SigType::HYBRID_ED25519_MLDSA87:
            return "Hybrid Ed25519 + ML-DSA-87 (AND-composition, recommended)";
    }
    return "Unknown SigType";
}

} // namespace pqc
} // namespace nocturne
