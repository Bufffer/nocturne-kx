/**
 * @file hybrid_sig.hpp
 * @brief Hybrid signature: Ed25519 (classical) concatenated with ML-DSA-87 (PQ).
 *
 * Wire format (concatenated, fixed-size components):
 *   public_key = ed25519_pk(32) || mldsa87_pk(2592)         = 2624 B
 *   secret_key = ed25519_sk(64) || mldsa87_sk(4896)         = 4960 B
 *   signature  = ed25519_sig(64) || mldsa87_sig(4627)       = 4691 B
 *
 * Verification rule: **both** signatures must verify. AND-composition is
 * the standard hybrid-signature construction (RFC 9764 §3.1 strategy):
 * an adversary needs to break Ed25519 AND ML-DSA-87 simultaneously to
 * forge a hybrid sig.
 *
 * @version 4.1.0
 */

#pragma once

#include "sig_interface.hpp"
#include "mldsa_wrapper.hpp"
#include "../pqc_config.hpp"
#include "../../core/side_channel.hpp"

#ifdef NOCTURNE_ENABLE_PQC
#include <sodium.h>
#include <cstring>
#include <stdexcept>

namespace nocturne {
namespace pqc {

class HybridSig : public SignatureScheme {
private:
    MLDSAWrapper mldsa_;

    static constexpr size_t ED_PK_SIZE  = crypto_sign_PUBLICKEYBYTES;  // 32
    static constexpr size_t ED_SK_SIZE  = crypto_sign_SECRETKEYBYTES;  // 64
    static constexpr size_t ED_SIG_SIZE = crypto_sign_BYTES;           // 64

    static constexpr size_t MLDSA_PK_SIZE  = 2592;
    static constexpr size_t MLDSA_SK_SIZE  = 4896;
    static constexpr size_t MLDSA_SIG_SIZE = 4627;

    static constexpr size_t HYBRID_PK_SIZE  = ED_PK_SIZE  + MLDSA_PK_SIZE;   // 2624
    static constexpr size_t HYBRID_SK_SIZE  = ED_SK_SIZE  + MLDSA_SK_SIZE;   // 4960
    static constexpr size_t HYBRID_SIG_SIZE = ED_SIG_SIZE + MLDSA_SIG_SIZE;  // 4691

public:
    HybridSig() = default;
    ~HybridSig() override = default;

    SigKeyPair generate_keypair() override {
        // Ed25519 half via libsodium.
        std::vector<uint8_t> ed_pk(ED_PK_SIZE), ed_sk(ED_SK_SIZE);
        if (crypto_sign_keypair(ed_pk.data(), ed_sk.data()) != 0) {
            throw std::runtime_error("Hybrid sig: Ed25519 keygen failed");
        }

        // ML-DSA-87 half via liboqs.
        auto mldsa_kp = mldsa_.generate_keypair();

        SigKeyPair kp;
        kp.type       = SigType::HYBRID_ED25519_MLDSA87;
        kp.created_at = std::chrono::system_clock::now();
        kp.public_key.reserve(HYBRID_PK_SIZE);
        kp.public_key.insert(kp.public_key.end(), ed_pk.begin(),  ed_pk.end());
        kp.public_key.insert(kp.public_key.end(),
                             mldsa_kp.public_key.begin(),
                             mldsa_kp.public_key.end());

        kp.secret_key.reserve(HYBRID_SK_SIZE);
        kp.secret_key.insert(kp.secret_key.end(), ed_sk.begin(),  ed_sk.end());
        kp.secret_key.insert(kp.secret_key.end(),
                             mldsa_kp.secret_key.begin(),
                             mldsa_kp.secret_key.end());

        side_channel::secure_zero_memory(ed_sk.data(), ed_sk.size());
        return kp;
    }

    Signature sign(BytesView message,
                   const std::vector<uint8_t>& secret_key) override {
        if (secret_key.size() != HYBRID_SK_SIZE) {
            throw std::invalid_argument(
                "Hybrid sig: secret key wrong size (expected " +
                std::to_string(HYBRID_SK_SIZE) + ", got " +
                std::to_string(secret_key.size()) + ")");
        }

        // Ed25519 half — sk is the first 64 B of the hybrid sk.
        std::vector<uint8_t> ed_sig(ED_SIG_SIZE);
        unsigned long long ed_siglen = 0;
        if (crypto_sign_detached(ed_sig.data(), &ed_siglen,
                                 message.data(), message.size(),
                                 secret_key.data()) != 0 ||
            ed_siglen != ED_SIG_SIZE) {
            throw std::runtime_error("Hybrid sig: Ed25519 sign failed");
        }

        // ML-DSA half — sk is the trailing 4896 B.
        std::vector<uint8_t> mldsa_sk(secret_key.begin() + ED_SK_SIZE,
                                      secret_key.end());
        auto mldsa_sig = mldsa_.sign(message, mldsa_sk);
        side_channel::secure_zero_memory(mldsa_sk.data(), mldsa_sk.size());

        Signature out;
        out.type = SigType::HYBRID_ED25519_MLDSA87;
        out.bytes.reserve(HYBRID_SIG_SIZE);
        out.bytes.insert(out.bytes.end(), ed_sig.begin(), ed_sig.end());
        out.bytes.insert(out.bytes.end(),
                         mldsa_sig.bytes.begin(),
                         mldsa_sig.bytes.end());
        return out;
    }

    bool verify(BytesView message,
                const Signature& signature,
                const std::vector<uint8_t>& public_key) override {
        if (signature.type != SigType::HYBRID_ED25519_MLDSA87) return false;
        if (public_key.size() != HYBRID_PK_SIZE)               return false;
        if (signature.bytes.size() != HYBRID_SIG_SIZE)         return false;

        // Ed25519 half.
        if (crypto_sign_verify_detached(
                signature.bytes.data(),
                message.data(), message.size(),
                public_key.data()) != 0) {
            return false;
        }

        // ML-DSA half. AND-composition: classical pass alone is not enough.
        Signature mldsa_only;
        mldsa_only.type = SigType::PURE_MLDSA87;
        mldsa_only.bytes.assign(signature.bytes.begin() + ED_SIG_SIZE,
                                signature.bytes.end());
        std::vector<uint8_t> mldsa_pk(public_key.begin() + ED_PK_SIZE,
                                      public_key.end());
        return mldsa_.verify(message, mldsa_only, mldsa_pk);
    }

    SigType     get_type()        const override { return SigType::HYBRID_ED25519_MLDSA87; }
    size_t      public_key_size() const override { return HYBRID_PK_SIZE; }
    size_t      secret_key_size() const override { return HYBRID_SK_SIZE; }
    size_t      signature_size()  const override { return HYBRID_SIG_SIZE; }
    std::string algorithm_name()  const override { return "Hybrid-Ed25519-ML-DSA-87"; }
};

} // namespace pqc
} // namespace nocturne

#endif // NOCTURNE_ENABLE_PQC
