/**
 * @file mldsa_wrapper.hpp
 * @brief ML-DSA-87 (CRYSTALS-Dilithium) signature wrapper using liboqs.
 *
 * NIST FIPS 204 Level 5 — equivalent classical strength to AES-256.
 *
 * Sizes (fixed by spec):
 *   - Public key:  2592 bytes
 *   - Secret key:  4896 bytes
 *   - Signature:   4627 bytes
 *
 * Use in hybrid mode (Ed25519 + ML-DSA-87) for defense-in-depth: a
 * classical break of Ed25519 still leaves an unbroken post-quantum
 * signature, and a (theoretical) lattice break of ML-DSA still leaves
 * an unbroken classical signature. Either alone is risky.
 *
 * @version 4.1.0
 */

#pragma once

#include "sig_interface.hpp"
#include "../pqc_config.hpp"
#include "../../core/flags.hpp"
#include "../../core/side_channel.hpp"

#ifdef NOCTURNE_ENABLE_PQC
#include <oqs/oqs.h>
#include <memory>
#include <stdexcept>
#include <string>

namespace nocturne {
namespace pqc {

class MLDSAWrapper : public SignatureScheme {
public:
    // FIPS 204 fixed sizes for ML-DSA-87 (Level 5). Public so composed
    // schemes (HybridSig) derive their sizes from this single source of
    // truth.
    static constexpr size_t PUBLIC_KEY_BYTES = 2592;
    static constexpr size_t SECRET_KEY_BYTES = 4896;
    static constexpr size_t SIGNATURE_BYTES  = 4627;

    // Wire contract: the signature must fit the packet field cap.
    static_assert(SIGNATURE_BYTES <= MAX_PQC_SIG_SIZE,
                  "ML-DSA-87 signature exceeds MAX_PQC_SIG_SIZE");

private:
    static constexpr const char* ALGORITHM_NAME = "ML-DSA-87";

    struct OQSSIGDeleter {
        void operator()(OQS_SIG* p) { if (p) OQS_SIG_free(p); }
    };
    std::unique_ptr<OQS_SIG, OQSSIGDeleter> sig_;

    void initialize() {
        sig_.reset(OQS_SIG_new(OQS_SIG_alg_ml_dsa_87));
        if (!sig_) {
            throw std::runtime_error(
                "Failed to initialize ML-DSA-87 (liboqs not available or alg disabled)");
        }
        if (sig_->length_public_key != PUBLIC_KEY_BYTES ||
            sig_->length_secret_key != SECRET_KEY_BYTES ||
            sig_->length_signature  != SIGNATURE_BYTES) {
            throw std::runtime_error(
                "ML-DSA-87 size mismatch with FIPS 204 (expected pk=2592, sk=4896, sig=4627)");
        }
    }

public:
    MLDSAWrapper() { initialize(); }
    ~MLDSAWrapper() override = default;

    SigKeyPair generate_keypair() override {
        SigKeyPair kp;
        kp.type       = SigType::PURE_MLDSA87;
        kp.created_at = std::chrono::system_clock::now();
        kp.public_key.resize(PUBLIC_KEY_BYTES);
        kp.secret_key.resize(SECRET_KEY_BYTES);

        if (Config::instance().side_channel_protection) side_channel::random_delay();

        OQS_STATUS rv = OQS_SIG_keypair(sig_.get(),
                                        kp.public_key.data(),
                                        kp.secret_key.data());
        if (rv != OQS_SUCCESS) {
            side_channel::secure_zero_memory(kp.secret_key.data(), kp.secret_key.size());
            throw std::runtime_error("ML-DSA-87 keypair generation failed");
        }
        if (Config::instance().side_channel_protection) {
            side_channel::flush_cache_line(kp.secret_key.data());
            side_channel::memory_barrier();
        }
        return kp;
    }

    Signature sign(BytesView message,
                   const std::vector<uint8_t>& secret_key) override {
        if (secret_key.size() != SECRET_KEY_BYTES) {
            throw std::invalid_argument(
                "ML-DSA-87 secret key wrong size (expected 4896, got " +
                std::to_string(secret_key.size()) + ")");
        }
        Signature out;
        out.type = SigType::PURE_MLDSA87;
        out.bytes.resize(SIGNATURE_BYTES);
        size_t sig_len = 0;

        if (Config::instance().side_channel_protection) side_channel::random_delay();

        OQS_STATUS rv = OQS_SIG_sign(sig_.get(),
                                     out.bytes.data(), &sig_len,
                                     message.data(), message.size(),
                                     secret_key.data());
        if (rv != OQS_SUCCESS) {
            throw std::runtime_error("ML-DSA-87 sign failed");
        }
        // ML-DSA's signature is fixed length per FIPS 204; trim defensively
        // in case a future liboqs returns a shorter byte count.
        out.bytes.resize(sig_len);
        return out;
    }

    bool verify(BytesView message,
                const Signature& signature,
                const std::vector<uint8_t>& public_key) override {
        if (signature.type != SigType::PURE_MLDSA87) return false;
        if (public_key.size() != PUBLIC_KEY_BYTES)   return false;
        if (signature.bytes.size() > SIGNATURE_BYTES) return false;

        if (Config::instance().side_channel_protection) side_channel::random_delay();

        OQS_STATUS rv = OQS_SIG_verify(sig_.get(),
                                       message.data(), message.size(),
                                       signature.bytes.data(), signature.bytes.size(),
                                       public_key.data());
        return rv == OQS_SUCCESS;
    }

    SigType     get_type()        const override { return SigType::PURE_MLDSA87; }
    size_t      public_key_size() const override { return PUBLIC_KEY_BYTES; }
    size_t      secret_key_size() const override { return SECRET_KEY_BYTES; }
    size_t      signature_size()  const override { return SIGNATURE_BYTES; }
    std::string algorithm_name()  const override { return ALGORITHM_NAME; }
};

} // namespace pqc
} // namespace nocturne

#endif // NOCTURNE_ENABLE_PQC
