/**
 * @file mlkem_wrapper.hpp
 * @brief ML-KEM-1024 (CRYSTALS-Kyber) wrapper using liboqs
 *
 * NIST FIPS 203 compliant Key Encapsulation Mechanism.
 * Security level: NIST PQC Level 5 (equivalent to AES-256)
 *
 * Wire format compatibility:
 * - Public key: 1,568 bytes
 * - Secret key: 3,168 bytes
 * - Ciphertext: 1,568 bytes
 * - Shared secret: 32 bytes
 *
 * Performance (typical Intel i7):
 * - Keygen: ~50 µs
 * - Encaps: ~70 µs
 * - Decaps: ~80 µs
 *
 * @warning This is a lattice-based scheme. While standardized by NIST,
 *          use in hybrid mode (X25519+ML-KEM) for defense-in-depth.
 *
 * @version 4.0.0
 */

#pragma once

#include "kem_interface.hpp"
#include "../pqc_config.hpp"
#include "../../core/side_channel.hpp"

#ifdef NOCTURNE_ENABLE_PQC
#include <oqs/oqs.h>
#include <sodium.h>
#include <memory>
#include <stdexcept>

namespace nocturne {
namespace pqc {

/**
 * @brief ML-KEM-1024 wrapper class
 *
 * Provides RAII wrapper around liboqs ML-KEM-1024 implementation
 * with automatic cleanup and side-channel protection.
 */
class MLKEMWrapper : public KEMInterface {
private:
    // FIPS 203 constants for ML-KEM-1024
    static constexpr const char* ALGORITHM_NAME = "ML-KEM-1024";
    static constexpr size_t PUBLIC_KEY_BYTES = 1568;
    static constexpr size_t SECRET_KEY_BYTES = 3168;
    static constexpr size_t CIPHERTEXT_BYTES = 1568;
    static constexpr size_t SHARED_SECRET_BYTES = 32;

    /**
     * @brief RAII deleter for OQS_KEM
     */
    struct OQSKEMDeleter {
        void operator()(OQS_KEM* kem) {
            if (kem) {
                OQS_KEM_free(kem);
            }
        }
    };

    std::unique_ptr<OQS_KEM, OQSKEMDeleter> kem_;

    /**
     * @brief Initialize liboqs KEM instance
     * @throws std::runtime_error if initialization fails
     */
    void initialize() {
        kem_.reset(OQS_KEM_new(OQS_KEM_alg_ml_kem_1024));
        if (!kem_) {
            throw std::runtime_error("Failed to initialize ML-KEM-1024 (liboqs not available)");
        }

        // Verify algorithm parameters match FIPS 203
        if (kem_->length_public_key != PUBLIC_KEY_BYTES ||
            kem_->length_secret_key != SECRET_KEY_BYTES ||
            kem_->length_ciphertext != CIPHERTEXT_BYTES ||
            kem_->length_shared_secret != SHARED_SECRET_BYTES) {
            throw std::runtime_error(
                "ML-KEM-1024 size mismatch with FIPS 203 specification. "
                "Expected pk=1568, sk=3168, ct=1568, ss=32 bytes.");
        }
    }

public:
    /**
     * @brief Constructor - initializes ML-KEM-1024
     */
    MLKEMWrapper() {
        initialize();
    }

    /**
     * @brief Destructor - secure cleanup
     */
    ~MLKEMWrapper() override = default;

    /**
     * @brief Generate ML-KEM-1024 keypair
     *
     * Uses secure random number generation from liboqs (which uses OS RNG).
     * Applies side-channel protections during generation.
     *
     * @return KEMKeyPair with public and secret keys
     * @throws std::runtime_error if key generation fails
     */
    KEMKeyPair generate_keypair() override {
        KEMKeyPair kp;
        kp.type = KEMType::PURE_MLKEM1024;
        kp.created_at = std::chrono::system_clock::now();

        // Allocate buffers
        kp.public_key.resize(PUBLIC_KEY_BYTES);
        kp.secret_key.resize(SECRET_KEY_BYTES);

        // Side-channel protection: random delay
        if (Config::instance().side_channel_protection) {
            side_channel_protection::random_delay();
        }

        // Generate keypair via liboqs
        OQS_STATUS status = OQS_KEM_keypair(
            kem_.get(),
            kp.public_key.data(),
            kp.secret_key.data()
        );

        if (status != OQS_SUCCESS) {
            // Secure cleanup on error
            side_channel_protection::secure_zero_memory(
                kp.secret_key.data(), kp.secret_key.size());
            throw std::runtime_error("ML-KEM-1024 keypair generation failed (OQS_KEM_keypair)");
        }

        // Side-channel protection: flush cache
        if (Config::instance().side_channel_protection) {
            side_channel_protection::flush_cache_line(kp.secret_key.data());
            side_channel_protection::memory_barrier();
        }

        // Verbose logging
        if (Config::instance().verbose_logging) {
            // Note: In production, don't log key material!
            std::cerr << "[PQC] ML-KEM-1024 keypair generated (pk="
                      << kp.public_key.size() << "B, sk="
                      << kp.secret_key.size() << "B)" << std::endl;
        }

        return kp;
    }

    /**
     * @brief Encapsulate shared secret (sender side)
     *
     * Given receiver's public key, generates random shared secret
     * and encapsulates it using ML-KEM-1024.
     *
     * @param public_key Receiver's ML-KEM-1024 public key (1,568 bytes)
     * @return Pair of (ciphertext, shared_secret)
     * @throws std::invalid_argument if public_key size is wrong
     * @throws std::runtime_error if encapsulation fails
     */
    std::pair<KEMCiphertext, KEMSharedSecret>
    encapsulate(const std::vector<uint8_t>& public_key) override {
        // Validate input
        if (public_key.size() != PUBLIC_KEY_BYTES) {
            throw std::invalid_argument(
                "Invalid ML-KEM-1024 public key size: expected " +
                std::to_string(PUBLIC_KEY_BYTES) + " bytes, got " +
                std::to_string(public_key.size()) + " bytes");
        }

        // Prepare output structures
        KEMCiphertext ct;
        ct.type = KEMType::PURE_MLKEM1024;
        ct.version = NOCTURNE_PROTOCOL_VERSION;
        ct.ciphertext.resize(CIPHERTEXT_BYTES);

        KEMSharedSecret ss;
        ss.type = KEMType::PURE_MLKEM1024;

        // Side-channel protection: random delay
        if (Config::instance().side_channel_protection) {
            side_channel_protection::random_delay();
        }

        // Encapsulation via liboqs
        OQS_STATUS status = OQS_KEM_encaps(
            kem_.get(),
            ct.ciphertext.data(),
            ss.secret.data(),
            public_key.data()
        );

        if (status != OQS_SUCCESS) {
            // Secure cleanup
            side_channel_protection::secure_zero_memory(
                ss.secret.data(), ss.secret.size());
            throw std::runtime_error("ML-KEM-1024 encapsulation failed (OQS_KEM_encaps)");
        }

        // Side-channel protection: flush
        if (Config::instance().side_channel_protection) {
            side_channel_protection::flush_cache_line(ss.secret.data());
            side_channel_protection::memory_barrier();
        }

        if (Config::instance().verbose_logging) {
            std::cerr << "[PQC] ML-KEM-1024 encapsulation: ct="
                      << ct.ciphertext.size() << "B" << std::endl;
        }

        return {std::move(ct), std::move(ss)};
    }

    /**
     * @brief Decapsulate shared secret (receiver side)
     *
     * Given ciphertext and receiver's secret key, extracts the
     * shared secret using ML-KEM-1024 decapsulation.
     *
     * @param ciphertext Encapsulated shared secret (1,568 bytes)
     * @param secret_key Receiver's ML-KEM-1024 secret key (3,168 bytes)
     * @return KEMSharedSecret (32 bytes)
     * @throws std::invalid_argument if inputs are malformed
     * @throws std::runtime_error if decapsulation fails
     */
    KEMSharedSecret decapsulate(
        const KEMCiphertext& ciphertext,
        const std::vector<uint8_t>& secret_key) override {

        // Validate type
        if (ciphertext.type != KEMType::PURE_MLKEM1024) {
            throw std::invalid_argument(
                "Ciphertext type mismatch: expected PURE_MLKEM1024, got " +
                std::string(kem_type_to_string(ciphertext.type)));
        }

        // Validate sizes
        if (ciphertext.ciphertext.size() != CIPHERTEXT_BYTES) {
            throw std::invalid_argument(
                "Invalid ML-KEM-1024 ciphertext size: expected " +
                std::to_string(CIPHERTEXT_BYTES) + " bytes, got " +
                std::to_string(ciphertext.ciphertext.size()) + " bytes");
        }

        if (secret_key.size() != SECRET_KEY_BYTES) {
            throw std::invalid_argument(
                "Invalid ML-KEM-1024 secret key size: expected " +
                std::to_string(SECRET_KEY_BYTES) + " bytes, got " +
                std::to_string(secret_key.size()) + " bytes");
        }

        KEMSharedSecret ss;
        ss.type = KEMType::PURE_MLKEM1024;

        // Side-channel protection: random delay
        if (Config::instance().side_channel_protection) {
            side_channel_protection::random_delay();
        }

        // Decapsulation via liboqs
        OQS_STATUS status = OQS_KEM_decaps(
            kem_.get(),
            ss.secret.data(),
            ciphertext.ciphertext.data(),
            secret_key.data()
        );

        if (status != OQS_SUCCESS) {
            // Secure cleanup
            side_channel_protection::secure_zero_memory(
                ss.secret.data(), ss.secret.size());

            // Constant-time error handling (prevent timing oracle)
            if (Config::instance().side_channel_protection) {
                side_channel_protection::random_delay();
            }

            throw std::runtime_error(
                "ML-KEM-1024 decapsulation failed (OQS_KEM_decaps). "
                "Possible causes: wrong secret key, corrupted ciphertext, or memory error.");
        }

        // Side-channel protection: flush
        if (Config::instance().side_channel_protection) {
            side_channel_protection::flush_cache_line(ss.secret.data());
            side_channel_protection::memory_barrier();
        }

        if (Config::instance().verbose_logging) {
            std::cerr << "[PQC] ML-KEM-1024 decapsulation: ss=32B" << std::endl;
        }

        return ss;
    }

    // Metadata methods
    KEMType get_type() const override {
        return KEMType::PURE_MLKEM1024;
    }

    size_t public_key_size() const override {
        return PUBLIC_KEY_BYTES;
    }

    size_t secret_key_size() const override {
        return SECRET_KEY_BYTES;
    }

    size_t ciphertext_size() const override {
        return CIPHERTEXT_BYTES;
    }

    std::string algorithm_name() const override {
        return ALGORITHM_NAME;
    }
};

} // namespace pqc
} // namespace nocturne

#endif // NOCTURNE_ENABLE_PQC
