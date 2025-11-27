/**
 * @file hybrid_kem.hpp
 * @brief Hybrid KEM combining X25519 (classical) and ML-KEM-1024 (post-quantum)
 *
 * Security model: Both underlying KEMs must be broken for the hybrid to be insecure.
 * This provides "defense-in-depth" against cryptanalysis advances.
 *
 * Construction follows NIST SP 800-56Cr2 recommendations:
 * 1. Perform X25519 ECDH
 * 2. Perform ML-KEM-1024 encapsulation/decapsulation
 * 3. Combine secrets: shared_secret = KDF(x25519_secret || mlkem_secret || context)
 *
 * Wire format (encapsulation):
 *   [1 byte version][32 bytes X25519 ephemeral pk][1568 bytes ML-KEM ciphertext]
 *   Total overhead: 1,601 bytes per key exchange
 *
 * @note This is the RECOMMENDED default for production use.
 * @version 4.0.0
 */

#pragma once

#include "kem_interface.hpp"
#include "mlkem_wrapper.hpp"
#include "../pqc_config.hpp"
#include "../../core/side_channel.hpp"

#ifdef NOCTURNE_ENABLE_PQC
#include <sodium.h>
#include <array>
#include <cstring>

namespace nocturne {
namespace pqc {

/**
 * @brief Hybrid KEM: X25519 + ML-KEM-1024
 *
 * Provides quantum-resistant key exchange by combining classical
 * ECDH (X25519) with post-quantum lattice-based KEM (ML-KEM-1024).
 */
class HybridKEM : public KEMInterface {
private:
    MLKEMWrapper mlkem_;

    // X25519 key sizes
    static constexpr size_t X25519_PK_SIZE = crypto_scalarmult_BYTES;  // 32
    static constexpr size_t X25519_SK_SIZE = crypto_scalarmult_SCALARBYTES;  // 32

    // Combined sizes
    static constexpr size_t HYBRID_PK_SIZE = X25519_PK_SIZE + 1568;  // 1600 bytes
    static constexpr size_t HYBRID_SK_SIZE = X25519_SK_SIZE + 3168;  // 3200 bytes
    static constexpr size_t HYBRID_CT_SIZE = 1 + X25519_PK_SIZE + 1568;  // 1601 bytes (with version)

    /**
     * @brief Combine two shared secrets using domain-separated KDF
     *
     * Uses BLAKE2b-256 with the following structure:
     *   combined = BLAKE2b-256(
     *       key = "nocturne-hybrid-kem-v1",
     *       data = x25519_secret || mlkem_secret || version || context
     *   )
     *
     * Domain separation prevents cross-protocol attacks.
     *
     * @param x25519_secret X25519 DH shared secret (32 bytes)
     * @param mlkem_secret ML-KEM-1024 shared secret (32 bytes)
     * @param version Protocol version (4 bytes, big-endian)
     * @param context Optional context string for binding
     * @return Combined 32-byte shared secret
     */
    std::array<uint8_t, 32> combine_secrets(
        const std::array<uint8_t, 32>& x25519_secret,
        const std::array<uint8_t, 32>& mlkem_secret,
        uint32_t version,
        const std::string& context = "") {

        std::array<uint8_t, 32> combined;

        // Domain separation key (prevents cross-protocol attacks)
        const char* domain = "nocturne-hybrid-kem-v1";

        // Build input: x25519_secret || mlkem_secret || version || context
        std::vector<uint8_t> input;
        input.reserve(64 + 4 + context.size());

        // Append X25519 secret
        input.insert(input.end(), x25519_secret.begin(), x25519_secret.end());

        // Append ML-KEM secret
        input.insert(input.end(), mlkem_secret.begin(), mlkem_secret.end());

        // Append version (big-endian, 4 bytes)
        input.push_back(static_cast<uint8_t>((version >> 24) & 0xFF));
        input.push_back(static_cast<uint8_t>((version >> 16) & 0xFF));
        input.push_back(static_cast<uint8_t>((version >> 8) & 0xFF));
        input.push_back(static_cast<uint8_t>(version & 0xFF));

        // Append optional context
        if (!context.empty()) {
            input.insert(input.end(), context.begin(), context.end());
        }

        // KDF: BLAKE2b with keyed hashing
        if (crypto_generichash(
                combined.data(), combined.size(),
                input.data(), input.size(),
                reinterpret_cast<const uint8_t*>(domain), std::strlen(domain)) != 0) {
            // Secure cleanup before throwing
            side_channel_protection::secure_zero_memory(input.data(), input.size());
            throw std::runtime_error("Hybrid KDF (BLAKE2b) failed");
        }

        // Secure cleanup of intermediate values
        side_channel_protection::secure_zero_memory(input.data(), input.size());

        if (Config::instance().verbose_logging) {
            std::cerr << "[PQC] Hybrid KDF: combined " << x25519_secret.size()
                      << "B + " << mlkem_secret.size() << "B -> 32B" << std::endl;
        }

        return combined;
    }

public:
    /**
     * @brief Constructor
     */
    HybridKEM() = default;

    /**
     * @brief Destructor
     */
    ~HybridKEM() override = default;

    /**
     * @brief Generate hybrid keypair (X25519 + ML-KEM-1024)
     *
     * @return KEMKeyPair with hybrid public/secret keys
     * @throws std::runtime_error if key generation fails
     */
    KEMKeyPair generate_keypair() override {
        KEMKeyPair hybrid_kp;
        hybrid_kp.type = KEMType::HYBRID_X25519_MLKEM1024;
        hybrid_kp.created_at = std::chrono::system_clock::now();

        // 1. Generate X25519 keypair
        std::array<uint8_t, X25519_PK_SIZE> x25519_pk;
        std::array<uint8_t, X25519_SK_SIZE> x25519_sk;

        if (crypto_box_keypair(x25519_pk.data(), x25519_sk.data()) != 0) {
            throw std::runtime_error("X25519 keypair generation failed");
        }

        // 2. Generate ML-KEM-1024 keypair
        auto mlkem_kp = mlkem_.generate_keypair();

        // 3. Combine public keys: [x25519_pk || mlkem_pk]
        hybrid_kp.public_key.reserve(HYBRID_PK_SIZE);
        hybrid_kp.public_key.insert(hybrid_kp.public_key.end(),
                                    x25519_pk.begin(), x25519_pk.end());
        hybrid_kp.public_key.insert(hybrid_kp.public_key.end(),
                                    mlkem_kp.public_key.begin(),
                                    mlkem_kp.public_key.end());

        // 4. Combine secret keys: [x25519_sk || mlkem_sk]
        hybrid_kp.secret_key.reserve(HYBRID_SK_SIZE);
        hybrid_kp.secret_key.insert(hybrid_kp.secret_key.end(),
                                    x25519_sk.begin(), x25519_sk.end());
        hybrid_kp.secret_key.insert(hybrid_kp.secret_key.end(),
                                    mlkem_kp.secret_key.begin(),
                                    mlkem_kp.secret_key.end());

        // Secure cleanup of temporary keys
        side_channel_protection::secure_zero_memory(x25519_sk.data(), x25519_sk.size());
        side_channel_protection::secure_zero_memory(
            mlkem_kp.secret_key.data(), mlkem_kp.secret_key.size());

        if (Config::instance().verbose_logging) {
            std::cerr << "[PQC] Hybrid keypair: pk=" << hybrid_kp.public_key.size()
                      << "B, sk=" << hybrid_kp.secret_key.size() << "B" << std::endl;
        }

        return hybrid_kp;
    }

    /**
     * @brief Encapsulate shared secret using hybrid KEM
     *
     * @param public_key Receiver's hybrid public key (1,600 bytes)
     * @return Pair of (hybrid_ciphertext, shared_secret)
     * @throws std::invalid_argument if public_key is malformed
     * @throws std::runtime_error if encapsulation fails
     */
    std::pair<KEMCiphertext, KEMSharedSecret>
    encapsulate(const std::vector<uint8_t>& public_key) override {

        // Validate input size
        if (public_key.size() != HYBRID_PK_SIZE) {
            throw std::invalid_argument(
                "Invalid hybrid public key size: expected " +
                std::to_string(HYBRID_PK_SIZE) + " bytes, got " +
                std::to_string(public_key.size()) + " bytes");
        }

        // Parse hybrid public key
        std::array<uint8_t, X25519_PK_SIZE> x25519_peer_pk;
        std::memcpy(x25519_peer_pk.data(), public_key.data(), X25519_PK_SIZE);

        std::vector<uint8_t> mlkem_pk(
            public_key.begin() + X25519_PK_SIZE,
            public_key.end()
        );

        // 1. X25519: Generate ephemeral keypair + compute DH
        std::array<uint8_t, X25519_PK_SIZE> x25519_eph_pk;
        std::array<uint8_t, X25519_SK_SIZE> x25519_eph_sk;
        std::array<uint8_t, 32> x25519_shared;

        if (crypto_box_keypair(x25519_eph_pk.data(), x25519_eph_sk.data()) != 0) {
            throw std::runtime_error("X25519 ephemeral keypair generation failed");
        }

        if (crypto_scalarmult(x25519_shared.data(),
                             x25519_eph_sk.data(),
                             x25519_peer_pk.data()) != 0) {
            side_channel_protection::secure_zero_memory(x25519_eph_sk.data(), X25519_SK_SIZE);
            side_channel_protection::secure_zero_memory(x25519_shared.data(), 32);
            throw std::runtime_error("X25519 key exchange failed (invalid public key?)");
        }

        // 2. ML-KEM-1024: Encapsulate
        auto [mlkem_ct, mlkem_ss] = mlkem_.encapsulate(mlkem_pk);

        // 3. Combine secrets
        auto combined_secret = combine_secrets(
            x25519_shared, mlkem_ss.secret, NOCTURNE_PROTOCOL_VERSION, "encapsulation");

        // 4. Build hybrid ciphertext: [version || x25519_eph_pk || mlkem_ct]
        KEMCiphertext hybrid_ct;
        hybrid_ct.type = KEMType::HYBRID_X25519_MLKEM1024;
        hybrid_ct.version = NOCTURNE_PROTOCOL_VERSION;
        hybrid_ct.ciphertext.reserve(HYBRID_CT_SIZE);

        // Version byte
        hybrid_ct.ciphertext.push_back(static_cast<uint8_t>(NOCTURNE_PROTOCOL_VERSION));

        // X25519 ephemeral public key
        hybrid_ct.ciphertext.insert(hybrid_ct.ciphertext.end(),
                                    x25519_eph_pk.begin(), x25519_eph_pk.end());

        // ML-KEM ciphertext
        hybrid_ct.ciphertext.insert(hybrid_ct.ciphertext.end(),
                                    mlkem_ct.ciphertext.begin(),
                                    mlkem_ct.ciphertext.end());

        // 5. Build shared secret
        KEMSharedSecret hybrid_ss;
        hybrid_ss.type = KEMType::HYBRID_X25519_MLKEM1024;
        std::memcpy(hybrid_ss.secret.data(), combined_secret.data(), 32);

        // Secure cleanup
        side_channel_protection::secure_zero_memory(x25519_eph_sk.data(), X25519_SK_SIZE);
        side_channel_protection::secure_zero_memory(x25519_shared.data(), 32);
        side_channel_protection::secure_zero_memory(mlkem_ss.secret.data(), 32);
        side_channel_protection::secure_zero_memory(combined_secret.data(), 32);

        if (Config::instance().verbose_logging) {
            std::cerr << "[PQC] Hybrid encaps: ct=" << hybrid_ct.ciphertext.size()
                      << "B (X25519:" << X25519_PK_SIZE << "B + ML-KEM:1568B)" << std::endl;
        }

        return {std::move(hybrid_ct), std::move(hybrid_ss)};
    }

    /**
     * @brief Decapsulate shared secret using hybrid KEM
     *
     * @param ciphertext Hybrid ciphertext (1,601 bytes)
     * @param secret_key Receiver's hybrid secret key (3,200 bytes)
     * @return KEMSharedSecret (32 bytes)
     * @throws std::invalid_argument if inputs are malformed
     * @throws std::runtime_error if decapsulation fails
     */
    KEMSharedSecret decapsulate(
        const KEMCiphertext& ciphertext,
        const std::vector<uint8_t>& secret_key) override {

        // Validate type
        if (ciphertext.type != KEMType::HYBRID_X25519_MLKEM1024) {
            throw std::invalid_argument(
                "Ciphertext type mismatch: expected HYBRID_X25519_MLKEM1024");
        }

        // Validate sizes
        if (ciphertext.ciphertext.size() != HYBRID_CT_SIZE) {
            throw std::invalid_argument(
                "Invalid hybrid ciphertext size: expected " +
                std::to_string(HYBRID_CT_SIZE) + " bytes, got " +
                std::to_string(ciphertext.ciphertext.size()) + " bytes");
        }

        if (secret_key.size() != HYBRID_SK_SIZE) {
            throw std::invalid_argument(
                "Invalid hybrid secret key size: expected " +
                std::to_string(HYBRID_SK_SIZE) + " bytes, got " +
                std::to_string(secret_key.size()) + " bytes");
        }

        // Parse hybrid secret key
        std::array<uint8_t, X25519_SK_SIZE> x25519_sk;
        std::memcpy(x25519_sk.data(), secret_key.data(), X25519_SK_SIZE);

        std::vector<uint8_t> mlkem_sk(
            secret_key.begin() + X25519_SK_SIZE,
            secret_key.end()
        );

        // Parse hybrid ciphertext
        uint8_t version = ciphertext.ciphertext[0];
        if (version != NOCTURNE_PROTOCOL_VERSION) {
            throw std::runtime_error(
                "Protocol version mismatch: expected " +
                std::to_string(NOCTURNE_PROTOCOL_VERSION) + ", got " +
                std::to_string(version));
        }

        std::array<uint8_t, X25519_PK_SIZE> x25519_eph_pk;
        std::memcpy(x25519_eph_pk.data(), ciphertext.ciphertext.data() + 1, X25519_PK_SIZE);

        KEMCiphertext mlkem_ct;
        mlkem_ct.type = KEMType::PURE_MLKEM1024;
        mlkem_ct.version = ciphertext.version;
        mlkem_ct.ciphertext.assign(
            ciphertext.ciphertext.begin() + 1 + X25519_PK_SIZE,
            ciphertext.ciphertext.end()
        );

        // 1. X25519: Compute DH
        std::array<uint8_t, 32> x25519_shared;
        if (crypto_scalarmult(x25519_shared.data(),
                             x25519_sk.data(),
                             x25519_eph_pk.data()) != 0) {
            side_channel_protection::secure_zero_memory(x25519_sk.data(), X25519_SK_SIZE);
            side_channel_protection::secure_zero_memory(x25519_shared.data(), 32);
            throw std::runtime_error("X25519 key exchange failed (invalid ephemeral key?)");
        }

        // 2. ML-KEM-1024: Decapsulate
        auto mlkem_ss = mlkem_.decapsulate(mlkem_ct, mlkem_sk);

        // 3. Combine secrets
        auto combined_secret = combine_secrets(
            x25519_shared, mlkem_ss.secret, ciphertext.version, "encapsulation");

        // 4. Build shared secret
        KEMSharedSecret hybrid_ss;
        hybrid_ss.type = KEMType::HYBRID_X25519_MLKEM1024;
        std::memcpy(hybrid_ss.secret.data(), combined_secret.data(), 32);

        // Secure cleanup
        side_channel_protection::secure_zero_memory(x25519_sk.data(), X25519_SK_SIZE);
        side_channel_protection::secure_zero_memory(x25519_shared.data(), 32);
        side_channel_protection::secure_zero_memory(mlkem_ss.secret.data(), 32);
        side_channel_protection::secure_zero_memory(mlkem_sk.data(), mlkem_sk.size());
        side_channel_protection::secure_zero_memory(combined_secret.data(), 32);

        if (Config::instance().verbose_logging) {
            std::cerr << "[PQC] Hybrid decaps: ss=32B" << std::endl;
        }

        return hybrid_ss;
    }

    // Metadata methods
    KEMType get_type() const override {
        return KEMType::HYBRID_X25519_MLKEM1024;
    }

    size_t public_key_size() const override {
        return HYBRID_PK_SIZE;
    }

    size_t secret_key_size() const override {
        return HYBRID_SK_SIZE;
    }

    size_t ciphertext_size() const override {
        return HYBRID_CT_SIZE;
    }

    std::string algorithm_name() const override {
        return "Hybrid-X25519-ML-KEM-1024";
    }
};

} // namespace pqc
} // namespace nocturne

#endif // NOCTURNE_ENABLE_PQC
