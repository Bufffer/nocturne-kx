/**
 * @file kem_factory.cpp
 * @brief KEM factory implementation
 */

#include "kem_interface.hpp"

#ifdef NOCTURNE_ENABLE_PQC
#include "mlkem_wrapper.hpp"
#include "hybrid_kem.hpp"
#endif

#include <sodium.h>
#include <memory>
#include <stdexcept>

namespace nocturne {
namespace pqc {

/**
 * @brief Classical X25519 KEM (fallback when PQC is disabled)
 *
 * Provides X25519 ECDH as a KEM-style interface for backward compatibility.
 * This is NOT post-quantum secure!
 */
class ClassicX25519KEM : public KEMInterface {
private:
    static constexpr size_t PK_SIZE = crypto_scalarmult_BYTES;  // 32
    static constexpr size_t SK_SIZE = crypto_scalarmult_SCALARBYTES;  // 32

public:
    KEMKeyPair generate_keypair() override {
        KEMKeyPair kp;
        kp.type = KEMType::CLASSIC_X25519;
        kp.created_at = std::chrono::system_clock::now();

        kp.public_key.resize(PK_SIZE);
        kp.secret_key.resize(SK_SIZE);

        if (crypto_box_keypair(kp.public_key.data(), kp.secret_key.data()) != 0) {
            throw std::runtime_error("X25519 keypair generation failed");
        }

        return kp;
    }

    std::pair<KEMCiphertext, KEMSharedSecret>
    encapsulate(const std::vector<uint8_t>& public_key) override {
        if (public_key.size() != PK_SIZE) {
            throw std::invalid_argument("Invalid X25519 public key size");
        }

        // Generate ephemeral keypair
        std::array<uint8_t, PK_SIZE> eph_pk;
        std::array<uint8_t, SK_SIZE> eph_sk;
        if (crypto_box_keypair(eph_pk.data(), eph_sk.data()) != 0) {
            throw std::runtime_error("X25519 ephemeral keypair failed");
        }

        // Compute DH
        std::array<uint8_t, 32> shared;
        if (crypto_scalarmult(shared.data(), eph_sk.data(), public_key.data()) != 0) {
            throw std::runtime_error("X25519 DH failed");
        }

        // Ciphertext is just the ephemeral public key
        KEMCiphertext ct;
        ct.type = KEMType::CLASSIC_X25519;
        ct.version = 3;  // Classic protocol
        ct.ciphertext.assign(eph_pk.begin(), eph_pk.end());

        KEMSharedSecret ss;
        ss.type = KEMType::CLASSIC_X25519;
        std::memcpy(ss.secret.data(), shared.data(), 32);

        // Cleanup
        sodium_memzero(eph_sk.data(), eph_sk.size());
        sodium_memzero(shared.data(), shared.size());

        return {std::move(ct), std::move(ss)};
    }

    KEMSharedSecret decapsulate(
        const KEMCiphertext& ciphertext,
        const std::vector<uint8_t>& secret_key) override {

        if (ciphertext.type != KEMType::CLASSIC_X25519) {
            throw std::invalid_argument("Ciphertext type mismatch");
        }
        if (ciphertext.ciphertext.size() != PK_SIZE) {
            throw std::invalid_argument("Invalid X25519 ciphertext size");
        }
        if (secret_key.size() != SK_SIZE) {
            throw std::invalid_argument("Invalid X25519 secret key size");
        }

        // Compute DH
        KEMSharedSecret ss;
        ss.type = KEMType::CLASSIC_X25519;

        if (crypto_scalarmult(ss.secret.data(),
                             secret_key.data(),
                             ciphertext.ciphertext.data()) != 0) {
            throw std::runtime_error("X25519 DH failed");
        }

        return ss;
    }

    KEMType get_type() const override { return KEMType::CLASSIC_X25519; }
    size_t public_key_size() const override { return PK_SIZE; }
    size_t secret_key_size() const override { return SK_SIZE; }
    size_t ciphertext_size() const override { return PK_SIZE; }
    std::string algorithm_name() const override { return "X25519"; }
};

/**
 * @brief Create KEM instance of specified type
 */
std::unique_ptr<KEMInterface> create_kem(KEMType type) {
    switch (type) {
        case KEMType::CLASSIC_X25519:
            return std::make_unique<ClassicX25519KEM>();

#ifdef NOCTURNE_ENABLE_PQC
        case KEMType::PURE_MLKEM1024:
            return std::make_unique<MLKEMWrapper>();

        case KEMType::HYBRID_X25519_MLKEM1024:
            return std::make_unique<HybridKEM>();
#else
        case KEMType::PURE_MLKEM1024:
        case KEMType::HYBRID_X25519_MLKEM1024:
            throw std::runtime_error(
                "PQC support not enabled. Recompile with ENABLE_PQC=ON");
#endif

        default:
            throw std::invalid_argument("Unknown KEM type");
    }
}

} // namespace pqc
} // namespace nocturne
