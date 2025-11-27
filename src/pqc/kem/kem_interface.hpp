/**
 * @file kem_interface.hpp
 * @brief Abstract interface for Key Encapsulation Mechanisms (KEM)
 *
 * Provides a unified interface for both classical (X25519) and post-quantum
 * (ML-KEM-1024) key exchange algorithms, as well as hybrid combinations.
 *
 * @version 4.0.0
 */

#pragma once

#include <vector>
#include <array>
#include <string>
#include <optional>
#include <chrono>
#include <cstdint>

namespace nocturne {
namespace pqc {

/**
 * @brief KEM algorithm type
 */
enum class KEMType : uint8_t {
    CLASSIC_X25519 = 0,              ///< Classical ECDH (fallback, no PQC)
    HYBRID_X25519_MLKEM1024 = 1,     ///< Hybrid: X25519 + ML-KEM-1024 (recommended)
    PURE_MLKEM1024 = 2               ///< Pure post-quantum (future mode)
};

/**
 * @brief Convert KEM type to string
 */
inline const char* kem_type_to_string(KEMType type) {
    switch (type) {
        case KEMType::CLASSIC_X25519: return "X25519";
        case KEMType::HYBRID_X25519_MLKEM1024: return "Hybrid-X25519-ML-KEM-1024";
        case KEMType::PURE_MLKEM1024: return "ML-KEM-1024";
        default: return "Unknown";
    }
}

/**
 * @brief KEM key pair structure
 *
 * Contains both public and secret keys for a KEM instance.
 * Secret keys are automatically zeroed on destruction.
 */
struct KEMKeyPair {
    std::vector<uint8_t> public_key;     ///< Public key (can be shared)
    std::vector<uint8_t> secret_key;     ///< Secret key (must be protected)
    KEMType type;                         ///< Algorithm type
    std::chrono::system_clock::time_point created_at;  ///< Creation timestamp
    std::optional<uint32_t> hsm_key_id;   ///< HSM key handle (if stored in HSM)

    /**
     * @brief Destructor - securely wipes secret key
     */
    ~KEMKeyPair();

    // Disable copy (secret keys should not be copied)
    KEMKeyPair(const KEMKeyPair&) = delete;
    KEMKeyPair& operator=(const KEMKeyPair&) = delete;

    // Allow move
    KEMKeyPair(KEMKeyPair&&) noexcept = default;
    KEMKeyPair& operator=(KEMKeyPair&&) noexcept = default;

    // Default constructor
    KEMKeyPair() : type(KEMType::CLASSIC_X25519), created_at(std::chrono::system_clock::now()) {}
};

/**
 * @brief KEM ciphertext structure
 *
 * Result of encapsulation operation. Contains encrypted shared secret.
 */
struct KEMCiphertext {
    std::vector<uint8_t> ciphertext;     ///< Encapsulated shared secret
    KEMType type;                         ///< Algorithm type
    uint32_t version;                     ///< Protocol version

    KEMCiphertext() : type(KEMType::CLASSIC_X25519), version(4) {}
};

/**
 * @brief KEM shared secret structure
 *
 * The symmetric key derived from KEM operations.
 * Always normalized to 32 bytes regardless of underlying algorithm.
 * Automatically zeroed on destruction.
 */
struct KEMSharedSecret {
    std::array<uint8_t, 32> secret;      ///< 32-byte shared secret
    KEMType type;                         ///< Algorithm type that produced this secret

    /**
     * @brief Destructor - securely wipes secret
     */
    ~KEMSharedSecret();

    // Disable copy
    KEMSharedSecret(const KEMSharedSecret&) = delete;
    KEMSharedSecret& operator=(const KEMSharedSecret&) = delete;

    // Allow move
    KEMSharedSecret(KEMSharedSecret&&) noexcept = default;
    KEMSharedSecret& operator=(KEMSharedSecret&&) noexcept = default;

    // Default constructor
    KEMSharedSecret() : type(KEMType::CLASSIC_X25519) { secret.fill(0); }
};

/**
 * @brief Abstract KEM interface
 *
 * All KEM implementations (classical, post-quantum, hybrid) must implement
 * this interface for interoperability.
 */
class KEMInterface {
public:
    virtual ~KEMInterface() = default;

    /**
     * @brief Generate a new KEM keypair
     *
     * @return KEMKeyPair with freshly generated keys
     * @throws std::runtime_error if key generation fails
     */
    virtual KEMKeyPair generate_keypair() = 0;

    /**
     * @brief Encapsulate a shared secret (sender side)
     *
     * Given the receiver's public key, generate a random shared secret
     * and encapsulate it so only the receiver can extract it.
     *
     * @param public_key Receiver's public key
     * @return Pair of (ciphertext, shared_secret)
     * @throws std::invalid_argument if public_key is malformed
     * @throws std::runtime_error if encapsulation fails
     */
    virtual std::pair<KEMCiphertext, KEMSharedSecret>
        encapsulate(const std::vector<uint8_t>& public_key) = 0;

    /**
     * @brief Decapsulate a shared secret (receiver side)
     *
     * Given a ciphertext and the receiver's secret key, extract the
     * shared secret that the sender encapsulated.
     *
     * @param ciphertext Encapsulated shared secret
     * @param secret_key Receiver's secret key
     * @return KEMSharedSecret extracted from ciphertext
     * @throws std::invalid_argument if inputs are malformed
     * @throws std::runtime_error if decapsulation fails (wrong key, corrupted ct)
     */
    virtual KEMSharedSecret decapsulate(
        const KEMCiphertext& ciphertext,
        const std::vector<uint8_t>& secret_key) = 0;

    /**
     * @brief Get the KEM type
     */
    virtual KEMType get_type() const = 0;

    /**
     * @brief Get public key size in bytes
     */
    virtual size_t public_key_size() const = 0;

    /**
     * @brief Get secret key size in bytes
     */
    virtual size_t secret_key_size() const = 0;

    /**
     * @brief Get ciphertext size in bytes
     */
    virtual size_t ciphertext_size() const = 0;

    /**
     * @brief Get algorithm name (human-readable)
     */
    virtual std::string algorithm_name() const = 0;
};

/**
 * @brief KEM factory function
 *
 * Creates a KEM instance of the specified type.
 *
 * @param type KEM algorithm to instantiate
 * @return Unique pointer to KEMInterface implementation
 * @throws std::runtime_error if type is not supported or PQC is disabled
 */
std::unique_ptr<KEMInterface> create_kem(KEMType type);

} // namespace pqc
} // namespace nocturne
