#ifndef NOCTURNE_HSM_INTERFACE_HPP
#define NOCTURNE_HSM_INTERFACE_HPP

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>
#include <chrono>
#include <sodium.h>

namespace nocturne {
namespace hsm {

/**
 * @brief HSM key policy for access control
 */
struct KeyPolicy {
    bool require_authentication = true;      ///< Require PIN/passphrase
    bool allow_export = false;               ///< Allow key export (wrapped)
    bool extractable = false;                ///< Can key leave HSM (plain)
    bool sensitive = true;                   ///< Sensitive key (never export)
    uint32_t max_operations = 0;             ///< 0 = unlimited
    std::chrono::seconds max_lifetime{0};    ///< 0 = no expiration
    bool require_dual_control = false;       ///< Require 2+ approvals
};

/**
 * @brief HSM key metadata
 */
struct KeyMetadata {
    std::string label;                       ///< Key label/identifier
    std::string key_id;                      ///< Unique key ID (hex)
    std::string algorithm;                   ///< e.g., "Ed25519", "RSA-2048"
    KeyPolicy policy;                        ///< Access control policy
    std::chrono::system_clock::time_point created_at;
    std::chrono::system_clock::time_point expires_at;
    uint64_t operation_count = 0;            ///< Total operations performed
    bool is_active = true;                   ///< Key is active
};

/**
 * @brief HSM status information
 */
struct HSMStatus {
    bool initialized = false;                ///< HSM initialized
    bool authenticated = false;              ///< User authenticated
    bool fips_mode = false;                  ///< FIPS 140-3 mode
    std::string firmware_version;            ///< Firmware version
    std::string serial_number;               ///< HSM serial number
    uint32_t free_memory_kb = 0;             ///< Free memory (KB)
    uint32_t key_count = 0;                  ///< Total keys stored
    std::chrono::system_clock::time_point last_health_check;
};

/**
 * @brief Audit record for HSM operations
 */
struct AuditRecord {
    std::chrono::system_clock::time_point timestamp;
    std::string operation;                   ///< e.g., "SIGN", "VERIFY", "GENERATE_KEY"
    std::string key_label;                   ///< Key involved
    std::string result;                      ///< "SUCCESS" or "FAILURE"
    std::optional<std::string> error_message;
    std::string operator_id;                 ///< User/process ID
};

/**
 * @brief Wrapped key blob for backup/export
 */
struct EncryptedKeyBlob {
    std::vector<uint8_t> encrypted_key;      ///< Encrypted key material
    std::vector<uint8_t> nonce;              ///< Nonce/IV
    std::vector<uint8_t> auth_tag;           ///< Authentication tag
    std::string wrap_key_id;                 ///< ID of wrapping key
    std::string algorithm;                   ///< Encryption algorithm
    std::chrono::system_clock::time_point created_at;
};

/**
 * @brief Key rotation policy
 */
struct RotationPolicy {
    enum class Trigger {
        TIME_BASED,                          ///< Rotate every N days
        COUNT_BASED,                         ///< Rotate after N operations
        MANUAL,                              ///< Manual rotation only
        COMPROMISE                           ///< Emergency rotation
    };

    Trigger trigger_type = Trigger::TIME_BASED;
    std::chrono::seconds rotation_interval{30 * 24 * 3600}; ///< 30 days default
    uint64_t max_operations = 1'000'000;     ///< Max ops before rotation
    bool archive_old_keys = true;            ///< Keep old keys for decrypt
    std::chrono::seconds archive_retention{365 * 24 * 3600}; ///< 1 year
};

/**
 * @brief Abstract HSM interface (PKCS#11, TPM, FileHSM)
 *
 * This interface provides a unified API for interacting with Hardware Security Modules,
 * Trusted Platform Modules, and file-based key storage (development only).
 *
 * Security guarantees:
 * - Keys never leave HSM in plaintext (except FileHSM for development)
 * - All cryptographic operations performed inside HSM
 * - Comprehensive audit logging
 * - FIPS 140-3 Level 3+ compliance (where supported)
 */
class HSMInterface {
public:
    virtual ~HSMInterface() = default;

    // ==================== Core Cryptographic Operations ====================

    /**
     * @brief Sign data using Ed25519 (deterministic, RFC 8032)
     * @param data Data to sign
     * @param len Length of data
     * @return 64-byte Ed25519 signature
     * @throws HSMError if signing fails
     */
    virtual std::array<uint8_t, crypto_sign_BYTES> sign(
        const uint8_t* data,
        size_t len
    ) = 0;

    /**
     * @brief Verify Ed25519 signature
     * @param data Data that was signed
     * @param len Length of data
     * @param signature 64-byte signature
     * @param sig_len Signature length (must be 64)
     * @return true if valid, false otherwise
     */
    virtual bool verify(
        const uint8_t* data,
        size_t len,
        const uint8_t* signature,
        size_t sig_len
    ) = 0;

    /**
     * @brief Encrypt data using authenticated encryption (AEAD)
     * @param plaintext Data to encrypt
     * @param pt_len Length of plaintext
     * @param aad Additional authenticated data (optional)
     * @param aad_len Length of AAD
     * @param ciphertext Output buffer (must be pt_len + tag_len)
     * @param ct_len Output ciphertext length
     * @return true on success
     */
    virtual bool encrypt(
        const uint8_t* plaintext,
        size_t pt_len,
        const uint8_t* aad,
        size_t aad_len,
        uint8_t* ciphertext,
        size_t* ct_len
    ) {
        // Default: not implemented (optional operation)
        (void)plaintext; (void)pt_len; (void)aad; (void)aad_len;
        (void)ciphertext; (void)ct_len;
        return false;
    }

    /**
     * @brief Decrypt data using authenticated encryption (AEAD)
     * @param ciphertext Data to decrypt
     * @param ct_len Length of ciphertext
     * @param aad Additional authenticated data (optional)
     * @param aad_len Length of AAD
     * @param plaintext Output buffer
     * @param pt_len Output plaintext length
     * @return true on success, false if authentication fails
     */
    virtual bool decrypt(
        const uint8_t* ciphertext,
        size_t ct_len,
        const uint8_t* aad,
        size_t aad_len,
        uint8_t* plaintext,
        size_t* pt_len
    ) {
        // Default: not implemented (optional operation)
        (void)ciphertext; (void)ct_len; (void)aad; (void)aad_len;
        (void)plaintext; (void)pt_len;
        return false;
    }

    // ==================== Key Management ====================

    /**
     * @brief Generate new key pair
     * @param label Key label
     * @param algorithm Algorithm ("Ed25519", "X25519", "RSA-2048")
     * @param policy Access control policy
     * @return Key metadata
     */
    virtual KeyMetadata generate_key(
        const std::string& label,
        const std::string& algorithm,
        const KeyPolicy& policy
    ) {
        // Default: not implemented
        (void)label; (void)algorithm; (void)policy;
        throw std::runtime_error("generate_key not implemented");
    }

    /**
     * @brief Import existing key
     * @param label Key label
     * @param key_material Key bytes (will be zeroed after import)
     * @param algorithm Algorithm identifier
     * @param policy Access control policy
     * @return Key metadata
     */
    virtual KeyMetadata import_key(
        const std::string& label,
        std::vector<uint8_t>& key_material,
        const std::string& algorithm,
        const KeyPolicy& policy
    ) {
        // Default: not implemented
        (void)label; (void)key_material; (void)algorithm; (void)policy;
        throw std::runtime_error("import_key not implemented");
    }

    /**
     * @brief Get public key for signing/verification
     * @return 32-byte Ed25519 public key (optional if not available)
     */
    virtual std::optional<std::array<uint8_t, crypto_sign_PUBLICKEYBYTES>> get_public_key() = 0;

    /**
     * @brief Check if key exists
     * @param label Key label
     * @return true if key exists
     */
    virtual bool has_key(const std::string& label) = 0;

    /**
     * @brief Delete key (if policy allows)
     * @param label Key label
     * @return true on success
     */
    virtual bool delete_key(const std::string& label) {
        (void)label;
        return false; // Default: not allowed
    }

    /**
     * @brief List all keys
     * @return Vector of key metadata
     */
    virtual std::vector<KeyMetadata> list_keys() {
        return {}; // Default: empty
    }

    // ==================== Key Rotation ====================

    /**
     * @brief Rotate key (generate new, archive old)
     * @param old_label Current key label
     * @param new_label New key label
     * @param policy Rotation policy
     * @return New key metadata
     */
    virtual KeyMetadata rotate_key(
        const std::string& old_label,
        const std::string& new_label,
        const RotationPolicy& policy
    ) {
        (void)old_label; (void)new_label; (void)policy;
        throw std::runtime_error("rotate_key not implemented");
    }

    /**
     * @brief Export wrapped key for backup
     * @param label Key to export
     * @param wrap_key_label Wrapping key label
     * @return Encrypted key blob
     */
    virtual EncryptedKeyBlob export_wrapped_key(
        const std::string& label,
        const std::string& wrap_key_label
    ) {
        (void)label; (void)wrap_key_label;
        throw std::runtime_error("export_wrapped_key not implemented");
    }

    // ==================== Random Number Generation ====================

    /**
     * @brief Generate cryptographically secure random bytes
     * @param length Number of bytes to generate
     * @return Random bytes
     */
    virtual std::vector<uint8_t> generate_random(size_t length) = 0;

    // ==================== Health & Monitoring ====================

    /**
     * @brief Check HSM health status
     * @return true if HSM is healthy and operational
     */
    virtual bool is_healthy() = 0;

    /**
     * @brief Get detailed HSM status
     * @return Status information
     */
    virtual HSMStatus get_status() const {
        HSMStatus status;
        status.initialized = false;
        return status;
    }

    /**
     * @brief Get audit trail for compliance
     * @param start Start time (optional)
     * @param end End time (optional)
     * @return Vector of audit records
     */
    virtual std::vector<AuditRecord> get_audit_trail(
        std::optional<std::chrono::system_clock::time_point> start = std::nullopt,
        std::optional<std::chrono::system_clock::time_point> end = std::nullopt
    ) const {
        (void)start; (void)end;
        return {}; // Default: empty
    }

    // ==================== Session Management ====================

    /**
     * @brief Authenticate to HSM
     * @param pin PIN/passphrase (will be zeroed after use)
     * @return true on success
     */
    virtual bool authenticate(std::string& pin) {
        (void)pin;
        return true; // Default: no authentication required
    }

    /**
     * @brief Logout from HSM
     */
    virtual void logout() {
        // Default: no-op
    }
};

} // namespace hsm
} // namespace nocturne

#endif // NOCTURNE_HSM_INTERFACE_HPP
