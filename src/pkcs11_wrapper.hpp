#pragma once

#include <array>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>
#include <optional>
// libsodium primitives/constants used in this header
#include <sodium.h>

namespace nocturne {

/**
 * PKCS#11 wrapper for HSM integration
 * 
 * This provides a high-level interface to PKCS#11 tokens/HSMs for:
 * - Key storage and management
 * - Signing operations
 * - Random number generation
 * - Session management
 * 
 * IMPORTANT: This is a prototype wrapper. For production use:
 * 1. Implement proper error handling and logging
 * 2. Add session pooling and connection management
 * 3. Implement proper key lifecycle management
 * 4. Add audit logging for all operations
 * 5. Implement proper authentication and access control
 * 6. Add support for multiple token types and vendors
 */

class PKCS11Wrapper {
public:
    struct TokenInfo {
        std::string label;
        std::string manufacturer;
        std::string model;
        std::string serial;
        bool is_initialized;
        bool is_login_required;
    };

    struct KeyInfo {
        std::string label;
        std::string id;
        bool is_private;
        std::string key_type; // "EC", "RSA", etc.
        size_t key_size;
    };

    // Initialize PKCS#11 library and connect to token
    static std::unique_ptr<PKCS11Wrapper> create(
        const std::string& library_path,
        const std::string& token_label = "",
        const std::string& pin = ""
    );

    virtual ~PKCS11Wrapper() = default;

    // Token management
    virtual std::vector<TokenInfo> list_tokens() = 0;
    virtual TokenInfo get_token_info() = 0;
    virtual bool login(const std::string& pin) = 0;
    virtual void logout() = 0;

    // Key management
    virtual std::vector<KeyInfo> list_keys() = 0;
    virtual std::optional<KeyInfo> find_key(const std::string& label) = 0;
    
    // Generate new key pair on HSM
    virtual bool generate_ed25519_keypair(
        const std::string& label,
        std::array<uint8_t, crypto_sign_PUBLICKEYBYTES>& public_key
    ) = 0;
    
    virtual bool generate_x25519_keypair(
        const std::string& label,
        std::array<uint8_t, crypto_kx_PUBLICKEYBYTES>& public_key
    ) = 0;

    // Signing operations
    virtual std::optional<std::array<uint8_t, crypto_sign_BYTES>> sign_ed25519(
        const std::string& key_label,
        const std::vector<uint8_t>& data
    ) = 0;

    // Random number generation
    virtual std::optional<std::vector<uint8_t>> generate_random(size_t length) = 0;

    // Key derivation (if supported by HSM)
    virtual std::optional<std::array<uint8_t, crypto_kx_SESSIONKEYBYTES>> derive_session_keys(
        const std::string& private_key_label,
        const std::array<uint8_t, crypto_kx_PUBLICKEYBYTES>& peer_public_key,
        bool is_client
    ) = 0;

protected:
    PKCS11Wrapper() = default;
};

/**
 * Concrete PKCS#11 implementation using libpkcs11
 * 
 * This is a basic implementation. Production code should:
 * 1. Handle all PKCS#11 return codes properly
 * 2. Implement proper session management
 * 3. Add retry logic for transient failures
 * 4. Implement proper cleanup on errors
 * 5. Add comprehensive logging
 */
class LibPKCS11Wrapper : public PKCS11Wrapper {
public:
    explicit LibPKCS11Wrapper(const std::string& library_path);
    ~LibPKCS11Wrapper() override;

    // Token management
    std::vector<TokenInfo> list_tokens() override;
    TokenInfo get_token_info() override;
    bool login(const std::string& pin) override;
    void logout() override;

    // Key management
    std::vector<KeyInfo> list_keys() override;
    std::optional<KeyInfo> find_key(const std::string& label) override;
    
    bool generate_ed25519_keypair(
        const std::string& label,
        std::array<uint8_t, crypto_sign_PUBLICKEYBYTES>& public_key
    ) override;
    
    bool generate_x25519_keypair(
        const std::string& label,
        std::array<uint8_t, crypto_kx_PUBLICKEYBYTES>& public_key
    ) override;

    // Signing operations
    std::optional<std::array<uint8_t, crypto_sign_BYTES>> sign_ed25519(
        const std::string& key_label,
        const std::vector<uint8_t>& data
    ) override;

    // Random number generation
    std::optional<std::vector<uint8_t>> generate_random(size_t length) override;

    // Key derivation
    std::optional<std::array<uint8_t, crypto_kx_SESSIONKEYBYTES>> derive_session_keys(
        const std::string& private_key_label,
        const std::array<uint8_t, crypto_kx_PUBLICKEYBYTES>& peer_public_key,
        bool is_client
    ) override;

private:
    // PKCS#11 function pointers and handles
    void* library_handle_;
    void* session_handle_;
    void* token_handle_;
    
    // Function pointers (would be populated from libpkcs11)
    // This is a simplified version - real implementation would load all PKCS#11 functions
    
    bool initialize_library(const std::string& library_path);
    bool open_session();
    void close_session();
    bool find_token(const std::string& label);
};

/**
 * HSM interface that can use either PKCS#11 or file-based keys
 * 
 * This provides a unified interface for both development and production use.
 */
class HSMInterface {
public:
    enum class Type {
        FILE,      // File-based keys (development only)
        PKCS11     // PKCS#11 HSM
    };

    static std::unique_ptr<HSMInterface> create(
        Type type,
        const std::string& config
    );

    virtual ~HSMInterface() = default;

    // Core signing interface
    virtual std::array<uint8_t, crypto_sign_BYTES> sign(
        const uint8_t* data, 
        size_t len
    ) = 0;

    // Key management
    virtual std::optional<std::array<uint8_t, crypto_sign_PUBLICKEYBYTES>> get_public_key() = 0;
    virtual bool has_key(const std::string& label) = 0;

    // Random number generation
    virtual std::vector<uint8_t> generate_random(size_t length) = 0;

    // Health check
    virtual bool is_healthy() = 0;
};

/**
 * File-based HSM implementation (for development/testing)
 * 
 * WARNING: This is NOT secure for production use!
 * Private keys are stored in plain text on disk.
 */
class FileHSM : public HSMInterface {
public:
    explicit FileHSM(const std::string& key_path);
    ~FileHSM() override;

    std::array<uint8_t, crypto_sign_BYTES> sign(
        const uint8_t* data, 
        size_t len
    ) override;

    std::optional<std::array<uint8_t, crypto_sign_PUBLICKEYBYTES>> get_public_key() override;
    bool has_key(const std::string& label) override;
    std::vector<uint8_t> generate_random(size_t length) override;
    bool is_healthy() override;

private:
    std::array<uint8_t, crypto_sign_SECRETKEYBYTES> secret_key_;
    std::array<uint8_t, crypto_sign_PUBLICKEYBYTES> public_key_;
    bool initialized_;
};

/**
 * PKCS#11-based HSM implementation
 */
class PKCS11HSM : public HSMInterface {
public:
    explicit PKCS11HSM(const std::string& config);
    ~PKCS11HSM() override;

    std::array<uint8_t, crypto_sign_BYTES> sign(
        const uint8_t* data, 
        size_t len
    ) override;

    std::optional<std::array<uint8_t, crypto_sign_PUBLICKEYBYTES>> get_public_key() override;
    bool has_key(const std::string& label) override;
    std::vector<uint8_t> generate_random(size_t length) override;
    bool is_healthy() override;

private:
    std::unique_ptr<PKCS11Wrapper> pkcs11_;
    std::string key_label_;
    std::optional<std::array<uint8_t, crypto_sign_PUBLICKEYBYTES>> cached_public_key_;
};

} // namespace nocturne
