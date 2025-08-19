#pragma once

#include <array>
#include <cstdint>
#include <memory>
#include <optional>
#include <queue>
#include <unordered_map>
#include <vector>

namespace nocturne {

/**
 * Double Ratchet Algorithm Implementation
 * 
 * This implements the Signal Protocol's Double Ratchet algorithm for:
 * - Forward secrecy
 * - Post-compromise recovery
 * - Message ordering and replay protection
 * - Skipped message key storage
 * 
 * IMPORTANT: This is a prototype implementation. For production use:
 * 1. Implement proper message ordering and gap handling
 * 2. Add proper skipped message key storage with limits
 * 3. Implement header key chains for additional security
 * 4. Add proper session state persistence
 * 5. Implement proper error handling and recovery
 * 6. Add comprehensive logging and audit trails
 */

struct RatchetState {
    // DH ratchet state
    std::array<uint8_t, crypto_kx_SECRETKEYBYTES> dh_private_key{};
    std::array<uint8_t, crypto_kx_PUBLICKEYBYTES> dh_public_key{};
    std::optional<std::array<uint8_t, crypto_kx_PUBLICKEYBYTES>> dh_remote_public_key;
    
    // Symmetric ratchet states
    std::array<uint8_t, crypto_aead_xchacha20poly1305_ietf_KEYBYTES> root_key{};
    std::array<uint8_t, crypto_aead_xchacha20poly1305_ietf_KEYBYTES> header_key{};
    
    // Chain keys
    std::array<uint8_t, crypto_aead_xchacha20poly1305_ietf_KEYBYTES> send_chain_key{};
    std::array<uint8_t, crypto_aead_xchacha20poly1305_ietf_KEYBYTES> recv_chain_key{};
    
    // Message keys
    std::array<uint8_t, crypto_aead_xchacha20poly1305_ietf_KEYBYTES> send_message_key{};
    std::array<uint8_t, crypto_aead_xchacha20poly1305_ietf_KEYBYTES> recv_message_key{};
    
    // Counters
    uint32_t send_chain_count{0};
    uint32_t recv_chain_count{0};
    uint32_t send_message_count{0};
    uint32_t recv_message_count{0};
    
    // Skipped message keys (for out-of-order messages)
    std::unordered_map<uint32_t, std::array<uint8_t, crypto_aead_xchacha20poly1305_ietf_KEYBYTES>> skipped_message_keys;
    
    // Session state
    bool is_initialized{false};
    bool is_sending{false};
    bool is_receiving{false};
};

struct RatchetMessage {
    std::array<uint8_t, crypto_kx_PUBLICKEYBYTES> dh_public_key;
    uint32_t prev_chain_count;
    uint32_t message_count;
    std::vector<uint8_t> ciphertext;
    std::array<uint8_t, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES> nonce;
};

class DoubleRatchet {
public:
    // Initialize with shared secret from initial key exchange
    explicit DoubleRatchet(const std::array<uint8_t, crypto_kx_SESSIONKEYBYTES>& shared_secret);
    
    // Initialize with existing state (for persistence)
    explicit DoubleRatchet(const RatchetState& state);
    
    ~DoubleRatchet();
    
    // Core ratchet operations
    RatchetMessage encrypt_message(const std::vector<uint8_t>& plaintext);
    std::vector<uint8_t> decrypt_message(const RatchetMessage& message);
    
    // State management
    RatchetState get_state() const;
    void set_state(const RatchetState& state);
    
    // Key management
    std::array<uint8_t, crypto_kx_PUBLICKEYBYTES> get_public_key() const;
    void set_remote_public_key(const std::array<uint8_t, crypto_kx_PUBLICKEYBYTES>& remote_pk);
    
    // Session management
    bool is_initialized() const;
    void reset();
    
    // Skipped message management
    size_t get_skipped_message_count() const;
    void clear_skipped_messages();
    
    // Serialization for persistence
    std::vector<uint8_t> serialize_state() const;
    static std::optional<DoubleRatchet> deserialize_state(const std::vector<uint8_t>& data);

private:
    RatchetState state_;
    
    // Internal ratchet operations
    void perform_dh_ratchet();
    void perform_symmetric_ratchet(bool is_sending);
    std::array<uint8_t, crypto_aead_xchacha20poly1305_ietf_KEYBYTES> derive_chain_key(
        const std::array<uint8_t, crypto_aead_xchacha20poly1305_ietf_KEYBYTES>& input_key,
        const std::string& info
    );
    std::array<uint8_t, crypto_aead_xchacha20poly1305_ietf_KEYBYTES> derive_message_key(
        const std::array<uint8_t, crypto_aead_xchacha20poly1305_ietf_KEYBYTES>& chain_key
    );
    
    // Key derivation helpers
    void derive_root_key(const std::array<uint8_t, crypto_scalarmult_BYTES>& dh_shared);
    void derive_header_key();
    void derive_chain_keys();
    
    // Message key management
    std::optional<std::array<uint8_t, crypto_aead_xchacha20poly1305_ietf_KEYBYTES>> 
    get_message_key(uint32_t message_number);
    void store_skipped_message_key(uint32_t message_number, 
                                  const std::array<uint8_t, crypto_aead_xchacha20poly1305_ietf_KEYBYTES>& key);
    
    // Utility functions
    void generate_new_dh_keypair();
    void zero_memory(void* ptr, size_t size);
};

/**
 * Ratchet Session Manager
 * 
 * Manages multiple ratchet sessions and provides high-level interface
 */
class RatchetSessionManager {
public:
    struct SessionInfo {
        std::string session_id;
        std::array<uint8_t, crypto_kx_PUBLICKEYBYTES> remote_public_key;
        bool is_active;
        uint64_t message_count;
        std::chrono::system_clock::time_point last_activity;
    };
    
    explicit RatchetSessionManager(const std::string& storage_path = "");
    ~RatchetSessionManager();
    
    // Session management
    std::string create_session(const std::array<uint8_t, crypto_kx_SESSIONKEYBYTES>& shared_secret,
                              const std::array<uint8_t, crypto_kx_PUBLICKEYBYTES>& remote_pk);
    
    bool has_session(const std::string& session_id) const;
    void remove_session(const std::string& session_id);
    
    // Message operations
    RatchetMessage encrypt_message(const std::string& session_id, const std::vector<uint8_t>& plaintext);
    std::vector<uint8_t> decrypt_message(const std::string& session_id, const RatchetMessage& message);
    
    // Session information
    std::vector<SessionInfo> list_sessions() const;
    std::optional<SessionInfo> get_session_info(const std::string& session_id) const;
    
    // Persistence
    bool save_session(const std::string& session_id);
    bool load_session(const std::string& session_id);
    void save_all_sessions();
    void load_all_sessions();
    
    // Cleanup
    void cleanup_inactive_sessions(std::chrono::hours max_inactive_time = std::chrono::hours(24));

private:
    std::unordered_map<std::string, std::unique_ptr<DoubleRatchet>> sessions_;
    std::string storage_path_;
    std::mutex sessions_mutex_;
    
    // Persistence helpers
    std::string get_session_file_path(const std::string& session_id) const;
    bool serialize_session(const std::string& session_id, const DoubleRatchet& ratchet);
    std::optional<DoubleRatchet> deserialize_session(const std::string& session_id);
};

/**
 * Ratchet Protocol Implementation
 * 
 * High-level protocol that combines Double Ratchet with packet encryption
 */
class RatchetProtocol {
public:
    struct ProtocolMessage {
        uint8_t version;
        uint8_t flags;
        uint32_t rotation_id;
        std::array<uint8_t, crypto_kx_PUBLICKEYBYTES> eph_pk;
        std::array<uint8_t, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES> nonce;
        uint64_t counter;
        RatchetMessage ratchet_message;
        std::vector<uint8_t> aad;
        std::vector<uint8_t> ciphertext;
        std::optional<std::array<uint8_t, crypto_sign_BYTES>> signature;
    };
    
    explicit RatchetProtocol(const std::string& session_id = "");
    ~RatchetProtocol();
    
    // Protocol operations
    ProtocolMessage encrypt_message(const std::vector<uint8_t>& plaintext,
                                   const std::array<uint8_t, crypto_kx_PUBLICKEYBYTES>& receiver_pk,
                                   uint32_t rotation_id = 0,
                                   const std::vector<uint8_t>& aad = {},
                                   HSMInterface* signer = nullptr);
    
    std::vector<uint8_t> decrypt_message(const ProtocolMessage& message,
                                        const std::array<uint8_t, crypto_kx_PUBLICKEYBYTES>& receiver_pk,
                                        const std::array<uint8_t, crypto_kx_SECRETKEYBYTES>& receiver_sk,
                                        const std::optional<std::array<uint8_t, crypto_sign_PUBLICKEYBYTES>>& expected_signer = std::nullopt);
    
    // Session management
    void set_session_id(const std::string& session_id);
    std::string get_session_id() const;
    
    // Serialization
    std::vector<uint8_t> serialize_message(const ProtocolMessage& message);
    std::optional<ProtocolMessage> deserialize_message(const std::vector<uint8_t>& data);

private:
    std::string session_id_;
    std::unique_ptr<RatchetSessionManager> session_manager_;
    
    // Internal helpers
    std::array<uint8_t, crypto_aead_xchacha20poly1305_ietf_KEYBYTES> derive_packet_key(
        const std::array<uint8_t, crypto_kx_PUBLICKEYBYTES>& eph_pk,
        const std::array<uint8_t, crypto_kx_SECRETKEYBYTES>& receiver_sk
    );
};

} // namespace nocturne
