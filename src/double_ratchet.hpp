#pragma once

#include <array>
#include <cstdint>
#include <cstring>
#include <memory>
#include <mutex>
#include <optional>
#include <queue>
#include <string>
#include <unordered_map>
#include <vector>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <sodium.h>

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

// ===== DoubleRatchet inline implementation =====

inline void DoubleRatchet::zero_memory(void* ptr, size_t size) {
    volatile uint8_t* p = static_cast<volatile uint8_t*>(ptr);
    for (size_t i = 0; i < size; ++i) p[i] = 0;
}

inline std::array<uint8_t, crypto_aead_xchacha20poly1305_ietf_KEYBYTES>
DoubleRatchet::derive_chain_key(
    const std::array<uint8_t, crypto_aead_xchacha20poly1305_ietf_KEYBYTES>& input_key,
    const std::string& info
) {
    std::array<uint8_t, crypto_aead_xchacha20poly1305_ietf_KEYBYTES> out{};
    if (crypto_generichash(out.data(), out.size(),
            input_key.data(), input_key.size(),
            reinterpret_cast<const unsigned char*>(info.data()), info.size()) != 0) {
        throw std::runtime_error("derive_chain_key failed");
    }
    return out;
}

inline std::array<uint8_t, crypto_aead_xchacha20poly1305_ietf_KEYBYTES>
DoubleRatchet::derive_message_key(
    const std::array<uint8_t, crypto_aead_xchacha20poly1305_ietf_KEYBYTES>& chain_key
) {
    std::array<uint8_t, crypto_aead_xchacha20poly1305_ietf_KEYBYTES> out{};
    if (crypto_generichash(out.data(), out.size(),
            chain_key.data(), chain_key.size(),
            reinterpret_cast<const unsigned char*>("nocturne-dr-msg"), sizeof("nocturne-dr-msg") - 1) != 0) {
        throw std::runtime_error("derive_message_key failed");
    }
    return out;
}

inline void DoubleRatchet::derive_root_key(const std::array<uint8_t, crypto_scalarmult_BYTES>& dh_shared) {
    std::array<uint8_t, crypto_aead_xchacha20poly1305_ietf_KEYBYTES> mixed{};
    std::vector<uint8_t> seed;
    seed.insert(seed.end(), state_.root_key.begin(), state_.root_key.end());
    seed.insert(seed.end(), dh_shared.begin(), dh_shared.end());
    if (crypto_generichash(mixed.data(), mixed.size(), seed.data(), seed.size(),
            reinterpret_cast<const unsigned char*>("nocturne-dr-root"), sizeof("nocturne-dr-root") - 1) != 0) {
        throw std::runtime_error("derive_root_key failed");
    }
    state_.root_key = mixed;
    derive_header_key();
}

inline void DoubleRatchet::derive_header_key() {
    state_.header_key = derive_chain_key(state_.root_key, "nocturne-dr-header");
}

inline void DoubleRatchet::derive_chain_keys() {
    state_.send_chain_key = derive_chain_key(state_.root_key, "nocturne-dr-send");
    state_.recv_chain_key = derive_chain_key(state_.root_key, "nocturne-dr-recv");
}

inline void DoubleRatchet::generate_new_dh_keypair() {
    crypto_kx_keypair(state_.dh_public_key.data(), state_.dh_private_key.data());
}

inline DoubleRatchet::DoubleRatchet(const std::array<uint8_t, crypto_kx_SESSIONKEYBYTES>& shared_secret) {
    if (crypto_generichash(state_.root_key.data(), state_.root_key.size(),
            shared_secret.data(), shared_secret.size(),
            reinterpret_cast<const unsigned char*>("nocturne-dr-init"), sizeof("nocturne-dr-init") - 1) != 0) {
        throw std::runtime_error("DoubleRatchet init KDF failed");
    }
    generate_new_dh_keypair();
    derive_header_key();
    derive_chain_keys();
    state_.is_initialized = true;
}

inline DoubleRatchet::DoubleRatchet(const RatchetState& state) {
    state_ = state;
}

inline DoubleRatchet::~DoubleRatchet() {
    zero_memory(state_.dh_private_key.data(), state_.dh_private_key.size());
}

inline void DoubleRatchet::set_remote_public_key(const std::array<uint8_t, crypto_kx_PUBLICKEYBYTES>& remote_pk) {
    state_.dh_remote_public_key = remote_pk;
}

inline std::array<uint8_t, crypto_kx_PUBLICKEYBYTES> DoubleRatchet::get_public_key() const {
    return state_.dh_public_key;
}

inline bool DoubleRatchet::is_initialized() const {
    return state_.is_initialized;
}

inline void DoubleRatchet::reset() {
    RatchetState empty{};
    state_ = empty;
}

inline RatchetState DoubleRatchet::get_state() const {
    return state_;
}

inline void DoubleRatchet::set_state(const RatchetState& state) {
    state_ = state;
}

inline void DoubleRatchet::perform_dh_ratchet() {
    if (!state_.dh_remote_public_key.has_value()) {
        throw std::runtime_error("DR: remote public key not set");
    }
    std::array<uint8_t, crypto_scalarmult_BYTES> dh1{};
    if (crypto_scalarmult(dh1.data(), state_.dh_private_key.data(), state_.dh_remote_public_key->data()) != 0) {
        throw std::runtime_error("DR: scalarmult failed (dh1)");
    }
    derive_root_key(dh1);
    state_.recv_chain_count = 0;

    generate_new_dh_keypair();
    std::array<uint8_t, crypto_scalarmult_BYTES> dh2{};
    if (crypto_scalarmult(dh2.data(), state_.dh_private_key.data(), state_.dh_remote_public_key->data()) != 0) {
        throw std::runtime_error("DR: scalarmult failed (dh2)");
    }
    derive_root_key(dh2);
    derive_chain_keys();
    state_.send_chain_count = 0;
}

inline void DoubleRatchet::perform_symmetric_ratchet(bool is_sending) {
    if (is_sending) {
        // SECURITY: Prevent integer overflow - critical for nonce safety
        if (state_.send_message_count == UINT32_MAX) {
            throw std::runtime_error("DR: send message counter exhausted - rekeying required");
        }
        state_.send_message_key = derive_message_key(state_.send_chain_key);
        state_.send_chain_key = derive_chain_key(state_.send_chain_key, "nocturne-dr-send-next");
        state_.send_message_count++;
    } else {
        // SECURITY: Prevent integer overflow
        if (state_.recv_message_count == UINT32_MAX) {
            throw std::runtime_error("DR: recv message counter exhausted - rekeying required");
        }
        state_.recv_message_key = derive_message_key(state_.recv_chain_key);
        state_.recv_chain_key = derive_chain_key(state_.recv_chain_key, "nocturne-dr-recv-next");
        state_.recv_message_count++;
    }
}

inline void DoubleRatchet::store_skipped_message_key(
    uint32_t message_number,
    const std::array<uint8_t, crypto_aead_xchacha20poly1305_ietf_KEYBYTES>& key
) {
    constexpr size_t MAX_SKIPPED = 128;
    if (state_.skipped_message_keys.size() >= MAX_SKIPPED) {
        state_.skipped_message_keys.erase(state_.skipped_message_keys.begin());
    }
    state_.skipped_message_keys[message_number] = key;
}

inline std::optional<std::array<uint8_t, crypto_aead_xchacha20poly1305_ietf_KEYBYTES>>
DoubleRatchet::get_message_key(uint32_t message_number) {
    auto it = state_.skipped_message_keys.find(message_number);
    if (it == state_.skipped_message_keys.end()) return std::nullopt;
    auto key = it->second;
    state_.skipped_message_keys.erase(it);
    return key;
}

inline RatchetMessage DoubleRatchet::encrypt_message(const std::vector<uint8_t>& plaintext) {
    if (!state_.is_initialized) throw std::runtime_error("DR: not initialized");
    if (!state_.dh_remote_public_key.has_value()) throw std::runtime_error("DR: remote key not set");
    perform_symmetric_ratchet(true);

    RatchetMessage m{};
    m.dh_public_key = state_.dh_public_key;
    m.prev_chain_count = state_.recv_chain_count;
    m.message_count = state_.send_message_count;

    // SECURITY: Use deterministic nonce derived from message count
    // This provides defense-in-depth against RNG failures
    std::array<uint8_t, 32> nonce_key{};
    crypto_generichash(nonce_key.data(), nonce_key.size(),
        state_.send_message_key.data(), state_.send_message_key.size(),
        reinterpret_cast<const unsigned char*>("nocturne-nonce"), sizeof("nocturne-nonce") - 1);

    // Derive nonce from message count and key
    std::array<uint8_t, 8> counter_bytes{};
    for (int i = 0; i < 8; ++i) {
        counter_bytes[i] = static_cast<uint8_t>((m.message_count >> (8 * i)) & 0xFF);
    }
    crypto_generichash(m.nonce.data(), m.nonce.size(),
        counter_bytes.data(), counter_bytes.size(),
        nonce_key.data(), nonce_key.size());

    std::vector<uint8_t> aad;
    aad.insert(aad.end(), m.dh_public_key.begin(), m.dh_public_key.end());
    for (int i = 0; i < 4; ++i) aad.push_back(static_cast<uint8_t>((m.prev_chain_count >> (8 * i)) & 0xFF));
    for (int i = 0; i < 4; ++i) aad.push_back(static_cast<uint8_t>((m.message_count >> (8 * i)) & 0xFF));

    m.ciphertext.resize(plaintext.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES);
    unsigned long long ct_len = 0;
    if (crypto_aead_xchacha20poly1305_ietf_encrypt(
            m.ciphertext.data(), &ct_len,
            plaintext.data(), plaintext.size(),
            aad.data(), aad.size(),
            nullptr,
            m.nonce.data(), state_.send_message_key.data()) != 0) {
        throw std::runtime_error("DR: aead encrypt failed");
    }
    m.ciphertext.resize(static_cast<size_t>(ct_len));
    return m;
}

inline std::vector<uint8_t> DoubleRatchet::decrypt_message(const RatchetMessage& message) {
    if (!state_.is_initialized) throw std::runtime_error("DR: not initialized");
    if (!state_.dh_remote_public_key.has_value() || *state_.dh_remote_public_key != message.dh_public_key) {
        set_remote_public_key(message.dh_public_key);
        perform_dh_ratchet();
    }

    if (auto mk = get_message_key(message.message_count)) {
        std::vector<uint8_t> aad;
        aad.insert(aad.end(), message.dh_public_key.begin(), message.dh_public_key.end());
        for (int i = 0; i < 4; ++i) aad.push_back(static_cast<uint8_t>((message.prev_chain_count >> (8 * i)) & 0xFF));
        for (int i = 0; i < 4; ++i) aad.push_back(static_cast<uint8_t>((message.message_count >> (8 * i)) & 0xFF));

        std::vector<uint8_t> pt(message.ciphertext.size() - crypto_aead_xchacha20poly1305_ietf_ABYTES);
        unsigned long long pt_len = 0;
        if (crypto_aead_xchacha20poly1305_ietf_decrypt(
                pt.data(), &pt_len, nullptr,
                message.ciphertext.data(), message.ciphertext.size(),
                aad.data(), aad.size(),
                message.nonce.data(), mk->data()) != 0) {
            throw std::runtime_error("DR: aead decrypt failed (skipped)");
        }
        pt.resize(static_cast<size_t>(pt_len));
        return pt;
    }

    // SECURITY: Enforce maximum message gap to prevent DoS attacks
    constexpr uint32_t MAX_MESSAGE_GAP = 10000;
    if (message.message_count > state_.recv_message_count) {
        uint32_t gap = message.message_count - state_.recv_message_count;
        if (gap > MAX_MESSAGE_GAP) {
            throw std::runtime_error("DR: message gap too large - possible DoS attack");
        }
    }

    while (state_.recv_message_count < message.message_count) {
        auto mk = derive_message_key(state_.recv_chain_key);
        store_skipped_message_key(state_.recv_message_count + 1, mk);
        state_.recv_chain_key = derive_chain_key(state_.recv_chain_key, "nocturne-dr-recv-next");
        state_.recv_message_count++;
    }

    perform_symmetric_ratchet(false);

    std::vector<uint8_t> aad;
    aad.insert(aad.end(), message.dh_public_key.begin(), message.dh_public_key.end());
    for (int i = 0; i < 4; ++i) aad.push_back(static_cast<uint8_t>((message.prev_chain_count >> (8 * i)) & 0xFF));
    for (int i = 0; i < 4; ++i) aad.push_back(static_cast<uint8_t>((message.message_count >> (8 * i)) & 0xFF));

    std::vector<uint8_t> pt(message.ciphertext.size() - crypto_aead_xchacha20poly1305_ietf_ABYTES);
    unsigned long long pt_len = 0;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            pt.data(), &pt_len, nullptr,
            message.ciphertext.data(), message.ciphertext.size(),
            aad.data(), aad.size(),
            message.nonce.data(), state_.recv_message_key.data()) != 0) {
        throw std::runtime_error("DR: aead decrypt failed");
    }
    pt.resize(static_cast<size_t>(pt_len));
    return pt;
}

inline size_t DoubleRatchet::get_skipped_message_count() const {
    return state_.skipped_message_keys.size();
}

inline void DoubleRatchet::clear_skipped_messages() {
    state_.skipped_message_keys.clear();
}

inline std::vector<uint8_t> DoubleRatchet::serialize_state() const {
    std::vector<uint8_t> out;
    auto append = [&](const uint8_t* p, size_t n){ out.insert(out.end(), p, p + n); };
    append(state_.root_key.data(), state_.root_key.size());
    append(state_.header_key.data(), state_.header_key.size());
    append(state_.send_chain_key.data(), state_.send_chain_key.size());
    append(state_.recv_chain_key.data(), state_.recv_chain_key.size());
    append(state_.send_message_key.data(), state_.send_message_key.size());
    append(state_.recv_message_key.data(), state_.recv_message_key.size());
    append(reinterpret_cast<const uint8_t*>(&state_.send_chain_count), sizeof(state_.send_chain_count));
    append(reinterpret_cast<const uint8_t*>(&state_.recv_chain_count), sizeof(state_.recv_chain_count));
    append(reinterpret_cast<const uint8_t*>(&state_.send_message_count), sizeof(state_.send_message_count));
    append(reinterpret_cast<const uint8_t*>(&state_.recv_message_count), sizeof(state_.recv_message_count));
    append(state_.dh_public_key.data(), state_.dh_public_key.size());
    append(state_.dh_private_key.data(), state_.dh_private_key.size());
    uint8_t has_remote = state_.dh_remote_public_key.has_value() ? 1 : 0;
    append(&has_remote, 1);
    if (has_remote) append(state_.dh_remote_public_key->data(), state_.dh_remote_public_key->size());
    return out;
}

inline std::optional<DoubleRatchet> DoubleRatchet::deserialize_state(const std::vector<uint8_t>& data) {
    RatchetState st{};
    size_t off = 0;
    auto need = [&](size_t n){ if (off + n > data.size()) throw std::runtime_error("DR: state truncated"); };
    auto get = [&](void* dst, size_t n){ need(n); std::memcpy(dst, data.data() + off, n); off += n; };
    try {
        get(st.root_key.data(), st.root_key.size());
        get(st.header_key.data(), st.header_key.size());
        get(st.send_chain_key.data(), st.send_chain_key.size());
        get(st.recv_chain_key.data(), st.recv_chain_key.size());
        get(st.send_message_key.data(), st.send_message_key.size());
        get(st.recv_message_key.data(), st.recv_message_key.size());
        get(&st.send_chain_count, sizeof(st.send_chain_count));
        get(&st.recv_chain_count, sizeof(st.recv_chain_count));
        get(&st.send_message_count, sizeof(st.send_message_count));
        get(&st.recv_message_count, sizeof(st.recv_message_count));
        get(st.dh_public_key.data(), st.dh_public_key.size());
        get(st.dh_private_key.data(), st.dh_private_key.size());
        uint8_t has_remote = 0; get(&has_remote, 1);
        if (has_remote) {
            std::array<uint8_t, crypto_kx_PUBLICKEYBYTES> r{};
            get(r.data(), r.size());
            st.dh_remote_public_key = r;
        }
        st.is_initialized = true;
        DoubleRatchet dr(st);
        return dr;
    } catch (...) {
        return std::nullopt;
    }
}

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
                                   void* signer_unused = nullptr);
    
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

// ============================================================================
// RatchetSessionManager — inline implementation
// ============================================================================
namespace detail {

inline void dr_write_u32_le(std::vector<uint8_t>& out, uint32_t v) {
    out.push_back(static_cast<uint8_t>(v & 0xFF));
    out.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
    out.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
}
inline uint32_t dr_read_u32_le(const uint8_t* p) {
    return static_cast<uint32_t>(p[0])
         | (static_cast<uint32_t>(p[1]) << 8)
         | (static_cast<uint32_t>(p[2]) << 16)
         | (static_cast<uint32_t>(p[3]) << 24);
}
inline void dr_write_u64_le(std::vector<uint8_t>& out, uint64_t v) {
    for (int i = 0; i < 8; ++i) out.push_back(static_cast<uint8_t>((v >> (8 * i)) & 0xFF));
}
inline uint64_t dr_read_u64_le(const uint8_t* p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v |= static_cast<uint64_t>(p[i]) << (8 * i);
    return v;
}

inline std::string dr_session_id_hex(const uint8_t* p, size_t n) {
    static const char* hex = "0123456789abcdef";
    std::string s; s.reserve(n * 2);
    for (size_t i = 0; i < n; ++i) {
        s.push_back(hex[(p[i] >> 4) & 0x0F]);
        s.push_back(hex[p[i] & 0x0F]);
    }
    return s;
}

inline bool dr_safe_filename(const std::string& s) {
    if (s.empty() || s.size() > 128) return false;
    for (char c : s) {
        bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                  (c >= '0' && c <= '9') || c == '-' || c == '_';
        if (!ok) return false;
    }
    return true;
}

} // namespace detail

// Internal metadata kept alongside each DoubleRatchet
struct RatchetSessionMeta {
    std::array<uint8_t, crypto_kx_PUBLICKEYBYTES> remote_public_key{};
    bool has_remote{false};
    uint64_t message_count{0};
    std::chrono::system_clock::time_point last_activity{std::chrono::system_clock::now()};
};

inline RatchetSessionManager::RatchetSessionManager(const std::string& storage_path)
    : storage_path_(storage_path) {
    if (!storage_path_.empty()) {
        std::error_code ec;
        std::filesystem::create_directories(storage_path_, ec);
    }
}

inline RatchetSessionManager::~RatchetSessionManager() {
    // Best-effort: persist all sessions on shutdown if storage configured
    if (!storage_path_.empty()) {
        try { save_all_sessions(); } catch (...) { /* best-effort */ }
    }
}

inline std::string RatchetSessionManager::create_session(
    const std::array<uint8_t, crypto_kx_SESSIONKEYBYTES>& shared_secret,
    const std::array<uint8_t, crypto_kx_PUBLICKEYBYTES>& remote_pk) {

    std::lock_guard<std::mutex> lock(sessions_mutex_);

    // Generate random 16-byte session id (32 hex chars)
    std::array<uint8_t, 16> id_bytes{};
    randombytes_buf(id_bytes.data(), id_bytes.size());
    std::string session_id = detail::dr_session_id_hex(id_bytes.data(), id_bytes.size());

    auto dr = std::make_unique<DoubleRatchet>(shared_secret);
    dr->set_remote_public_key(remote_pk);
    sessions_[session_id] = std::move(dr);
    return session_id;
}

inline bool RatchetSessionManager::has_session(const std::string& session_id) const {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    return sessions_.find(session_id) != sessions_.end();
}

inline void RatchetSessionManager::remove_session(const std::string& session_id) {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    sessions_.erase(session_id);
    if (!storage_path_.empty() && detail::dr_safe_filename(session_id)) {
        std::error_code ec;
        std::filesystem::remove(get_session_file_path(session_id), ec);
    }
}

inline RatchetMessage RatchetSessionManager::encrypt_message(
    const std::string& session_id, const std::vector<uint8_t>& plaintext) {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    auto it = sessions_.find(session_id);
    if (it == sessions_.end()) {
        throw std::runtime_error("RatchetSessionManager: unknown session id");
    }
    return it->second->encrypt_message(plaintext);
}

inline std::vector<uint8_t> RatchetSessionManager::decrypt_message(
    const std::string& session_id, const RatchetMessage& message) {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    auto it = sessions_.find(session_id);
    if (it == sessions_.end()) {
        throw std::runtime_error("RatchetSessionManager: unknown session id");
    }
    return it->second->decrypt_message(message);
}

inline std::vector<RatchetSessionManager::SessionInfo>
RatchetSessionManager::list_sessions() const {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    std::vector<SessionInfo> out;
    out.reserve(sessions_.size());
    for (const auto& [id, dr] : sessions_) {
        SessionInfo info;
        info.session_id = id;
        info.is_active = dr && dr->is_initialized();
        info.message_count = 0; // tracked at higher layers if needed
        info.last_activity = std::chrono::system_clock::now();
        if (dr) {
            auto state = dr->get_state();
            if (state.dh_remote_public_key.has_value()) {
                info.remote_public_key = *state.dh_remote_public_key;
            } else {
                info.remote_public_key.fill(0);
            }
        }
        out.push_back(std::move(info));
    }
    return out;
}

inline std::optional<RatchetSessionManager::SessionInfo>
RatchetSessionManager::get_session_info(const std::string& session_id) const {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    auto it = sessions_.find(session_id);
    if (it == sessions_.end()) return std::nullopt;
    SessionInfo info;
    info.session_id = session_id;
    info.is_active = it->second && it->second->is_initialized();
    info.message_count = 0;
    info.last_activity = std::chrono::system_clock::now();
    if (it->second) {
        auto state = it->second->get_state();
        if (state.dh_remote_public_key.has_value()) {
            info.remote_public_key = *state.dh_remote_public_key;
        } else {
            info.remote_public_key.fill(0);
        }
    }
    return info;
}

inline std::string RatchetSessionManager::get_session_file_path(const std::string& session_id) const {
    std::filesystem::path p = storage_path_;
    p /= (session_id + ".dr");
    return p.string();
}

inline bool RatchetSessionManager::serialize_session(
    const std::string& session_id, const DoubleRatchet& ratchet) {
    if (storage_path_.empty()) return false;
    if (!detail::dr_safe_filename(session_id)) return false;
    try {
        std::filesystem::create_directories(storage_path_);
        auto path = get_session_file_path(session_id);
        std::string tmp = path + ".tmp";
        {
            std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
            if (!f) return false;
            auto blob = ratchet.serialize_state();
            // Magic header + length + payload
            const char magic[4] = {'D','R','S','1'};
            f.write(magic, 4);
            uint32_t n = static_cast<uint32_t>(blob.size());
            uint8_t lenbuf[4] = {
                static_cast<uint8_t>(n & 0xFF),
                static_cast<uint8_t>((n >> 8) & 0xFF),
                static_cast<uint8_t>((n >> 16) & 0xFF),
                static_cast<uint8_t>((n >> 24) & 0xFF)
            };
            f.write(reinterpret_cast<const char*>(lenbuf), 4);
            if (!blob.empty()) {
                f.write(reinterpret_cast<const char*>(blob.data()),
                        static_cast<std::streamsize>(blob.size()));
            }
            f.flush();
            if (!f) return false;
        }
        std::error_code ec;
        std::filesystem::rename(tmp, path, ec);
        if (ec) {
            std::filesystem::remove(path, ec);
            std::filesystem::rename(tmp, path, ec);
            if (ec) return false;
        }
        return true;
    } catch (...) {
        return false;
    }
}

inline std::optional<DoubleRatchet>
RatchetSessionManager::deserialize_session(const std::string& session_id) {
    if (storage_path_.empty()) return std::nullopt;
    if (!detail::dr_safe_filename(session_id)) return std::nullopt;
    try {
        auto path = get_session_file_path(session_id);
        if (!std::filesystem::exists(path)) return std::nullopt;
        std::ifstream f(path, std::ios::binary);
        if (!f) return std::nullopt;
        char magic[4];
        f.read(magic, 4);
        if (f.gcount() != 4 || std::memcmp(magic, "DRS1", 4) != 0) return std::nullopt;
        uint8_t lenbuf[4];
        f.read(reinterpret_cast<char*>(lenbuf), 4);
        if (f.gcount() != 4) return std::nullopt;
        uint32_t n = detail::dr_read_u32_le(lenbuf);
        if (n > 64u * 1024u) return std::nullopt; // sanity cap
        std::vector<uint8_t> blob(n);
        if (n > 0) {
            f.read(reinterpret_cast<char*>(blob.data()), static_cast<std::streamsize>(n));
            if (static_cast<uint32_t>(f.gcount()) != n) return std::nullopt;
        }
        return DoubleRatchet::deserialize_state(blob);
    } catch (...) {
        return std::nullopt;
    }
}

inline bool RatchetSessionManager::save_session(const std::string& session_id) {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    auto it = sessions_.find(session_id);
    if (it == sessions_.end() || !it->second) return false;
    return serialize_session(session_id, *it->second);
}

inline bool RatchetSessionManager::load_session(const std::string& session_id) {
    auto dr = deserialize_session(session_id);
    if (!dr.has_value()) return false;
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    sessions_[session_id] = std::make_unique<DoubleRatchet>(std::move(*dr));
    return true;
}

inline void RatchetSessionManager::save_all_sessions() {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    if (storage_path_.empty()) return;
    for (const auto& [id, dr] : sessions_) {
        if (dr) (void)serialize_session(id, *dr);
    }
}

inline void RatchetSessionManager::load_all_sessions() {
    if (storage_path_.empty() || !std::filesystem::exists(storage_path_)) return;
    std::error_code ec;
    for (const auto& entry : std::filesystem::directory_iterator(storage_path_, ec)) {
        if (!entry.is_regular_file()) continue;
        auto fname = entry.path().filename().string();
        if (fname.size() <= 3) continue;
        if (fname.substr(fname.size() - 3) != ".dr") continue;
        std::string id = fname.substr(0, fname.size() - 3);
        if (!detail::dr_safe_filename(id)) continue;
        (void)load_session(id);
    }
}

inline void RatchetSessionManager::cleanup_inactive_sessions(std::chrono::hours max_inactive_time) {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    auto now = std::chrono::system_clock::now();
    for (auto it = sessions_.begin(); it != sessions_.end(); ) {
        // Without per-session activity tracking we keep them; future versions
        // should track last_activity in a sibling map. For now, keep all.
        (void)now; (void)max_inactive_time;
        ++it;
    }
}

// ============================================================================
// RatchetProtocol — inline implementation
// ============================================================================

inline RatchetProtocol::RatchetProtocol(const std::string& session_id)
    : session_id_(session_id),
      session_manager_(std::make_unique<RatchetSessionManager>()) {}

inline RatchetProtocol::~RatchetProtocol() = default;

inline void RatchetProtocol::set_session_id(const std::string& session_id) {
    session_id_ = session_id;
}
inline std::string RatchetProtocol::get_session_id() const {
    return session_id_;
}

inline std::array<uint8_t, crypto_aead_xchacha20poly1305_ietf_KEYBYTES>
RatchetProtocol::derive_packet_key(
    const std::array<uint8_t, crypto_kx_PUBLICKEYBYTES>& eph_pk,
    const std::array<uint8_t, crypto_kx_SECRETKEYBYTES>& receiver_sk) {
    // Packet-level key derivation kept available for callers that want to
    // wrap the DR ciphertext in an additional AEAD layer bound to the
    // packet header. Uses BLAKE2b with domain separation.
    std::array<uint8_t, crypto_scalarmult_BYTES> shared{};
    if (crypto_scalarmult(shared.data(), receiver_sk.data(), eph_pk.data()) != 0) {
        throw std::runtime_error("RatchetProtocol::derive_packet_key: scalarmult failed");
    }
    std::array<uint8_t, crypto_aead_xchacha20poly1305_ietf_KEYBYTES> out{};
    static const char info[] = "nocturne-rp-pkt-v1";
    if (crypto_generichash(out.data(), out.size(),
                           shared.data(), shared.size(),
                           reinterpret_cast<const unsigned char*>(info), sizeof(info) - 1) != 0) {
        throw std::runtime_error("RatchetProtocol::derive_packet_key: KDF failed");
    }
    return out;
}

inline RatchetProtocol::ProtocolMessage RatchetProtocol::encrypt_message(
    const std::vector<uint8_t>& plaintext,
    const std::array<uint8_t, crypto_kx_PUBLICKEYBYTES>& receiver_pk,
    uint32_t rotation_id,
    const std::vector<uint8_t>& aad,
    void* /*signer_unused*/) {

    if (session_id_.empty() || !session_manager_->has_session(session_id_)) {
        throw std::runtime_error("RatchetProtocol::encrypt_message: no active session");
    }

    ProtocolMessage m{};
    m.version = 0x04;
    m.flags = 0;
    m.rotation_id = rotation_id;
    m.eph_pk = receiver_pk;            // packet-level identifier of intended receiver
    randombytes_buf(m.nonce.data(), m.nonce.size());
    m.counter = 0;
    m.aad = aad;
    m.signature = std::nullopt;

    // The DR encryption is the canonical confidentiality boundary; keep the
    // outer packet ciphertext field empty so wire format is unambiguous.
    m.ratchet_message = session_manager_->encrypt_message(session_id_, plaintext);
    m.counter = m.ratchet_message.message_count;
    m.ciphertext.clear();
    return m;
}

inline std::vector<uint8_t> RatchetProtocol::decrypt_message(
    const ProtocolMessage& message,
    const std::array<uint8_t, crypto_kx_PUBLICKEYBYTES>& /*receiver_pk*/,
    const std::array<uint8_t, crypto_kx_SECRETKEYBYTES>& /*receiver_sk*/,
    const std::optional<std::array<uint8_t, crypto_sign_PUBLICKEYBYTES>>& /*expected_signer*/) {

    if (session_id_.empty() || !session_manager_->has_session(session_id_)) {
        throw std::runtime_error("RatchetProtocol::decrypt_message: no active session");
    }
    return session_manager_->decrypt_message(session_id_, message.ratchet_message);
}

inline std::vector<uint8_t>
RatchetProtocol::serialize_message(const ProtocolMessage& m) {
    std::vector<uint8_t> out;
    constexpr uint8_t FLAG_HAS_SIG_RP = 0x01;
    uint8_t flags = m.flags;
    if (m.signature.has_value()) flags |= FLAG_HAS_SIG_RP;

    out.push_back(m.version);
    out.push_back(flags);
    detail::dr_write_u32_le(out, m.rotation_id);
    out.insert(out.end(), m.eph_pk.begin(), m.eph_pk.end());
    out.insert(out.end(), m.nonce.begin(), m.nonce.end());
    detail::dr_write_u64_le(out, m.counter);

    // Ratchet message payload
    out.insert(out.end(),
               m.ratchet_message.dh_public_key.begin(),
               m.ratchet_message.dh_public_key.end());
    detail::dr_write_u32_le(out, m.ratchet_message.prev_chain_count);
    detail::dr_write_u32_le(out, m.ratchet_message.message_count);
    out.insert(out.end(),
               m.ratchet_message.nonce.begin(),
               m.ratchet_message.nonce.end());
    detail::dr_write_u32_le(out, static_cast<uint32_t>(m.ratchet_message.ciphertext.size()));
    out.insert(out.end(),
               m.ratchet_message.ciphertext.begin(),
               m.ratchet_message.ciphertext.end());

    detail::dr_write_u32_le(out, static_cast<uint32_t>(m.aad.size()));
    out.insert(out.end(), m.aad.begin(), m.aad.end());
    detail::dr_write_u32_le(out, static_cast<uint32_t>(m.ciphertext.size()));
    out.insert(out.end(), m.ciphertext.begin(), m.ciphertext.end());

    if (m.signature.has_value()) {
        out.insert(out.end(), m.signature->begin(), m.signature->end());
    }
    return out;
}

inline std::optional<RatchetProtocol::ProtocolMessage>
RatchetProtocol::deserialize_message(const std::vector<uint8_t>& data) {
    constexpr uint8_t FLAG_HAS_SIG_RP = 0x01;
    constexpr size_t MIN_LEN =
        1 + 1 + 4
        + crypto_kx_PUBLICKEYBYTES
        + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
        + 8
        + crypto_kx_PUBLICKEYBYTES + 4 + 4
        + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES + 4
        + 4 + 4;

    if (data.size() < MIN_LEN) return std::nullopt;

    try {
        ProtocolMessage m{};
        size_t off = 0;
        auto need = [&](size_t n) {
            if (n > data.size() - off) throw std::runtime_error("RP: truncated");
        };
        auto get = [&](void* dst, size_t n) {
            need(n);
            std::memcpy(dst, data.data() + off, n);
            off += n;
        };

        get(&m.version, 1);
        uint8_t flags_raw = 0; get(&flags_raw, 1);
        m.flags = flags_raw & ~FLAG_HAS_SIG_RP;

        uint8_t b4[4]; get(b4, 4); m.rotation_id = detail::dr_read_u32_le(b4);
        get(m.eph_pk.data(), m.eph_pk.size());
        get(m.nonce.data(), m.nonce.size());
        uint8_t b8[8]; get(b8, 8); m.counter = detail::dr_read_u64_le(b8);

        get(m.ratchet_message.dh_public_key.data(), m.ratchet_message.dh_public_key.size());
        get(b4, 4); m.ratchet_message.prev_chain_count = detail::dr_read_u32_le(b4);
        get(b4, 4); m.ratchet_message.message_count = detail::dr_read_u32_le(b4);
        get(m.ratchet_message.nonce.data(), m.ratchet_message.nonce.size());
        get(b4, 4); uint32_t dr_ct_len = detail::dr_read_u32_le(b4);
        if (dr_ct_len > 16u * 1024u * 1024u) return std::nullopt; // 16MB cap
        m.ratchet_message.ciphertext.resize(dr_ct_len);
        if (dr_ct_len) get(m.ratchet_message.ciphertext.data(), dr_ct_len);

        get(b4, 4); uint32_t aad_len = detail::dr_read_u32_le(b4);
        if (aad_len > 64u * 1024u) return std::nullopt;
        m.aad.resize(aad_len);
        if (aad_len) get(m.aad.data(), aad_len);

        get(b4, 4); uint32_t ct_len = detail::dr_read_u32_le(b4);
        if (ct_len > 16u * 1024u * 1024u) return std::nullopt;
        m.ciphertext.resize(ct_len);
        if (ct_len) get(m.ciphertext.data(), ct_len);

        if (flags_raw & FLAG_HAS_SIG_RP) {
            std::array<uint8_t, crypto_sign_BYTES> sig{};
            get(sig.data(), sig.size());
            m.signature = sig;
        }

        if (off != data.size()) return std::nullopt; // trailing bytes
        return m;
    } catch (...) {
        return std::nullopt;
    }
}

} // namespace nocturne
