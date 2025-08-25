#pragma once

#include <array>
#include <cstdint>
#include <memory>
#include <optional>
#include <queue>
#include <unordered_map>
#include <vector>
#include <chrono>
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
        state_.send_message_key = derive_message_key(state_.send_chain_key);
        state_.send_chain_key = derive_chain_key(state_.send_chain_key, "nocturne-dr-send-next");
        state_.send_message_count++;
    } else {
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
    randombytes_buf(m.nonce.data(), m.nonce.size());

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

} // namespace nocturne
