#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>
#include <cstring>
#include <fstream>
#include <sstream>
#include <unordered_map>
#include <filesystem>

#include <sodium.h>

namespace nocturne {
namespace handshake {

using Bytes = std::vector<uint8_t>;

struct Ed25519KeyPair {
    std::array<uint8_t, crypto_sign_PUBLICKEYBYTES> pk{};
    std::array<uint8_t, crypto_sign_SECRETKEYBYTES> sk{};
};

inline Ed25519KeyPair generate_identity_ed25519() {
    Ed25519KeyPair kp{};
    crypto_sign_keypair(kp.pk.data(), kp.sk.data());
    return kp;
}

// Minimal trust store for identity public keys (label -> Ed25519 PK)
class TrustStore {
public:
    explicit TrustStore(std::filesystem::path path) : path_(std::move(path)) {
        try { load(); } catch (...) {}
    }

    void set(const std::string& label, const std::array<uint8_t, crypto_sign_PUBLICKEYBYTES>& pk) {
        store_[label] = pk;
        persist();
    }

    std::optional<std::array<uint8_t, crypto_sign_PUBLICKEYBYTES>> get(const std::string& label) const {
        auto it = store_.find(label);
        if (it == store_.end()) return std::nullopt;
        return it->second;
    }

    void remove(const std::string& label) {
        store_.erase(label);
        persist();
    }

private:
    std::filesystem::path path_;
    std::unordered_map<std::string, std::array<uint8_t, crypto_sign_PUBLICKEYBYTES>> store_;

    static std::string to_hex(const uint8_t* p, size_t n) {
        static const char* hex = "0123456789abcdef";
        std::string s; s.reserve(n*2);
        for (size_t i=0;i<n;i++){ s.push_back(hex[p[i]>>4]); s.push_back(hex[p[i]&0xF]); }
        return s;
    }
    static bool from_hex(const std::string& s, uint8_t* out, size_t n) {
        if (s.size() != n*2) return false;
        auto val = [](char c)->int{
            if (c>='0'&&c<='9') return c-'0';
            if (c>='a'&&c<='f') return c-'a'+10;
            if (c>='A'&&c<='F') return c-'A'+10;
            return -1;
        };
        for (size_t i=0;i<n;i++){
            int hi = val(s[2*i]);
            int lo = val(s[2*i+1]);
            if (hi<0||lo<0) return false;
            out[i] = static_cast<uint8_t>((hi<<4)|lo);
        }
        return true;
    }

    void load() {
        store_.clear();
        if (!std::filesystem::exists(path_)) return;
        std::ifstream f(path_);
        if (!f) throw std::runtime_error("trust store open failed");
        std::string line;
        while (std::getline(f, line)) {
            auto pos = line.find(':');
            if (pos == std::string::npos) continue;
            std::string label = line.substr(0, pos);
            std::string hex = line.substr(pos+1);
            std::array<uint8_t, crypto_sign_PUBLICKEYBYTES> pk{};
            if (from_hex(hex, pk.data(), pk.size())) store_[label] = pk;
        }
    }

    void persist() const {
        std::filesystem::create_directories(path_.parent_path());
        std::string tmp = path_.string() + ".tmp";
        {
            std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
            if (!f) throw std::runtime_error("trust store tmp open failed");
            for (const auto& kv : store_) {
                f << kv.first << ':' << to_hex(kv.second.data(), kv.second.size()) << '\n';
            }
        }
        std::error_code ec;
        std::filesystem::rename(tmp, path_, ec);
        if (ec) { std::filesystem::remove(path_, ec); std::filesystem::rename(tmp, path_, ec); if (ec) throw std::runtime_error("trust store rename failed: "+ec.message()); }
    }
};

// Handshake messages
struct Hello1 {
    std::array<uint8_t, crypto_kx_PUBLICKEYBYTES> eph_pk_i{};
};

struct Hello2 {
    std::array<uint8_t, crypto_kx_PUBLICKEYBYTES> eph_pk_r{};
    std::array<uint8_t, crypto_sign_BYTES> sig_r{}; // Ed25519(signature over transcript)
};

struct Hello3 {
    std::array<uint8_t, crypto_sign_BYTES> sig_i{}; // Ed25519(signature over transcript)
};

// Serialization helpers
inline Bytes serialize(const Hello1& m){ return Bytes(m.eph_pk_i.begin(), m.eph_pk_i.end()); }
inline Bytes serialize(const Hello2& m){ Bytes b; b.insert(b.end(), m.eph_pk_r.begin(), m.eph_pk_r.end()); b.insert(b.end(), m.sig_r.begin(), m.sig_r.end()); return b; }
inline Bytes serialize(const Hello3& m){ return Bytes(m.sig_i.begin(), m.sig_i.end()); }

inline Hello1 parse_hello1(const Bytes& b){ if (b.size()!=crypto_kx_PUBLICKEYBYTES) throw std::runtime_error("Hello1 size"); Hello1 m; std::memcpy(m.eph_pk_i.data(), b.data(), m.eph_pk_i.size()); return m; }
inline Hello2 parse_hello2(const Bytes& b){ if (b.size()!=crypto_kx_PUBLICKEYBYTES+crypto_sign_BYTES) throw std::runtime_error("Hello2 size"); Hello2 m; std::memcpy(m.eph_pk_r.data(), b.data(), m.eph_pk_r.size()); std::memcpy(m.sig_r.data(), b.data()+m.eph_pk_r.size(), m.sig_r.size()); return m; }
inline Hello3 parse_hello3(const Bytes& b){ if (b.size()!=crypto_sign_BYTES) throw std::runtime_error("Hello3 size"); Hello3 m; std::memcpy(m.sig_i.data(), b.data(), m.sig_i.size()); return m; }

// Transcript helper
inline std::array<uint8_t, 32> compute_transcript_hash(const std::array<uint8_t, crypto_kx_PUBLICKEYBYTES>& eph_i,
                                                       const std::array<uint8_t, crypto_kx_PUBLICKEYBYTES>& eph_r,
                                                       const std::string& prologue = "") {
    std::array<uint8_t, 32> h{};
    crypto_generichash_state st; crypto_generichash_init(&st, nullptr, 0, h.size());
    const char* ctx = "NOCTURNE-HS-V1"; crypto_generichash_update(&st, reinterpret_cast<const unsigned char*>(ctx), std::strlen(ctx));
    if (!prologue.empty()) crypto_generichash_update(&st, reinterpret_cast<const unsigned char*>(prologue.data()), prologue.size());
    crypto_generichash_update(&st, eph_i.data(), eph_i.size());
    crypto_generichash_update(&st, eph_r.data(), eph_r.size());
    crypto_generichash_final(&st, h.data(), h.size());
    return h;
}

// Key derivation helper for session keys
inline void derive_session_keys(const std::array<uint8_t, crypto_scalarmult_BYTES>& shared,
                                const std::array<uint8_t, 32>& transcript_hash,
                                bool initiator,
                                std::array<uint8_t, crypto_aead_xchacha20poly1305_ietf_KEYBYTES>& tx,
                                std::array<uint8_t, crypto_aead_xchacha20poly1305_ietf_KEYBYTES>& rx) {
    std::array<uint8_t, crypto_aead_xchacha20poly1305_ietf_KEYBYTES> kbase{};
    // Mix shared || transcript -> base key
    Bytes seed; seed.insert(seed.end(), shared.begin(), shared.end()); seed.insert(seed.end(), transcript_hash.begin(), transcript_hash.end());
    if (crypto_generichash(kbase.data(), kbase.size(), seed.data(), seed.size(), reinterpret_cast<const unsigned char*>("nocturne-hs-base"), sizeof("nocturne-hs-base")-1) != 0)
        throw std::runtime_error("hs base kdf failed");

    auto derive = [&](const char* info, std::array<uint8_t, crypto_aead_xchacha20poly1305_ietf_KEYBYTES>& out){
        if (crypto_generichash(out.data(), out.size(), kbase.data(), kbase.size(), reinterpret_cast<const unsigned char*>(info), std::strlen(info)) != 0)
            throw std::runtime_error("hs kdf failed");
    };

    if (initiator) {
        derive("nocturne-hs-init-tx", tx);
        derive("nocturne-hs-init-rx", rx);
    } else {
        derive("nocturne-hs-resp-tx", tx);
        derive("nocturne-hs-resp-rx", rx);
    }
}

// Initiator role
class InitiatorHandshake {
public:
    InitiatorHandshake(const Ed25519KeyPair& id, const std::array<uint8_t, crypto_sign_PUBLICKEYBYTES>& expected_responder_id_pk,
                       const std::string& prologue = "")
        : id_(id), responder_id_pk_(expected_responder_id_pk), prologue_(prologue) {
        crypto_kx_keypair(eph_pk_i_.data(), eph_sk_i_.data());
    }

    Hello1 create_hello1() const { Hello1 h{}; h.eph_pk_i = eph_pk_i_; return h; }

    // Returns Hello3 and derives tx/rx keys
    Hello3 process_hello2(const Hello2& h2) {
        auto th = compute_transcript_hash(eph_pk_i_, h2.eph_pk_r, prologue_);
        // Verify responder signature over transcript hash
        if (crypto_sign_verify_detached(h2.sig_r.data(), th.data(), th.size(), responder_id_pk_.data()) != 0)
            throw std::runtime_error("handshake: responder signature verify failed");
        // Compute shared
        std::array<uint8_t, crypto_scalarmult_BYTES> shared{};
        if (crypto_scalarmult(shared.data(), eph_sk_i_.data(), h2.eph_pk_r.data()) != 0)
            throw std::runtime_error("handshake: scalarmult failed (init)");
        derive_session_keys(shared, th, true, tx_key_, rx_key_);
        // Produce initiator signature
        Hello3 h3{};
        crypto_sign_detached(h3.sig_i.data(), nullptr, th.data(), th.size(), id_.sk.data());
        complete_ = true;
        return h3;
    }

    bool is_complete() const { return complete_; }
    std::array<uint8_t, crypto_aead_xchacha20poly1305_ietf_KEYBYTES> tx_key() const { return tx_key_; }
    std::array<uint8_t, crypto_aead_xchacha20poly1305_ietf_KEYBYTES> rx_key() const { return rx_key_; }

private:
    Ed25519KeyPair id_{};
    std::array<uint8_t, crypto_sign_PUBLICKEYBYTES> responder_id_pk_{};
    std::string prologue_{};
    std::array<uint8_t, crypto_kx_PUBLICKEYBYTES> eph_pk_i_{};
    std::array<uint8_t, crypto_kx_SECRETKEYBYTES> eph_sk_i_{};
    std::array<uint8_t, crypto_aead_xchacha20poly1305_ietf_KEYBYTES> tx_key_{};
    std::array<uint8_t, crypto_aead_xchacha20poly1305_ietf_KEYBYTES> rx_key_{};
    bool complete_{false};
};

// Responder role
class ResponderHandshake {
public:
    ResponderHandshake(const Ed25519KeyPair& id, const std::array<uint8_t, crypto_sign_PUBLICKEYBYTES>& expected_initiator_id_pk,
                       const std::string& prologue = "")
        : id_(id), initiator_id_pk_(expected_initiator_id_pk), prologue_(prologue) {}

    Hello2 process_hello1(const Hello1& h1) {
        crypto_kx_keypair(eph_pk_r_.data(), eph_sk_r_.data());
        auto th = compute_transcript_hash(h1.eph_pk_i, eph_pk_r_, prologue_);
        // Sign transcript
        Hello2 h2{}; h2.eph_pk_r = eph_pk_r_;
        crypto_sign_detached(h2.sig_r.data(), nullptr, th.data(), th.size(), id_.sk.data());
        // Compute shared and derive keys (responder perspective)
        std::array<uint8_t, crypto_scalarmult_BYTES> shared{};
        if (crypto_scalarmult(shared.data(), eph_sk_r_.data(), h1.eph_pk_i.data()) != 0)
            throw std::runtime_error("handshake: scalarmult failed (resp)");
        derive_session_keys(shared, th, false, tx_key_, rx_key_);
        seen_hello1_ = h1;
        return h2;
    }

    void finalize(const Hello3& h3) {
        if (!seen_hello1_.has_value()) throw std::runtime_error("handshake: missing hello1");
        auto th = compute_transcript_hash(seen_hello1_->eph_pk_i, eph_pk_r_, prologue_);
        if (crypto_sign_verify_detached(h3.sig_i.data(), th.data(), th.size(), initiator_id_pk_.data()) != 0)
            throw std::runtime_error("handshake: initiator signature verify failed");
        complete_ = true;
    }

    bool is_complete() const { return complete_; }
    std::array<uint8_t, crypto_aead_xchacha20poly1305_ietf_KEYBYTES> tx_key() const { return tx_key_; }
    std::array<uint8_t, crypto_aead_xchacha20poly1305_ietf_KEYBYTES> rx_key() const { return rx_key_; }

private:
    Ed25519KeyPair id_{};
    std::array<uint8_t, crypto_sign_PUBLICKEYBYTES> initiator_id_pk_{};
    std::string prologue_{};
    std::array<uint8_t, crypto_kx_PUBLICKEYBYTES> eph_pk_r_{};
    std::array<uint8_t, crypto_kx_SECRETKEYBYTES> eph_sk_r_{};
    std::optional<Hello1> seen_hello1_{};
    std::array<uint8_t, crypto_aead_xchacha20poly1305_ietf_KEYBYTES> tx_key_{};
    std::array<uint8_t, crypto_aead_xchacha20poly1305_ietf_KEYBYTES> rx_key_{};
    bool complete_{false};
};

} // namespace handshake
} // namespace nocturne


