#ifndef NOCTURNE_HSM_FILE_HSM_HPP
#define NOCTURNE_HSM_FILE_HSM_HPP

#include "hsm_interface.hpp"
#include "hsm_errors.hpp"
#include "../core/side_channel.hpp"

#include <array>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>
#include <sodium.h>

namespace nocturne {
namespace hsm {

// File-backed HSM. For development and CI only — keys live on disk as raw
// libsodium Ed25519 secret keys (64 B), one file per label. The point is
// to satisfy nocturne::hsm::HSMInterface so KeyRotationManager and other
// consumers have a working, testable backend without dragging SoftHSM
// into every unit test.
//
// Security:
//  - Keys are unencrypted at rest (the inline FileHSM in nocturne-kx.cpp
//    is the passphrase-protected production path; this class is the
//    in-namespace counterpart for hsm::HSMInterface consumers).
//  - The directory is created on demand. Use a path that's not world-
//    readable in real deployments.
//
// Behavior of generate_key:
//  - Algorithm must be "Ed25519" (the only one the project's signing
//    paths use). Anything else throws HSMOperationNotSupportedError.
//  - The newly generated keypair replaces the "active" key used by
//    sign()/get_public_key() — matching the semantics KeyRotationManager
//    expects (it calls generate_key, then immediately uses the HSM to
//    sign with the new key).
class FileHSM : public HSMInterface {
public:
    explicit FileHSM(std::filesystem::path key_dir)
        : key_dir_(std::move(key_dir)) {
        if (sodium_init() < 0) {
            throw HSMError("libsodium init failed");
        }
        std::filesystem::create_directories(key_dir_);
    }

    ~FileHSM() override {
        // Best-effort wipe of the cached secret key when the HSM goes
        // away. The on-disk copy is still there; callers who need true
        // forward secrecy must delete_key() before destruction.
        nocturne::side_channel::secure_zero_memory(active_sk_.data(), active_sk_.size());
    }

    std::array<uint8_t, crypto_sign_BYTES> sign(const uint8_t* data, size_t len) override {
        std::lock_guard<std::mutex> lk(mu_);
        if (!have_active_) {
            throw HSMError("FileHSM: no active key (call generate_key or load a key first)");
        }
        std::array<uint8_t, crypto_sign_BYTES> sig{};
        unsigned long long siglen = 0;
        if (crypto_sign_detached(sig.data(), &siglen, data, len, active_sk_.data()) != 0) {
            throw HSMError("FileHSM: crypto_sign_detached failed");
        }
        if (siglen != crypto_sign_BYTES) {
            throw HSMError("FileHSM: unexpected signature length");
        }
        return sig;
    }

    bool verify(const uint8_t* data, size_t len,
                const uint8_t* signature, size_t sig_len) override {
        std::lock_guard<std::mutex> lk(mu_);
        if (!have_active_ || sig_len != crypto_sign_BYTES) return false;
        return crypto_sign_verify_detached(signature, data, len, active_pk_.data()) == 0;
    }

    std::optional<std::array<uint8_t, crypto_sign_PUBLICKEYBYTES>> get_public_key() override {
        std::lock_guard<std::mutex> lk(mu_);
        if (!have_active_) return std::nullopt;
        return active_pk_;
    }

    bool has_key(const std::string& label) override {
        std::lock_guard<std::mutex> lk(mu_);
        return keys_.count(label) > 0 || std::filesystem::exists(path_for(label));
    }

    std::vector<uint8_t> generate_random(size_t length) override {
        std::vector<uint8_t> out(length);
        randombytes_buf(out.data(), out.size());
        return out;
    }

    bool is_healthy() override {
        return std::filesystem::is_directory(key_dir_);
    }

    KeyMetadata generate_key(const std::string& label,
                             const std::string& algorithm,
                             const KeyPolicy& policy) override {
        if (algorithm != "Ed25519") {
            throw HSMOperationNotSupportedError("FileHSM only supports Ed25519, got " + algorithm);
        }

        std::lock_guard<std::mutex> lk(mu_);

        std::array<uint8_t, crypto_sign_PUBLICKEYBYTES> pk{};
        std::array<uint8_t, crypto_sign_SECRETKEYBYTES> sk{};
        if (crypto_sign_keypair(pk.data(), sk.data()) != 0) {
            throw HSMError("FileHSM: crypto_sign_keypair failed");
        }

        // Persist the SK alongside its PK so it can be re-loaded later.
        auto sk_path = path_for(label);
        std::filesystem::create_directories(sk_path.parent_path());
        {
            std::ofstream f(sk_path, std::ios::binary | std::ios::trunc);
            if (!f) {
                nocturne::side_channel::secure_zero_memory(sk.data(), sk.size());
                throw HSMError("FileHSM: cannot write key file " + sk_path.string());
            }
            f.write(reinterpret_cast<const char*>(sk.data()),
                    static_cast<std::streamsize>(sk.size()));
        }

        // The newly generated key becomes the active signing key. The
        // previous active SK is securely zeroed first.
        nocturne::side_channel::secure_zero_memory(active_sk_.data(), active_sk_.size());
        active_sk_ = sk;
        active_pk_ = pk;
        active_label_ = label;
        have_active_ = true;

        KeyMetadata md;
        md.label = label;
        md.key_id = label;  // FileHSM uses label as id
        md.algorithm = algorithm;
        md.policy = policy;
        md.created_at = std::chrono::system_clock::now();
        if (policy.max_lifetime.count() > 0) {
            md.expires_at = md.created_at + policy.max_lifetime;
        }
        md.is_active = true;
        keys_[label] = md;

        nocturne::side_channel::secure_zero_memory(sk.data(), sk.size());
        return md;
    }

    bool delete_key(const std::string& label) override {
        std::lock_guard<std::mutex> lk(mu_);
        std::error_code ec;
        std::filesystem::remove(path_for(label), ec);
        keys_.erase(label);
        if (active_label_ && *active_label_ == label) {
            nocturne::side_channel::secure_zero_memory(active_sk_.data(), active_sk_.size());
            have_active_ = false;
            active_label_.reset();
        }
        return !ec;
    }

    std::vector<KeyMetadata> list_keys() override {
        std::lock_guard<std::mutex> lk(mu_);
        std::vector<KeyMetadata> out;
        out.reserve(keys_.size());
        for (const auto& [_, md] : keys_) out.push_back(md);
        return out;
    }

private:
    std::filesystem::path path_for(const std::string& label) const {
        return key_dir_ / (label + ".ed25519.sk");
    }

    std::filesystem::path key_dir_;
    mutable std::mutex mu_;
    std::optional<std::string> active_label_;
    std::array<uint8_t, crypto_sign_SECRETKEYBYTES> active_sk_{};
    std::array<uint8_t, crypto_sign_PUBLICKEYBYTES> active_pk_{};
    bool have_active_ = false;
    std::unordered_map<std::string, KeyMetadata> keys_;
};

} // namespace hsm
} // namespace nocturne

#endif // NOCTURNE_HSM_FILE_HSM_HPP
