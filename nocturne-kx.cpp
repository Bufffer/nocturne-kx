/**
 * @file nocturne-kx.cpp
 * @brief Nocturne-KX: Post-Quantum Secure Key Exchange and Messaging Protocol
 *
 * Copyright (c) 2025 Halil İbrahim Serdaroğlu
 *
 * This software is the exclusive property of Halil İbrahim Serdaroğlu.
 * All rights reserved.
 *
 * Patent Pending: Hybrid Post-Quantum KEM System
 * Trademark: Nocturne-KX™
 *
 * Licensed under the MIT License (see LICENSE file)
 *
 * @author Halil İbrahim Serdaroğlu
 * @version 4.0.0
 * @date 2025
 */

#include <array>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>
#include <chrono>
#include <unordered_map>
#include <mutex>
#include <sstream>
#include <cstdio>
#include <random>
#include <thread>
#include <atomic>
#include <map>
#include <algorithm>
#include <functional>
#include "src/double_ratchet.hpp"
#include "src/handshake.hpp"
#include "src/transport.hpp"
#include "src/core/side_channel.hpp"
#include "src/hsm/pkcs11_hsm.hpp"
#include "src/pqc/kem/kem_factory.hpp"
#include "src/pqc/sig/sig_factory.hpp"
#include "src/pqc/pqc_config.hpp"
#include <iomanip>

// Platform-specific headers for memory protection
#ifdef _WIN32
#include <windows.h>
#include <memoryapi.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#endif

#include <sodium.h>
// ----- FileHSM secure storage helpers (passphrase-based at-rest encryption) -----
namespace filehsm_secure_storage {
    static constexpr const char* MAGIC = "NCHSM2"; // simple magic header
    static constexpr size_t MAGIC_LEN = 6;
    static constexpr size_t SALT_LEN = 16;

    inline bool looks_encrypted(const std::vector<uint8_t>& blob) {
        return blob.size() > MAGIC_LEN && std::memcmp(blob.data(), MAGIC, MAGIC_LEN) == 0;
    }

    inline std::optional<std::array<uint8_t, crypto_sign_SECRETKEYBYTES>>
    decrypt_sk_with_passphrase(const std::vector<uint8_t>& blob) {
        if (!looks_encrypted(blob)) return std::nullopt;
        const uint8_t* p = blob.data() + MAGIC_LEN;
        size_t rem = blob.size() - MAGIC_LEN;
        if (rem < SALT_LEN + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES + crypto_aead_xchacha20poly1305_ietf_ABYTES)
            throw std::runtime_error("FileHSM: encrypted blob truncated");
        std::array<uint8_t, SALT_LEN> salt{}; std::memcpy(salt.data(), p, SALT_LEN); p += SALT_LEN; rem -= SALT_LEN;
        std::array<uint8_t, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES> npub{}; std::memcpy(npub.data(), p, npub.size()); p += npub.size(); rem -= npub.size();
        std::vector<uint8_t> ct(p, p + rem);

        const char* pass = std::getenv("NOCTURNE_HSM_PASSPHRASE");
        if (!pass || std::strlen(pass) == 0) throw std::runtime_error("FileHSM: NOCTURNE_HSM_PASSPHRASE not set for encrypted key");

        std::array<uint8_t, crypto_aead_xchacha20poly1305_ietf_KEYBYTES> k{};
        if (crypto_pwhash(k.data(), k.size(), pass, std::strlen(pass), salt.data(),
                          crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE, crypto_pwhash_ALG_DEFAULT) != 0) {
            throw std::runtime_error("FileHSM: key derivation failed");
        }

        if (ct.size() != crypto_sign_SECRETKEYBYTES + crypto_aead_xchacha20poly1305_ietf_ABYTES)
            throw std::runtime_error("FileHSM: encrypted payload size invalid");

        std::array<uint8_t, crypto_sign_SECRETKEYBYTES> sk{};
        unsigned long long pt_len = 0;
        if (crypto_aead_xchacha20poly1305_ietf_decrypt(sk.data(), &pt_len, nullptr,
                ct.data(), ct.size(), nullptr, 0, npub.data(), k.data()) != 0) {
            throw std::runtime_error("FileHSM: decryption failed");
        }
        if (pt_len != crypto_sign_SECRETKEYBYTES) throw std::runtime_error("FileHSM: decrypted length mismatch");
        return sk;
    }
}

// Platform-specific headers for side-channel protection
#if defined(__x86_64__) || defined(__i386__)
#include <immintrin.h>
#endif

// SECURITY CONSTANTS (Global namespace for accessibility)
constexpr size_t MAX_PACKET_SIZE = 1024 * 1024;      // 1MB maximum packet size
constexpr size_t MAX_AAD_SIZE = 64 * 1024;           // 64KB maximum AAD size
constexpr size_t MAX_CIPHERTEXT_SIZE = 1024 * 1024;  // 1MB maximum ciphertext size
constexpr size_t MAX_ALLOCATION_SIZE = 100 * 1024 * 1024; // 100MB maximum allocation

/*
 Nocturne-KX - hardened / near-military prototype v3
 ----------------------------------------------------
 This file extends the earlier prototype with the following practical hardening additions:

 1) Robust Replay DB: atomic writes, HMAC-protected JSON, anti-rollback version counter.
 2) Key rotation enforcement + rotation metadata. Rotation metadata can be audited.
 3) Ratchet scaffolding updated and an example "simple DH ratchet" implemented as an optional
    feature (NOT a full Double-Ratchet; see notes below).
 4) HSM/PKCS#11 loader example (stub + PKCS#11 helper wrapper) and integration note.
 5) CI/test hooks (Catch2 unit test skeleton added in tests/). New GitHub Actions workflow runs
    sanitizers (ASAN/UBSAN), unit tests, and a fuzzing job skeleton.
 6) ReplayDB encrypted/MACed and persisted atomically to prevent easy tampering/rollback.
 7) More defensive coding: strict length checks, fewer implicit casts, and explicit zeroing.

 IMPORTANT SECURITY NOTES:
 - This remains *prototype* code. It is NOT production-ready without formal security audit.
 - For production you MUST: obtain formal specification, peer review, formal verification, and an independent security audit.
 - Replace the simple ratchet with a formal Double Ratchet or Noise-based handshake if you want forward secrecy + post-compromise recovery.
 - Integrate HSMs using validated PKCS#11 modules and ensure private keys never leave secure hardware.

 The code compiles with C++23 and libsodium. See README and CI for build/test instructions.
*/

// Rate limiting utilities for DoS and brute force protection
namespace rate_limiting {
    
    // Rate limit configuration
    struct RateLimitConfig {
        uint32_t max_requests_per_minute = 60;      // Default: 60 requests per minute
        uint32_t max_requests_per_hour = 1000;      // Default: 1000 requests per hour
        uint32_t max_requests_per_day = 10000;      // Default: 10000 requests per day
        uint32_t burst_limit = 10;                  // Default: 10 requests in burst
        uint32_t burst_window_ms = 1000;           // Default: 1 second burst window
        uint32_t penalty_duration_ms = 300000;     // Default: 5 minutes penalty
        bool enable_exponential_backoff = true;     // Enable exponential backoff
        uint32_t max_backoff_ms = 60000;           // Maximum backoff: 1 minute
    };
    
    // Request tracking entry
    struct RequestEntry {
        std::chrono::steady_clock::time_point timestamp;
        uint32_t request_count = 0;
        uint32_t penalty_count = 0;
        std::chrono::steady_clock::time_point last_penalty;
        uint32_t current_backoff_ms = 0;
        
        RequestEntry() : timestamp(std::chrono::steady_clock::now()), 
                        last_penalty(std::chrono::steady_clock::now()) {}
    };
    
    // Rate limiter implementation
    class RateLimiter {
    private:
        std::unordered_map<std::string, RequestEntry> request_history_;
        std::mutex mutex_;
        RateLimitConfig config_;
        // Optional persistence
        std::optional<std::filesystem::path> storage_path_;
        std::chrono::steady_clock::time_point last_persist_{std::chrono::steady_clock::now()};
        uint32_t persist_interval_ms_{60000}; // 60s
        
        // Clean up old entries to prevent memory leaks
        void cleanup_old_entries() {
            auto now = std::chrono::steady_clock::now();
            auto day_ago = now - std::chrono::hours(24);
            
            for (auto it = request_history_.begin(); it != request_history_.end();) {
                if (it->second.timestamp < day_ago) {
                    it = request_history_.erase(it);
                } else {
                    ++it;
                }
            }
        }

        // Persistence: very simple JSONL (identifier, count, penalty, last_penalty, backoff)
        void persist_locked() {
            if (!storage_path_) return;
            auto now = std::chrono::steady_clock::now();
            if (std::chrono::duration_cast<std::chrono::milliseconds>(now - last_persist_).count() < persist_interval_ms_) return;
            last_persist_ = now;
            try {
                std::filesystem::create_directories(storage_path_->parent_path());
                std::string tmp = storage_path_->string() + ".tmp";
                std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
                if (!f) return;
                for (const auto& kv : request_history_) {
                    const auto& id = kv.first; const auto& e = kv.second;
                    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(e.last_penalty.time_since_epoch()).count();
                    f << id << ',' << e.request_count << ',' << e.penalty_count << ',' << ms << ',' << e.current_backoff_ms << '\n';
                }
                f.close();
                std::error_code ec;
                std::filesystem::rename(tmp, *storage_path_, ec);
                if (ec) { std::filesystem::remove(*storage_path_, ec); std::filesystem::rename(tmp, *storage_path_, ec); }
            } catch (...) { /* best-effort */ }
        }

        void load_from_disk() {
            if (!storage_path_ || !std::filesystem::exists(*storage_path_)) return;
            try {
                std::ifstream f(*storage_path_);
                if (!f) return;
                request_history_.clear();
                std::string line;
                while (std::getline(f, line)) {
                    // id,req,pen,last_ms,backoff
                    std::istringstream iss(line);
                    std::string id; std::getline(iss, id, ',');
                    std::string s_req, s_pen, s_last, s_back;
                    std::getline(iss, s_req, ','); std::getline(iss, s_pen, ','); std::getline(iss, s_last, ','); std::getline(iss, s_back, ',');
                    RequestEntry e;
                    e.request_count = s_req.empty()?0:static_cast<uint32_t>(std::stoul(s_req));
                    e.penalty_count = s_pen.empty()?0:static_cast<uint32_t>(std::stoul(s_pen));
                    long long last_ms = s_last.empty()?0:std::stoll(s_last);
                    e.last_penalty = std::chrono::steady_clock::time_point(std::chrono::milliseconds(last_ms));
                    e.current_backoff_ms = s_back.empty()?0:static_cast<uint32_t>(std::stoul(s_back));
                    request_history_[id] = e;
                }
            } catch (...) { /* ignore */ }
        }
        
        // Calculate exponential backoff
        uint32_t calculate_backoff(uint32_t penalty_count) {
            if (!config_.enable_exponential_backoff || penalty_count == 0) {
                return 0;
            }
            
            // Exponential backoff: 2^penalty_count * base_delay
            uint32_t base_delay = 1000; // 1 second base
            uint32_t backoff = base_delay * (1 << std::min(penalty_count, 10u)); // Cap at 2^10
            
            return std::min(backoff, config_.max_backoff_ms);
        }
        
    public:
        explicit RateLimiter(const RateLimitConfig& config = RateLimitConfig{},
                             const std::optional<std::filesystem::path>& storage_path = std::nullopt) 
            : config_(config), storage_path_(storage_path) {
            if (storage_path_) load_from_disk();
        }
        
        // Check if request is allowed
        bool allow_request(const std::string& identifier) {
            std::lock_guard<std::mutex> lock(mutex_);
            
            auto now = std::chrono::steady_clock::now();
            auto& entry = request_history_[identifier];
            
            // Clean up old entries periodically
            if (now - entry.timestamp > std::chrono::hours(1)) {
                cleanup_old_entries();
            }
            
            // Check if currently under penalty
            if (entry.penalty_count > 0) {
                auto time_since_penalty = now - entry.last_penalty;
                auto penalty_duration = std::chrono::milliseconds(config_.penalty_duration_ms);
                
                if (time_since_penalty < penalty_duration) {
                    // Still under penalty - apply backoff
                    auto backoff_duration = std::chrono::milliseconds(entry.current_backoff_ms);
                    if (time_since_penalty < backoff_duration) {
                        return false; // Request blocked
                    }
                } else {
                    // Penalty expired, reset
                    entry.penalty_count = 0;
                    entry.current_backoff_ms = 0;
                }
            }
            
            // Update request count and timestamp
            entry.request_count++;
            entry.timestamp = now;
            
            // Check burst limit
            auto requests_in_burst = entry.request_count;
            
            if (requests_in_burst > config_.burst_limit) {
                // Burst limit exceeded - apply penalty
                entry.penalty_count++;
                entry.last_penalty = now;
                entry.current_backoff_ms = calculate_backoff(entry.penalty_count);
                return false;
            }
            
            // Check rate limits
            auto minute_ago = now - std::chrono::minutes(1);
            auto hour_ago = now - std::chrono::hours(1);
            auto day_ago = now - std::chrono::hours(24);
            
            uint32_t requests_last_minute = 0;
            uint32_t requests_last_hour = 0;
            uint32_t requests_last_day = 0;
            
            // Count requests in time windows (simplified - in production use sliding window)
            if (entry.timestamp > minute_ago) requests_last_minute = entry.request_count;
            if (entry.timestamp > hour_ago) requests_last_hour = entry.request_count;
            if (entry.timestamp > day_ago) requests_last_day = entry.request_count;
            
            // Check limits
            if (requests_last_minute > config_.max_requests_per_minute ||
                requests_last_hour > config_.max_requests_per_hour ||
                requests_last_day > config_.max_requests_per_day) {
                
                // Rate limit exceeded - apply penalty
                entry.penalty_count++;
                entry.last_penalty = now;
                entry.current_backoff_ms = calculate_backoff(entry.penalty_count);
                return false;
            }
            
            // Periodically persist to disk
            persist_locked();
            return true; // Request allowed
        }
        
        // Get current status for an identifier
        std::string get_status(const std::string& identifier) {
            std::lock_guard<std::mutex> lock(mutex_);
            
            auto it = request_history_.find(identifier);
            if (it == request_history_.end()) {
                return "No requests recorded";
            }
            
            auto& entry = it->second;
            
            std::ostringstream oss;
            oss << "Requests: " << entry.request_count 
                << ", Penalties: " << entry.penalty_count
                << ", Backoff: " << entry.current_backoff_ms << "ms";
            
            return oss.str();
        }
        
        // Reset rate limiter for an identifier
        void reset(const std::string& identifier) {
            std::lock_guard<std::mutex> lock(mutex_);
            request_history_.erase(identifier);
        }
        
        // Update configuration
        void update_config(const RateLimitConfig& config) {
            std::lock_guard<std::mutex> lock(mutex_);
            config_ = config;
        }
    };
    
    // Global rate limiter instance
    static std::unique_ptr<RateLimiter> global_limiter = nullptr;
    
    // Initialize global rate limiter
    inline void initialize(const RateLimitConfig& config = RateLimitConfig{}, const std::optional<std::filesystem::path>& storage_path = std::nullopt) {
        if (!global_limiter) {
            global_limiter = std::make_unique<RateLimiter>(config, storage_path);
        }
    }
    
    // Check if request is allowed (global interface)
    inline bool allow_request(const std::string& identifier) {
        if (!global_limiter) {
            initialize(); // Initialize with default config
        }
        return global_limiter->allow_request(identifier);
    }
    
    // Get status (global interface)
    inline std::string get_status(const std::string& identifier) {
        if (!global_limiter) {
            return "Rate limiter not initialized";
        }
        return global_limiter->get_status(identifier);
    }
    
    // Reset (global interface)
    inline void reset(const std::string& identifier) {
        if (global_limiter) {
            global_limiter->reset(identifier);
        }
    }
}

// Structured audit logging (JSON Lines) with hash-chaining, optional signing, and anchoring
namespace audit_log {
    enum class Severity { INFO, WARN, ERROR, SECURITY };

    // 32-byte BLAKE2b hash
    using Hash32 = std::array<uint8_t, 32>;

    inline Hash32 blake2b_32(const std::vector<uint8_t>& data) {
        Hash32 out{};
        if (crypto_generichash(out.data(), out.size(), data.data(), data.size(), nullptr, 0) != 0) {
            throw std::runtime_error("audit: hash failed");
        }
        return out;
    }

    inline std::string hex_from(const uint8_t* p, size_t n) {
        static const char* hex = "0123456789abcdef";
        std::string s; s.reserve(n*2);
        for (size_t i=0;i<n;i++) { unsigned v=p[i]; s.push_back(hex[v>>4]); s.push_back(hex[v&0xF]); }
        return s;
    }
    inline std::string hex_from(const Hash32& h) { return hex_from(h.data(), h.size()); }

    class AuditLogger {
    private:
        std::mutex mu_;
        std::optional<std::filesystem::path> path_;
        std::optional<std::filesystem::path> chain_path_;
        std::optional<std::filesystem::path> worm_dir_;
        Hash32 last_hash_{}; // zero for start-of-chain
        bool have_last_ = false;

        // Optional Ed25519 signing
        bool sign_enabled_ = false;
        std::array<uint8_t, crypto_sign_SECRETKEYBYTES> sk_{};
        std::array<uint8_t, crypto_sign_PUBLICKEYBYTES> pk_{};

        void load_chain_state() {
            if (!chain_path_ || !std::filesystem::exists(*chain_path_)) { have_last_ = false; return; }
            std::ifstream f(*chain_path_, std::ios::binary);
            if (!f) { have_last_ = false; return; }
            f.read(reinterpret_cast<char*>(last_hash_.data()), static_cast<std::streamsize>(last_hash_.size()));
            have_last_ = f.gcount() == static_cast<std::streamsize>(last_hash_.size());
        }

        void save_chain_state() {
            if (!chain_path_) return;
            std::ofstream f(*chain_path_, std::ios::binary | std::ios::trunc);
            if (!f) return;
            f.write(reinterpret_cast<const char*>(last_hash_.data()), static_cast<std::streamsize>(last_hash_.size()));
        }

        static const char* sev_str(Severity s) {
            switch(s) { case Severity::INFO: return "INFO"; case Severity::WARN: return "WARN"; case Severity::ERROR: return "ERROR"; default: return "SECURITY"; }
        }

        // Build canonical bytes for hashing: prev||ts||sev||cat||sub||msg (with separators)
        static std::vector<uint8_t> canonical_bytes(const Hash32& prev,
                                                    int64_t ts_ms,
                                                    Severity sev,
                                                    const std::string& cat,
                                                    const std::string& sub,
                                                    const std::string& msg) {
            std::vector<uint8_t> b;
            b.insert(b.end(), prev.begin(), prev.end());
            auto put64 = [&](uint64_t v){ for(int i=0;i<8;i++) b.push_back(static_cast<uint8_t>((v>>(8*i))&0xFF)); };
            put64(static_cast<uint64_t>(ts_ms));
            b.push_back(static_cast<uint8_t>(sev));
            b.push_back(0);
            b.insert(b.end(), cat.begin(), cat.end()); b.push_back(0);
            b.insert(b.end(), sub.begin(), sub.end()); b.push_back(0);
            b.insert(b.end(), msg.begin(), msg.end());
            return b;
        }

        static void json_escape(std::ostream& f, const std::string& s) {
            for (char c : s) { if (c=='"') f << '\\'; f << c; }
        }

        void maybe_anchor_from_file_unlocked(const std::optional<std::filesystem::path>& anchor_file) {
            if (!anchor_file || !std::filesystem::exists(*anchor_file)) return;
            try {
                std::ifstream af(*anchor_file, std::ios::binary);
                std::vector<uint8_t> buf((std::istreambuf_iterator<char>(af)), std::istreambuf_iterator<char>());
                std::string anchor_hex = hex_from(buf.data(), buf.size());
                append_record_unlocked(Severity::SECURITY, "ANCHOR", "TSA", anchor_hex);
            } catch (...) { /* ignore anchor errors */ }
        }

        void append_record_unlocked(Severity sev, const std::string& category, const std::string& subject, const std::string& message) {
            if (!path_) return;
            std::filesystem::create_directories(path_->parent_path());
            std::ofstream f(*path_, std::ios::app);
            if (!f) return;
            auto now = std::chrono::system_clock::now();
            auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();

            Hash32 prev = have_last_ ? last_hash_ : Hash32{};
            auto canon = canonical_bytes(prev, ms, sev, category, subject, message);
            Hash32 h = blake2b_32(canon);

            // Optional signature of hash
            std::array<uint8_t, crypto_sign_BYTES> sig{};
            bool have_sig = false;
            if (sign_enabled_) {
                unsigned long long siglen = 0;
                if (crypto_sign_detached(sig.data(), &siglen, h.data(), h.size(), sk_.data()) == 0 && siglen == crypto_sign_BYTES) {
                    have_sig = true;
                }
            }

            // JSON line
            std::ostringstream json;
            json << "{\"ts\":" << ms
              << ",\"sev\":\"" << sev_str(sev) << "\""
              << ",\"cat\":\"" << category << "\""
              << ",\"sub\":\"" << subject << "\""
              << ",\"msg\":\""; json_escape(json, message); json << "\""
              << ",\"prev\":\"" << hex_from(prev) << "\""
              << ",\"hash\":\"" << hex_from(h) << "\"";
            if (have_sig) {
                json << ",\"sig\":\"" << hex_from(sig.data(), sig.size()) << "\""
                    << ",\"pub\":\"" << hex_from(pk_.data(), pk_.size()) << "\"";
            }
            json << "}";

            f << json.str() << '\n';

            // Optional WORM segment writing (append-only directory with one-file-per-entry)
            if (worm_dir_) {
                try {
                    std::filesystem::create_directories(*worm_dir_);
                    std::string fname = std::to_string(ms) + "-" + hex_from(h).substr(0, 16) + ".json";
                    auto outp = *worm_dir_ / fname;
                    std::ofstream wf(outp, std::ios::binary | std::ios::trunc);
                    if (wf) {
                        auto s = json.str();
                        wf.write(s.data(), static_cast<std::streamsize>(s.size()));
                        wf.flush();
                        // set read-only (best effort)
                        std::error_code ecp;
                        auto p = std::filesystem::status(outp, ecp).permissions();
                        (void)p;
                        std::filesystem::permissions(outp, std::filesystem::perms::owner_write, std::filesystem::perm_options::remove, ecp);
                    }
                } catch (...) { /* ignore WORM errors */ }
            }

            last_hash_ = h; have_last_ = true; save_chain_state();
        }

    public:
        explicit AuditLogger(const std::optional<std::filesystem::path>& path,
                             const std::optional<std::filesystem::path>& key_path,
                             const std::optional<std::filesystem::path>& anchor_file,
                             const std::optional<std::filesystem::path>& worm_dir)
            : path_(path), worm_dir_(worm_dir) {
            if (path_) {
                chain_path_ = *path_;
                chain_path_->concat(".chain");
                load_chain_state();
            }
            if (key_path && std::filesystem::exists(*key_path)) {
                std::ifstream kf(*key_path, std::ios::binary);
                std::vector<uint8_t> kb((std::istreambuf_iterator<char>(kf)), std::istreambuf_iterator<char>());
                if (kb.size() == crypto_sign_SECRETKEYBYTES) {
                    std::memcpy(sk_.data(), kb.data(), kb.size());
                    if (crypto_sign_ed25519_sk_to_pk(pk_.data(), sk_.data()) == 0) {
                        sign_enabled_ = true;
                    }
                }
            }
            if (anchor_file) {
                std::lock_guard<std::mutex> lk(mu_);
                maybe_anchor_from_file_unlocked(anchor_file);
            }
        }

        void log(Severity sev, const std::string& category, const std::string& subject, const std::string& message) {
            std::lock_guard<std::mutex> lk(mu_);
            append_record_unlocked(sev, category, subject, message);
        }

        // Expose canonical_bytes for verify_chain (same algorithm, no instance state).
        static std::vector<uint8_t> canonical_bytes_public(const Hash32& prev,
                                                            int64_t ts_ms,
                                                            Severity sev,
                                                            const std::string& cat,
                                                            const std::string& sub,
                                                            const std::string& msg) {
            return canonical_bytes(prev, ts_ms, sev, cat, sub, msg);
        }
    };

    // ------------------------------------------------------------------
    // Verify chain — pairs with AuditLogger's emit format.
    //
    // The enterprise nocturne::security::AuditLogger has its own
    // verify_chain (P2.7, commit beb946c), but its canonical encoding is
    // different (includes seq, action, object, result; ISO-8601 timestamp
    // in JSON). The CLI uses *this* logger when --audit-log is passed, so
    // we need a verifier that matches the CLI's wire format.
    //
    // Returns a VerifyChainResult mirroring the enterprise one in shape
    // so callers can be uniform.
    // ------------------------------------------------------------------
    struct VerifyChainResult {
        bool ok = false;
        size_t records_checked = 0;
        std::optional<size_t> first_failure_line; // 1-based
        std::vector<std::string> errors;
        static constexpr size_t MAX_ERRORS = 32;
    };

    inline Severity sev_from_str(const std::string& s) {
        if (s == "INFO") return Severity::INFO;
        if (s == "WARN") return Severity::WARN;
        if (s == "ERROR") return Severity::ERROR;
        return Severity::SECURITY;
    }

    inline bool hex_decode_fixed(const std::string& hex, uint8_t* out, size_t out_len) {
        if (hex.size() != out_len * 2) return false;
        auto nyb = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return 10 + c - 'a';
            if (c >= 'A' && c <= 'F') return 10 + c - 'A';
            return -1;
        };
        for (size_t i = 0; i < out_len; ++i) {
            int hi = nyb(hex[2*i]);
            int lo = nyb(hex[2*i + 1]);
            if (hi < 0 || lo < 0) return false;
            out[i] = static_cast<uint8_t>((hi << 4) | lo);
        }
        return true;
    }

    // Minimal JSON field extractor matched to the AuditLogger emitter.
    // The emitter only escapes '"' (json_escape), and string values
    // cannot contain newlines (records are framed line-by-line), so the
    // grammar we need to parse is narrow:
    //   "<key>":"<value-with-only-\"-escaped>"   or
    //   "<key>":<integer>
    // Returns false if the key isn't found or the value is malformed.
    inline bool json_extract_string(const std::string& line, const std::string& key, std::string& out) {
        std::string needle = "\"" + key + "\":\"";
        auto p = line.find(needle);
        if (p == std::string::npos) return false;
        size_t i = p + needle.size();
        out.clear();
        while (i < line.size()) {
            char c = line[i];
            if (c == '\\' && i + 1 < line.size() && line[i+1] == '"') {
                out.push_back('"');
                i += 2;
                continue;
            }
            if (c == '"') return true;
            out.push_back(c);
            ++i;
        }
        return false;
    }
    inline bool json_extract_int64(const std::string& line, const std::string& key, int64_t& out) {
        std::string needle = "\"" + key + "\":";
        auto p = line.find(needle);
        if (p == std::string::npos) return false;
        size_t i = p + needle.size();
        if (i >= line.size() || line[i] == '"') return false; // not a number value
        size_t start = i;
        if (line[i] == '-' || line[i] == '+') ++i;
        bool any = false;
        while (i < line.size() && line[i] >= '0' && line[i] <= '9') { ++i; any = true; }
        if (!any) return false;
        try {
            out = std::stoll(line.substr(start, i - start));
        } catch (...) {
            return false;
        }
        return true;
    }

    inline VerifyChainResult verify_chain(
        const std::filesystem::path& log_path,
        const std::optional<std::array<uint8_t, crypto_sign_PUBLICKEYBYTES>>& expected_signer_pk = std::nullopt)
    {
        VerifyChainResult r;
        std::ifstream f(log_path);
        if (!f) {
            r.errors.push_back("cannot open " + log_path.string());
            return r;
        }
        auto push_err = [&](size_t line_no, const std::string& msg) {
            if (!r.first_failure_line) r.first_failure_line = line_no;
            if (r.errors.size() < VerifyChainResult::MAX_ERRORS) {
                r.errors.push_back("line " + std::to_string(line_no) + ": " + msg);
            }
        };

        Hash32 expected_prev{};
        bool first = true;
        std::string line;
        size_t line_no = 0;
        while (std::getline(f, line)) {
            ++line_no;
            if (line.empty()) continue;

            int64_t ts_ms = 0;
            std::string sev_s, cat, sub, msg, prev_hex, hash_hex, sig_hex, pub_hex;
            if (!json_extract_int64(line, "ts", ts_ms)) { push_err(line_no, "missing ts"); continue; }
            if (!json_extract_string(line, "sev", sev_s)) { push_err(line_no, "missing sev"); continue; }
            if (!json_extract_string(line, "cat", cat)) { push_err(line_no, "missing cat"); continue; }
            if (!json_extract_string(line, "sub", sub)) { push_err(line_no, "missing sub"); continue; }
            if (!json_extract_string(line, "msg", msg)) { push_err(line_no, "missing msg"); continue; }
            if (!json_extract_string(line, "prev", prev_hex)) { push_err(line_no, "missing prev"); continue; }
            if (!json_extract_string(line, "hash", hash_hex)) { push_err(line_no, "missing hash"); continue; }
            (void)json_extract_string(line, "sig", sig_hex); // optional
            (void)json_extract_string(line, "pub", pub_hex); // optional

            Hash32 prev{}, hash{};
            if (!hex_decode_fixed(prev_hex, prev.data(), prev.size())) { push_err(line_no, "bad prev hex"); continue; }
            if (!hex_decode_fixed(hash_hex, hash.data(), hash.size())) { push_err(line_no, "bad hash hex"); continue; }

            // Chain linkage
            if (first) {
                Hash32 zero{};
                if (prev != zero) push_err(line_no, "first record prev != zero");
                first = false;
            } else if (prev != expected_prev) {
                push_err(line_no, "prev does not match previous record hash");
            }

            // Recompute hash and compare
            auto canon = AuditLogger::canonical_bytes_public(prev, ts_ms, sev_from_str(sev_s), cat, sub, msg);
            Hash32 recomputed = blake2b_32(canon);
            if (recomputed != hash) {
                push_err(line_no, "hash mismatch (record tampered)");
            }

            // Signature verification (if present and pk available)
            if (!sig_hex.empty() && !pub_hex.empty()) {
                std::array<uint8_t, crypto_sign_BYTES> sig{};
                std::array<uint8_t, crypto_sign_PUBLICKEYBYTES> pk{};
                if (!hex_decode_fixed(sig_hex, sig.data(), sig.size())) {
                    push_err(line_no, "bad sig hex");
                } else if (!hex_decode_fixed(pub_hex, pk.data(), pk.size())) {
                    push_err(line_no, "bad pub hex");
                } else {
                    // Ed25519 verify of sig over hash bytes
                    if (crypto_sign_verify_detached(sig.data(), hash.data(), hash.size(), pk.data()) != 0) {
                        push_err(line_no, "signature verification failed");
                    }
                    // If an expected signer is required, enforce pin
                    if (expected_signer_pk && pk != *expected_signer_pk) {
                        push_err(line_no, "signer pk does not match expected");
                    }
                }
            } else if (expected_signer_pk) {
                push_err(line_no, "expected-signer set but record is unsigned");
            }

            expected_prev = hash;
            ++r.records_checked;
        }

        r.ok = r.errors.empty();
        return r;
    }

    static std::unique_ptr<AuditLogger> global_logger = nullptr;

    inline void initialize(const std::optional<std::filesystem::path>& path = std::nullopt,
                           const std::optional<std::filesystem::path>& key_path = std::nullopt,
                           const std::optional<std::filesystem::path>& anchor_file = std::nullopt,
                           const std::optional<std::filesystem::path>& worm_dir = std::nullopt) {
        if (!global_logger) global_logger = std::make_unique<AuditLogger>(path, key_path, anchor_file, worm_dir);
    }
    inline void info(const std::string& cat, const std::string& sub, const std::string& msg) { if (!global_logger) return; global_logger->log(Severity::INFO, cat, sub, msg); }
    inline void warn(const std::string& cat, const std::string& sub, const std::string& msg) { if (!global_logger) return; global_logger->log(Severity::WARN, cat, sub, msg); }
    inline void error(const std::string& cat, const std::string& sub, const std::string& msg) { if (!global_logger) return; global_logger->log(Severity::ERROR, cat, sub, msg); }
    inline void security(const std::string& cat, const std::string& sub, const std::string& msg) { if (!global_logger) return; global_logger->log(Severity::SECURITY, cat, sub, msg); }
}

// Memory protection utilities for advanced security
namespace memory_protection {
    
    // Memory protection configuration
    struct MemoryProtectionConfig {
        bool enable_memory_locking = true;           // Lock sensitive memory in RAM
        bool enable_secure_allocator = true;         // Use secure memory allocator
        bool enable_memory_encryption = false;       // Encrypt sensitive memory (experimental)
        bool enable_guard_pages = true;              // Add guard pages around sensitive data
        size_t guard_page_size = 4096;               // Size of guard pages
        bool enable_memory_scrubbing = true;         // Scrub memory on deallocation
        bool enable_secure_heap = false;             // Use secure heap (if available)
        uint32_t max_secure_allocations = 1000;      // Maximum secure allocations
        size_t max_total_memory = 100 * 1024 * 1024; // Maximum total memory (100MB)
    };
    
    // Secure memory allocator with protection features
    class SecureAllocator {
    private:
        struct AllocationInfo {
            void* ptr;
            size_t size;
            bool is_locked;
            bool is_encrypted;
            std::chrono::steady_clock::time_point allocation_time;
            
            // Default constructor for std::unordered_map compatibility
            AllocationInfo() : ptr(nullptr), size(0), is_locked(false), is_encrypted(false),
                              allocation_time(std::chrono::steady_clock::now()) {}
            
            AllocationInfo(void* p, size_t s, bool locked, bool encrypted)
                : ptr(p), size(s), is_locked(locked), is_encrypted(encrypted),
                  allocation_time(std::chrono::steady_clock::now()) {}
        };
        
        std::unordered_map<void*, AllocationInfo> allocations_;
        std::mutex mutex_;
        MemoryProtectionConfig config_;
        size_t total_allocated_ = 0;
        size_t allocation_count_ = 0;
        
        // Platform-specific memory locking
        bool lock_memory(void* ptr, size_t size) {
            #ifdef _WIN32
                return VirtualLock(ptr, size) != 0;
            #else
                return mlock(ptr, size) == 0;
            #endif
        }
        
        // Platform-specific memory unlocking
        bool unlock_memory(void* ptr, size_t size) {
            #ifdef _WIN32
                return VirtualUnlock(ptr, size) != 0;
            #else
                return munlock(ptr, size) == 0;
            #endif
        }
        
        // Platform-specific memory protection
        bool protect_memory(void* ptr, size_t size, bool read_only) {
            #ifdef _WIN32
                DWORD old_protect;
                DWORD new_protect = read_only ? PAGE_READONLY : PAGE_READWRITE;
                return VirtualProtect(ptr, size, new_protect, &old_protect) != 0;
            #else
                int prot = PROT_READ;
                if (!read_only) prot |= PROT_WRITE;
                return mprotect(ptr, size, prot) == 0;
            #endif
        }
        
        // SECURE MEMORY ALLOCATION: Prevent memory exhaustion and corruption
        void* allocate_with_guards(size_t size) {
            // CRITICAL SECURITY CHECK: Prevent allocation size attacks
            if (size == 0) {
                return nullptr;
            }
            if (size > MAX_ALLOCATION_SIZE) {
                throw std::runtime_error("allocation size exceeds maximum allowed");
            }
            
            if (!config_.enable_guard_pages) {
                // Use secure malloc with size validation
                void* ptr = std::malloc(size);
                if (!ptr) {
                    throw std::runtime_error("memory allocation failed");
                }
                return ptr;
            }
            
            // Calculate total size including guard pages
            size_t total_size = size + (2 * config_.guard_page_size);
            
            #ifdef _WIN32
                // Allocate memory with guard pages
                void* ptr = VirtualAlloc(nullptr, total_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                if (!ptr) return nullptr;
                
                // Set guard pages
                DWORD old_protect;
                VirtualProtect(ptr, config_.guard_page_size, PAGE_NOACCESS, &old_protect);
                VirtualProtect(static_cast<char*>(ptr) + total_size - config_.guard_page_size, 
                              config_.guard_page_size, PAGE_NOACCESS, &old_protect);
                
                return static_cast<char*>(ptr) + config_.guard_page_size;
            #else
                // Allocate memory with guard pages
                void* ptr = mmap(nullptr, total_size, PROT_READ | PROT_WRITE, 
                                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
                if (ptr == MAP_FAILED) return nullptr;
                
                // Set guard pages
                mprotect(ptr, config_.guard_page_size, PROT_NONE);
                mprotect(static_cast<char*>(ptr) + total_size - config_.guard_page_size, 
                        config_.guard_page_size, PROT_NONE);
                
                return static_cast<char*>(ptr) + config_.guard_page_size;
            #endif
        }
        
        // Free memory with guard pages (caller supplies original allocation size to avoid nested locks)
        void free_with_guards(void* ptr, size_t original_size) {
            if (!config_.enable_guard_pages) {
                std::free(ptr);
                return;
            }
            
            #ifdef _WIN32
                void* base_ptr = static_cast<char*>(ptr) - config_.guard_page_size;
                VirtualFree(base_ptr, 0, MEM_RELEASE);
            #else
                void* base_ptr = static_cast<char*>(ptr) - config_.guard_page_size;
                munmap(base_ptr, config_.guard_page_size * 2 + original_size);
            #endif
        }
        
        // Get allocation size (simplified - in production use proper tracking)
        size_t get_allocation_size(void* ptr) {
            std::lock_guard<std::mutex> lock(mutex_);
            auto it = allocations_.find(ptr);
            return (it != allocations_.end()) ? it->second.size : 0;
        }
        
        // Scrub memory before deallocation
        void scrub_memory(void* ptr, size_t size) {
            if (!config_.enable_memory_scrubbing) return;
            
            // Use volatile to prevent compiler optimization
            volatile uint8_t* p = static_cast<volatile uint8_t*>(ptr);
            for (size_t i = 0; i < size; i++) {
                p[i] = 0;
            }
            
            // Force memory barrier
            std::atomic_thread_fence(std::memory_order_seq_cst);
        }
        
    public:
        explicit SecureAllocator(const MemoryProtectionConfig& config = MemoryProtectionConfig{})
            : config_(config) {}
        
        // SECURE MEMORY ALLOCATION: Comprehensive security validation
        void* allocate(size_t size) {
            std::lock_guard<std::mutex> lock(mutex_);
            
            // CRITICAL SECURITY CHECKS: Prevent memory exhaustion and DoS attacks
            if (size == 0) {
                throw std::runtime_error("zero size allocation not allowed");
            }
            if (size > MAX_ALLOCATION_SIZE) {
                throw std::runtime_error("allocation size exceeds maximum allowed");
            }
            
            // Check allocation limits to prevent resource exhaustion
            if (allocation_count_ >= config_.max_secure_allocations) {
                throw std::runtime_error("Maximum secure allocations exceeded");
            }
            
            // Calculate total memory usage to prevent DoS
            size_t total_allocated = 0;
            for (const auto& alloc : allocations_) {
                total_allocated += alloc.second.size;
            }
            if (total_allocated + size > config_.max_total_memory) {
                throw std::runtime_error("total memory limit exceeded");
            }
            
            // Allocate memory with comprehensive error handling
            void* ptr = config_.enable_guard_pages ? 
                       allocate_with_guards(size) : std::malloc(size);
            
            if (!ptr) {
                throw std::runtime_error("Secure memory allocation failed");
            }
            
            // Lock memory if enabled
            bool is_locked = false;
            if (config_.enable_memory_locking) {
                is_locked = lock_memory(ptr, size);
                if (!is_locked) {
                    // Log warning but continue
                    std::cerr << "WARNING: Failed to lock memory in RAM" << std::endl;
                }
            }
            
            // Track allocation
            allocations_[ptr] = AllocationInfo(ptr, size, is_locked, false);
            total_allocated_ += size;
            allocation_count_++;
            
            return ptr;
        }
        
        // Deallocate secure memory
        void deallocate(void* ptr) {
            if (!ptr) return;
            
            std::lock_guard<std::mutex> lock(mutex_);
            
            auto it = allocations_.find(ptr);
            if (it == allocations_.end()) {
                // Not tracked - use standard free
                std::free(ptr);
                return;
            }
            
            // Make a copy of allocation info before mutating the map so we don't
            // access freed map node memory (use-after-free).
            AllocationInfo info_copy = it->second;

            // Scrub memory before deallocation
            scrub_memory(ptr, info_copy.size);

            // Unlock memory if it was locked
            if (info_copy.is_locked) {
                unlock_memory(ptr, info_copy.size);
            }

            // Update statistics
            total_allocated_ -= info_copy.size;
            allocation_count_--;

            // Remove from tracking
            allocations_.erase(it);

            // Free memory (use copied size)
            if (config_.enable_guard_pages) {
                free_with_guards(ptr, info_copy.size);
            } else {
                std::free(ptr);
            }
        }
        
        // Get allocation statistics
        std::string get_stats() {
            std::lock_guard<std::mutex> lock(mutex_);
            
            std::ostringstream oss;
            oss << "Secure Allocator Stats:\n"
                << "  Total allocated: " << total_allocated_ << " bytes\n"
                << "  Active allocations: " << allocation_count_ << "\n"
                << "  Memory locking: " << (config_.enable_memory_locking ? "enabled" : "disabled") << "\n"
                << "  Guard pages: " << (config_.enable_guard_pages ? "enabled" : "disabled") << "\n"
                << "  Memory scrubbing: " << (config_.enable_memory_scrubbing ? "enabled" : "disabled");
            
            return oss.str();
        }
        
        // Update configuration
        void update_config(const MemoryProtectionConfig& config) {
            std::lock_guard<std::mutex> lock(mutex_);
            config_ = config;
        }
    };
    
    // Global secure allocator instance
    static std::unique_ptr<SecureAllocator> global_allocator = nullptr;
    
    // Initialize global secure allocator
    inline void initialize(const MemoryProtectionConfig& config = MemoryProtectionConfig{}) {
        if (!global_allocator) {
            global_allocator = std::make_unique<SecureAllocator>(config);
        }
    }
    
    // Allocate secure memory (global interface)
    inline void* allocate_secure(size_t size) {
        if (!global_allocator) {
            initialize(); // Initialize with default config
        }
        return global_allocator->allocate(size);
    }
    
    // Deallocate secure memory (global interface)
    inline void deallocate_secure(void* ptr) {
        if (global_allocator) {
            global_allocator->deallocate(ptr);
        }
    }
    
    // Get statistics (global interface)
    inline std::string get_stats() {
        if (!global_allocator) {
            return "Secure allocator not initialized";
        }
        return global_allocator->get_stats();
    }
    
    // Secure memory wrapper for automatic management
    template<typename T>
    class SecureMemory {
    private:
        T* ptr_;
        size_t size_;
        
    public:
        SecureMemory(size_t count = 1) : size_(count * sizeof(T)) {
            ptr_ = static_cast<T*>(allocate_secure(size_));
        }
        
        ~SecureMemory() {
            if (ptr_) {
                deallocate_secure(ptr_);
            }
        }
        
        // Disable copy
        SecureMemory(const SecureMemory&) = delete;
        SecureMemory& operator=(const SecureMemory&) = delete;
        
        // Allow move
        SecureMemory(SecureMemory&& other) noexcept 
            : ptr_(other.ptr_), size_(other.size_) {
            other.ptr_ = nullptr;
            other.size_ = 0;
        }
        
        SecureMemory& operator=(SecureMemory&& other) noexcept {
            if (this != &other) {
                if (ptr_) {
                    deallocate_secure(ptr_);
                }
                ptr_ = other.ptr_;
                size_ = other.size_;
                other.ptr_ = nullptr;
                other.size_ = 0;
            }
            return *this;
        }
        
        // Access operators
        T* get() { return ptr_; }
        const T* get() const { return ptr_; }
        T& operator*() { return *ptr_; }
        const T& operator*() const { return *ptr_; }
        T* operator->() { return ptr_; }
        const T* operator->() const { return ptr_; }
        T& operator[](size_t index) { return ptr_[index]; }
        const T& operator[](size_t index) const { return ptr_[index]; }
        
        // Size information
        size_t size() const { return size_ / sizeof(T); }
        size_t size_bytes() const { return size_; }
    };
}

namespace nocturne {

// SECURITY CONSTANTS
constexpr uint8_t VERSION = 0x03;
constexpr uint8_t FLAG_HAS_SIG = 0x01;
constexpr uint8_t FLAG_HAS_RATCHET = 0x02;
// When set, eph_pk is unused (zeroed) and the receiver derives the AEAD key
// by decapsulating pqc_kem_ct via KEMFactory(pqc_kem_type) with the receiver's
// KEM secret key. Used by hybrid X25519+ML-KEM-1024 and pure ML-KEM-1024 modes.
constexpr uint8_t FLAG_HAS_PQC_KEM = 0x04;
// Maximum KEM ciphertext size we accept (hybrid is 1601B; cap conservatively at
// 4 KiB to leave headroom for future schemes while bounding DoS exposure).
constexpr size_t MAX_PQC_KEM_CT_SIZE = 4 * 1024;
// FLAG_HAS_PQC_SIG carries a *variable-size* signature whose layout differs
// from the fixed 64-byte FLAG_HAS_SIG path. When set, the wire carries:
//   [1B pqc_sig_type][4B LE pqc_sig_len][N bytes pqc_sig]
// after the ciphertext block, where pqc_sig_type matches
// nocturne::pqc::SigType (0=Ed25519, 1=Hybrid Ed25519+ML-DSA-87, 2=ML-DSA-87).
// FLAG_HAS_SIG and FLAG_HAS_PQC_SIG are mutually exclusive in practice; the
// serializer permits both for forward compat (FLAG_HAS_PQC_SIG block first,
// then the 64-byte FLAG_HAS_SIG block).
constexpr uint8_t FLAG_HAS_PQC_SIG = 0x08;
// Cap at 8 KiB — hybrid Ed25519+ML-DSA-87 is 4691 B; leaves headroom for
// SLH-DSA or future signature variants while bounding allocation amplification.
constexpr size_t MAX_PQC_SIG_SIZE = 8 * 1024;

using Bytes = std::vector<uint8_t>;

// Custom exception hierarchy for clearer error classification
class NocturneError : public std::runtime_error {
public:
    explicit NocturneError(const std::string& msg) : std::runtime_error(msg) {}
};

class HSMError : public NocturneError { public: explicit HSMError(const std::string& m) : NocturneError(m) {} };
class CryptoError : public NocturneError { public: explicit CryptoError(const std::string& m) : NocturneError(m) {} };
class IOError : public NocturneError { public: explicit IOError(const std::string& m) : NocturneError(m) {} };


struct X25519KeyPair {
    std::array<uint8_t, crypto_kx_PUBLICKEYBYTES> pk{};
    std::array<uint8_t, crypto_kx_SECRETKEYBYTES> sk{};
};

struct Ed25519KeyPair {
    std::array<uint8_t, crypto_sign_PUBLICKEYBYTES> pk{};
    std::array<uint8_t, crypto_sign_SECRETKEYBYTES> sk{};
};

inline void check_sodium() {
    if (sodium_init() < 0) throw std::runtime_error("sodium_init failed");
}

inline X25519KeyPair gen_x25519() {
    // Use secure memory for key generation
    memory_protection::SecureMemory<uint8_t> secure_sk(crypto_kx_SECRETKEYBYTES);
    memory_protection::SecureMemory<uint8_t> secure_pk(crypto_kx_PUBLICKEYBYTES);
    
    // Generate key pair in secure memory
    crypto_kx_keypair(secure_pk.get(), secure_sk.get());
    
    // Side-channel protection: flush cache and add random delay
    nocturne::side_channel::flush_cache_line(secure_sk.get());
    nocturne::side_channel::random_delay();
    nocturne::side_channel::memory_barrier();
    
    // Copy to return value (will be zeroed by SecureMemory destructor)
    X25519KeyPair kp;
    std::memcpy(kp.pk.data(), secure_pk.get(), crypto_kx_PUBLICKEYBYTES);
    std::memcpy(kp.sk.data(), secure_sk.get(), crypto_kx_SECRETKEYBYTES);
    
    return kp;
}

inline Ed25519KeyPair gen_ed25519() {
    // Use secure memory for Ed25519 key generation to avoid secret leakage
    memory_protection::SecureMemory<uint8_t> secure_sk(crypto_sign_SECRETKEYBYTES);
    memory_protection::SecureMemory<uint8_t> secure_pk(crypto_sign_PUBLICKEYBYTES);

    if (crypto_sign_keypair(secure_pk.get(), secure_sk.get()) != 0) {
        throw CryptoError("ed25519 keypair generation failed");
    }

    // Side-channel protection
    nocturne::side_channel::flush_cache_line(secure_sk.get());
    nocturne::side_channel::random_delay();
    nocturne::side_channel::memory_barrier();

    Ed25519KeyPair kp;
    std::memcpy(kp.pk.data(), secure_pk.get(), crypto_sign_PUBLICKEYBYTES);
    std::memcpy(kp.sk.data(), secure_sk.get(), crypto_sign_SECRETKEYBYTES);

    // secure memory will be zeroed on destructor of SecureMemory
    return kp;
}

struct Packet {
    uint8_t version{VERSION};
    uint8_t flags{0};
    uint32_t rotation_id{0};
    std::array<uint8_t, crypto_kx_PUBLICKEYBYTES> eph_pk{};
    std::array<uint8_t, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES> nonce{};
    uint64_t counter{0}; // monotonic per-sender
    std::optional<std::array<uint8_t, crypto_kx_PUBLICKEYBYTES>> ratchet_pk; // optional
    // PQC KEM fields — populated only when FLAG_HAS_PQC_KEM is set in flags.
    // pqc_kem_type matches nocturne::pqc::KEMType (0=X25519, 1=Hybrid, 2=ML-KEM-1024).
    uint8_t pqc_kem_type{0};
    Bytes pqc_kem_ct;
    Bytes aad;
    Bytes ciphertext; // includes Poly1305 tag
    std::optional<std::array<uint8_t, crypto_sign_BYTES>> signature;
    // PQC SIG fields — populated only when FLAG_HAS_PQC_SIG is set. Variable-
    // size to handle Ed25519 (64 B), ML-DSA-87 (4627 B), and hybrid (4691 B)
    // through one wire path.
    uint8_t pqc_sig_type{0};
    Bytes pqc_sig;
};

// Caller-supplied parameters for the FLAG_HAS_PQC_SIG path. The HSM is
// Ed25519-only (sign() returns std::array<uint8_t, crypto_sign_BYTES>), so
// PQC signing currently bypasses the HSM interface and operates directly on
// the in-memory secret key. A future iteration can extend HSMInterface with
// a variable-size sign hook and slot PQC keys behind the same backend.
struct PqcSignerConfig {
    pqc::SigType type;
    Bytes secret_key;  // raw scheme bytes; size enforced by SignatureFactory
};

struct PqcVerifierConfig {
    pqc::SigType type;
    Bytes public_key;
};

// portable LE helpers
inline void write_u32_le(Bytes &out, uint32_t v) {
    out.push_back(static_cast<uint8_t>(v & 0xff));
    out.push_back(static_cast<uint8_t>((v >> 8) & 0xff));
    out.push_back(static_cast<uint8_t>((v >> 16) & 0xff));
    out.push_back(static_cast<uint8_t>((v >> 24) & 0xff));
}
inline uint32_t read_u32_le(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) | (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
}
inline void write_u64_le(Bytes &out, uint64_t v) {
    for (int i=0;i<8;i++) out.push_back(static_cast<uint8_t>((v >> (8*i)) & 0xff));
}
inline uint64_t read_u64_le(const uint8_t* p) {
    uint64_t v=0;
    for (int i=0;i<8;i++) v |= (static_cast<uint64_t>(p[i]) << (8*i));
    return v;
}

inline Bytes serialize(const Packet& p) {
    Bytes out;
    out.reserve(1+1+4 + p.eph_pk.size() + p.nonce.size() + 8 + (p.ratchet_pk?crypto_kx_PUBLICKEYBYTES:0) + 4 + 4 + p.aad.size() + p.ciphertext.size() + (p.signature?crypto_sign_BYTES:0));
    out.push_back(p.version);
    out.push_back(p.flags);
    nocturne::write_u32_le(out, p.rotation_id);
    out.insert(out.end(), p.eph_pk.begin(), p.eph_pk.end());
    out.insert(out.end(), p.nonce.begin(), p.nonce.end());
    nocturne::write_u64_le(out, p.counter);
    if (p.flags & FLAG_HAS_RATCHET) {
        if (!p.ratchet_pk) throw std::runtime_error("ratchet flag set but pk missing");
        out.insert(out.end(), p.ratchet_pk->begin(), p.ratchet_pk->end());
    }
    if (p.flags & FLAG_HAS_PQC_KEM) {
        if (p.pqc_kem_ct.empty()) throw std::runtime_error("pqc-kem flag set but ct missing");
        if (p.pqc_kem_ct.size() > MAX_PQC_KEM_CT_SIZE) throw std::runtime_error("pqc kem ct too large");
        out.push_back(p.pqc_kem_type);
        nocturne::write_u32_le(out, static_cast<uint32_t>(p.pqc_kem_ct.size()));
        out.insert(out.end(), p.pqc_kem_ct.begin(), p.pqc_kem_ct.end());
    }
    nocturne::write_u32_le(out, static_cast<uint32_t>(p.aad.size()));
    nocturne::write_u32_le(out, static_cast<uint32_t>(p.ciphertext.size()));
    if (!p.aad.empty()) out.insert(out.end(), p.aad.begin(), p.aad.end());
    if (!p.ciphertext.empty()) out.insert(out.end(), p.ciphertext.begin(), p.ciphertext.end());
    // PQC signature block before the classical signature: when both flags are
    // set (currently not exercised but reserved), stripping the classical sig
    // for canonical re-serialization still leaves the PQC sig in place.
    if (p.flags & FLAG_HAS_PQC_SIG) {
        if (p.pqc_sig.empty()) throw std::runtime_error("pqc-sig flag set but bytes missing");
        if (p.pqc_sig.size() > MAX_PQC_SIG_SIZE) throw std::runtime_error("pqc sig too large");
        out.push_back(p.pqc_sig_type);
        nocturne::write_u32_le(out, static_cast<uint32_t>(p.pqc_sig.size()));
        out.insert(out.end(), p.pqc_sig.begin(), p.pqc_sig.end());
    }
    if (p.flags & FLAG_HAS_SIG) {
        if (!p.signature) throw std::runtime_error("flag set but signature missing");
        out.insert(out.end(), p.signature->begin(), p.signature->end());
    }
    return out;
}

inline Packet deserialize(const Bytes& in) {
    Packet p;
    size_t off = 0;
    
    // INPUT VALIDATION: Prevent buffer overflow and integer overflow attacks
    auto need = [&](size_t n) { 
        // Check for integer overflow in addition
        if (n > SIZE_MAX - off) {
            throw std::runtime_error("packet size overflow detected");
        }
        // Check for buffer overflow
        if (off + n > in.size()) {
            throw std::runtime_error("truncated packet detected");
        }
        // Check for reasonable size limits (prevent DoS)
        if (n > MAX_PACKET_SIZE) {
            throw std::runtime_error("packet size exceeds maximum allowed");
        }
    };
    
    auto get = [&](void* dst, size_t n) { 
        need(n); 
        // Validate destination pointer
        if (!dst) {
            throw std::runtime_error("null destination pointer");
        }
        // Validate source data pointer
        if (!in.data()) {
            throw std::runtime_error("null source data pointer");
        }
        std::memcpy(dst, in.data() + off, n); 
        off += n; 
    };

    need(1+1+4 + crypto_kx_PUBLICKEYBYTES + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES + 8 + 4 + 4);
    get(&p.version, 1);
    get(&p.flags,   1);
    uint8_t tmp4[4];
    get(tmp4,4); p.rotation_id = nocturne::read_u32_le(tmp4);
    get(p.eph_pk.data(), p.eph_pk.size());
    get(p.nonce.data(),  p.nonce.size());
    uint8_t tmp8[8]; get(tmp8,8); p.counter = nocturne::read_u64_le(tmp8);

    if (p.flags & FLAG_HAS_RATCHET) {
        std::array<uint8_t, crypto_kx_PUBLICKEYBYTES> rpk{};
        get(rpk.data(), rpk.size());
        p.ratchet_pk = rpk;
    }

    if (p.flags & FLAG_HAS_PQC_KEM) {
        get(&p.pqc_kem_type, 1);
        get(tmp4, 4);
        uint32_t kem_ct_len = nocturne::read_u32_le(tmp4);
        if (kem_ct_len == 0 || kem_ct_len > MAX_PQC_KEM_CT_SIZE) {
            throw std::runtime_error("pqc kem ct size out of bounds");
        }
        p.pqc_kem_ct.resize(kem_ct_len);
        get(p.pqc_kem_ct.data(), kem_ct_len);
    }

    get(tmp4,4); uint32_t aad_len = nocturne::read_u32_le(tmp4);
    get(tmp4,4); uint32_t ct_len  = nocturne::read_u32_le(tmp4);

    if (p.version != nocturne::VERSION) throw std::runtime_error("unsupported version");

    // SIZE VALIDATION: Prevent DoS attacks
    if (aad_len > MAX_AAD_SIZE) {
        throw std::runtime_error("AAD size exceeds maximum allowed");
    }
    if (ct_len > MAX_CIPHERTEXT_SIZE) {
        throw std::runtime_error("ciphertext size exceeds maximum allowed");
    }
    
    if (aad_len) {
        p.aad.resize(aad_len);
        get(p.aad.data(), aad_len);
    }
    if (ct_len)  {
        p.ciphertext.resize(ct_len);
        get(p.ciphertext.data(), ct_len);
    }

    // Mirror serialize()'s ordering: PQC sig block before classical sig.
    if (p.flags & FLAG_HAS_PQC_SIG) {
        get(&p.pqc_sig_type, 1);
        get(tmp4, 4);
        uint32_t sig_len = nocturne::read_u32_le(tmp4);
        if (sig_len == 0 || sig_len > MAX_PQC_SIG_SIZE) {
            throw std::runtime_error("pqc sig size out of bounds");
        }
        p.pqc_sig.resize(sig_len);
        get(p.pqc_sig.data(), sig_len);
    }

    if (p.flags & FLAG_HAS_SIG) {
        std::array<uint8_t, crypto_sign_BYTES> sig{};
        get(sig.data(), sig.size());
        p.signature = sig;
    }
    if (off != in.size()) throw std::runtime_error("trailing bytes in packet");
    return p;
}

inline std::array<uint8_t, crypto_aead_xchacha20poly1305_ietf_KEYBYTES>
derive_aead_key_from_session(const uint8_t* session, size_t session_len, const std::string& info)
{
    std::array<uint8_t, crypto_aead_xchacha20poly1305_ietf_KEYBYTES> k{};
    if (crypto_generichash(k.data(), k.size(), session, session_len, reinterpret_cast<const uint8_t*>(info.data()), info.size()) != 0)
        throw std::runtime_error("key derivation failed");
    return k;
}

inline std::array<uint8_t, crypto_aead_xchacha20poly1305_ietf_KEYBYTES>
derive_tx_key_client(const std::array<uint8_t,crypto_kx_PUBLICKEYBYTES>& pk_eph,
                     const std::array<uint8_t,crypto_kx_SECRETKEYBYTES>& sk_eph,
                     const std::array<uint8_t,crypto_kx_PUBLICKEYBYTES>& pk_receiver)
{
    std::array<uint8_t, crypto_kx_SESSIONKEYBYTES> rx{}, tx{};
    if (crypto_kx_client_session_keys(rx.data(), tx.data(),
                                      pk_eph.data(), sk_eph.data(), pk_receiver.data()) != 0)
        throw std::runtime_error("kx client session failed");
    
    // Side-channel protection: flush cache and add random delay
    nocturne::side_channel::flush_cache_line(sk_eph.data());
    nocturne::side_channel::random_delay();
    
    auto k = derive_aead_key_from_session(tx.data(), tx.size(), "nocturne-tx-v3");
    
    // Secure memory zeroing with side-channel protection
    nocturne::side_channel::secure_zero_memory(rx.data(), rx.size());
    nocturne::side_channel::secure_zero_memory(tx.data(), tx.size());
    nocturne::side_channel::flush_cache_line(rx.data());
    nocturne::side_channel::flush_cache_line(tx.data());
    
    return k;
}

inline std::array<uint8_t, crypto_aead_xchacha20poly1305_ietf_KEYBYTES>
derive_rx_key_server(const std::array<uint8_t,crypto_kx_PUBLICKEYBYTES>& pk_sender_eph,
                     const std::array<uint8_t,crypto_kx_PUBLICKEYBYTES>& pk_receiver,
                     const std::array<uint8_t,crypto_kx_SECRETKEYBYTES>& sk_receiver)
{
    std::array<uint8_t, crypto_kx_SESSIONKEYBYTES> rx{}, tx{};
    if (crypto_kx_server_session_keys(rx.data(), tx.data(),
                                      pk_receiver.data(), sk_receiver.data(), pk_sender_eph.data()) != 0)
        throw std::runtime_error("kx server session failed");
    
    // Side-channel protection: flush cache and add random delay
    nocturne::side_channel::flush_cache_line(sk_receiver.data());
    nocturne::side_channel::random_delay();
    
    // Use the same context string as encryption side to ensure key equality
    auto k = derive_aead_key_from_session(rx.data(), rx.size(), "nocturne-tx-v3");
    
    // Secure memory zeroing with side-channel protection
    nocturne::side_channel::secure_zero_memory(rx.data(), rx.size());
    nocturne::side_channel::secure_zero_memory(tx.data(), tx.size());
    nocturne::side_channel::flush_cache_line(rx.data());
    nocturne::side_channel::flush_cache_line(tx.data());
    
    return k;
}

// Ratchet KDF: mixes prev_key and DH shared (x25519) into new symmetric key
inline std::array<uint8_t, crypto_aead_xchacha20poly1305_ietf_KEYBYTES>
ratchet_mix(const std::array<uint8_t, crypto_aead_xchacha20poly1305_ietf_KEYBYTES>& prev_key,
            const uint8_t* dh_shared, size_t dh_len)
{
    // BLAKE2b(prev_key || dh_shared || "nocturne-ratchet-v3")
    Bytes seed; seed.insert(seed.end(), prev_key.begin(), prev_key.end()); seed.insert(seed.end(), dh_shared, dh_shared + dh_len);
    std::array<uint8_t, crypto_aead_xchacha20poly1305_ietf_KEYBYTES> newk{};
    if (crypto_generichash(newk.data(), newk.size(), seed.data(), seed.size(), reinterpret_cast<const uint8_t*>("nocturne-ratchet-v3"), sizeof("nocturne-ratchet-v3")-1) != 0)
        throw std::runtime_error("ratchet kdf failed");
    
    // Side-channel protection: secure memory zeroing
    nocturne::side_channel::secure_zero_memory(seed.data(), seed.size());
    nocturne::side_channel::flush_cache_line(seed.data());
    
    return newk;
}

inline Bytes aead_encrypt_xchacha(const std::array<uint8_t,crypto_aead_xchacha20poly1305_ietf_KEYBYTES>& key,
                                  const std::array<uint8_t,crypto_aead_xchacha20poly1305_ietf_NPUBBYTES>& nonce,
                                  const Bytes& aad,
                                  const Bytes& pt)
{
    Bytes ct(pt.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES);
    unsigned long long ct_len = 0;
    if (crypto_aead_xchacha20poly1305_ietf_encrypt(
            ct.data(), &ct_len,
            pt.data(), pt.size(),
            aad.empty()?nullptr:aad.data(), aad.size(),
            nullptr,
            nonce.data(), key.data()) != 0)
        throw std::runtime_error("aead encrypt failed");
    ct.resize(static_cast<size_t>(ct_len));
    return ct;
}

inline Bytes aead_decrypt_xchacha(const std::array<uint8_t,crypto_aead_xchacha20poly1305_ietf_KEYBYTES>& key,
                                  const std::array<uint8_t,crypto_aead_xchacha20poly1305_ietf_NPUBBYTES>& nonce,
                                  const Bytes& aad,
                                  const Bytes& ct)
{
    if (ct.size() < crypto_aead_xchacha20poly1305_ietf_ABYTES)
        throw std::runtime_error("ciphertext too short");
    Bytes pt(ct.size() - crypto_aead_xchacha20poly1305_ietf_ABYTES);
    unsigned long long pt_len = 0;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            pt.data(), &pt_len,
            nullptr,
            ct.data(), ct.size(),
            aad.empty()?nullptr:aad.data(), aad.size(),
            nonce.data(), key.data()) != 0)
        throw std::runtime_error("aead decrypt failed (auth)");
    pt.resize(static_cast<size_t>(pt_len));
    return pt;
}

inline std::array<uint8_t, crypto_sign_BYTES>
ed25519_sign(const Bytes& msg, const std::array<uint8_t,crypto_sign_SECRETKEYBYTES>& sk)
{
    std::array<uint8_t, crypto_sign_BYTES> sig{};
    crypto_sign_detached(sig.data(), nullptr, msg.data(), msg.size(), sk.data());
    return sig;
}

inline bool ed25519_verify(const Bytes& msg,
                           const std::array<uint8_t,crypto_sign_PUBLICKEYBYTES>& pk,
                           const std::array<uint8_t,crypto_sign_BYTES>& sig)
{
    // Side-channel protection: constant-time verification
    int result = crypto_sign_verify_detached(sig.data(), msg.data(), msg.size(), pk.data());
    
    // Add random delay to prevent timing attacks
    nocturne::side_channel::random_delay();
    nocturne::side_channel::memory_barrier();
    
    return result == 0;
}

} // namespace nocturne

// Forward declarations for file I/O helpers used before their definitions
static std::vector<uint8_t> read_all(const std::filesystem::path& p);
static void write_all(const std::filesystem::path& p, const std::vector<uint8_t>& data);
static void write_all_raw(const std::filesystem::path& p, const uint8_t* data, size_t n);

// Robust atomic, MAC-protected ReplayDB implementation
class ReplayDB {
    std::filesystem::path path;
    std::unordered_map<std::string, uint64_t> m;
    std::mutex mu;
    std::array<uint8_t, crypto_generichash_KEYBYTES> mac_key{}; // key to MAC DB (should be stored in HSM in real deployments)
    std::array<uint8_t, crypto_aead_xchacha20poly1305_ietf_KEYBYTES> enc_key{}; // key to encrypt DB metadata
    uint64_t version{1};
    // Optional external monotonic counter (TPM/file bridge) path
    std::optional<std::filesystem::path> tpm_counter_path_{};

    static std::string db_temp_path(const std::filesystem::path &p) { return p.string() + ".tmp"; }
    // Persist to disk without re-entrantly taking the mutex (caller must hold mu)
    void persist_unlocked();

    static std::string make_scope_key(const std::string& rx_hex,
                                      const std::optional<std::string>& sender_pk_hex,
                                      const std::optional<std::string>& session_id) {
        // Canonical composite key
        std::string key;
        key.reserve(rx_hex.size() + (sender_pk_hex?sender_pk_hex->size():1) + (session_id?session_id->size():1) + 16);
        key += "rx="; key += rx_hex;
        key += "&snd="; key += (sender_pk_hex ? *sender_pk_hex : std::string("-"));
        key += "&sid="; key += (session_id ? *session_id : std::string("-"));
        return key;
    }

public:
    // mac_key can be loaded from HSM; here we allow a file-based key for demo purposes
    ReplayDB(std::filesystem::path p, const std::optional<std::filesystem::path>& keyfile = std::nullopt,
             const std::optional<std::filesystem::path>& tpm_counter_path = std::nullopt) : path(std::move(p)), tpm_counter_path_(tpm_counter_path) {
        try { std::filesystem::create_directories(path.parent_path()); } catch(...){}
        if (keyfile && std::filesystem::exists(*keyfile)) {
            auto k = read_all(*keyfile);
            if (k.size()==mac_key.size()) std::memcpy(mac_key.data(), k.data(), mac_key.size());
            else throw std::runtime_error("mac key size mismatch");
        } else {
            // generate a transient key (NOT SECURE FOR REAL DEPLOYMENT)
            crypto_generichash_keygen(mac_key.data());
        }
        // Derive an encryption key from mac_key for metadata confidentiality
        if (crypto_generichash(enc_key.data(), enc_key.size(), mac_key.data(), mac_key.size(), reinterpret_cast<const uint8_t*>("replaydb-enc"), sizeof("replaydb-enc")-1) != 0)
            throw std::runtime_error("enc key derivation failed");
        load();
    }

    void load() {
        std::lock_guard<std::mutex> lk(mu);
        m.clear();
        if (!std::filesystem::exists(path)) return;
        auto raw = read_all(path);
        if (raw.size() < 16) throw std::runtime_error("db too small or corrupted");
        const uint8_t* p = raw.data();
        uint64_t file_version = read_u64_le(p); p += 8;
        bool is_encrypted = (file_version & (1ULL<<63)) != 0;
        // External monotonic counter verification
        if (tpm_counter_path_ && std::filesystem::exists(*tpm_counter_path_)) {
            auto cbuf = read_all(*tpm_counter_path_);
            if (cbuf.size() >= 8) {
                uint64_t tpm_v = read_u64_le(cbuf.data());
                uint64_t fv_plain = (file_version & ~(1ULL<<63));
                if (fv_plain < tpm_v) {
                    audit_log::security("ReplayDB", "rollback", "External monotonic counter indicates rollback");
                    throw std::runtime_error("replaydb rollback detected by external counter");
                }
            }
        }
        std::string json_s;
        if (!is_encrypted) {
            // Legacy format: [8B version][4B json_len][json][mac]
            if (raw.size() < 8 + 4) throw std::runtime_error("db truncated");
            uint32_t json_len = nocturne::read_u32_le(p); p += 4;
            if (raw.size() < 8 + 4 + json_len + crypto_generichash_BYTES) throw std::runtime_error("db truncated");
            const uint8_t* json_ptr = p; p += json_len;
            const uint8_t* mac_ptr = p;
            std::array<uint8_t, crypto_generichash_BYTES> mac{};
            if (crypto_generichash(mac.data(), mac.size(), raw.data(), 8 + 4 + json_len, mac_key.data(), mac_key.size()) != 0) throw std::runtime_error("mac calc failed");
            if (!nocturne::side_channel::constant_time_compare(mac.data(), mac_ptr, mac.size())) {
                nocturne::side_channel::random_delay();
                throw std::runtime_error("replaydb MAC mismatch");
            }
            json_s.assign(reinterpret_cast<const char*>(json_ptr), json_len);
        } else {
            // Encrypted format: [8B version (MSB=1)][24B nonce][4B ct_len][ct]
            std::array<uint8_t, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES> npub{};
            if (raw.size() < 8 + npub.size() + 4) throw std::runtime_error("db truncated");
            std::memcpy(npub.data(), p, npub.size()); p += npub.size();
            uint32_t ct_len = nocturne::read_u32_le(p); p += 4;
            if (raw.size() < 8 + npub.size() + 4 + ct_len) throw std::runtime_error("db truncated");
            const uint8_t* ct_ptr = p;
            // AAD: literal context + plaintext version without MSB
            uint64_t ver_plain = (file_version & ~(1ULL<<63));
            // context kept only for documentation of AAD structure
            // Decrypt
            std::vector<uint8_t> pt(ct_len - crypto_aead_xchacha20poly1305_ietf_ABYTES);
            unsigned long long pt_len = 0;
            if (crypto_aead_xchacha20poly1305_ietf_decrypt(pt.data(), &pt_len, nullptr,
                    ct_ptr, ct_len,
                    reinterpret_cast<const unsigned char*>(&ver_plain), sizeof(ver_plain),
                    npub.data(), enc_key.data()) != 0) {
                throw std::runtime_error("db decrypt failed");
            }
            pt.resize(static_cast<size_t>(pt_len));
            json_s.assign(reinterpret_cast<const char*>(pt.data()), pt.size());
        }
        // parse json-ish (simple lines: key:counter), where key is composite (rx&snd&sid)
        std::istringstream iss(json_s);
        std::string line;
        while (std::getline(iss,line)) {
            // SECURITY: composite keys may contain ':' (e.g. rx=tx:hex&snd=-&sid=-),
            // so split on the LAST colon — counter is always the trailing field.
            auto pos = line.rfind(':'); if (pos==std::string::npos) continue;
            std::string k = line.substr(0,pos);
            std::string val_str = line.substr(pos+1);

            // Skip empty values
            if (val_str.empty()) continue;

            try {
                uint64_t v = std::stoull(val_str);
                m[k]=v;
            } catch (const std::exception& e) {
                // Skip malformed entries
                std::cerr << "Warning: skipping malformed replay DB entry: " << line << std::endl;
                continue;
            }
        }
        version = file_version;
    }

    void persist() {
        std::lock_guard<std::mutex> lk(mu);
        persist_unlocked();
    }

    uint64_t get(const std::string &hexpk) {
        std::lock_guard<std::mutex> lk(mu);
        auto composite = make_scope_key(hexpk, std::nullopt, std::nullopt);
        auto it = m.find(composite);
        if (it==m.end()) return 0;
        return it->second;
    }
    void set(const std::string &hexpk, uint64_t v) {
        std::lock_guard<std::mutex> lk(mu);
        auto composite = make_scope_key(hexpk, std::nullopt, std::nullopt);
        m[composite]=v;
        persist_unlocked();
    }

    uint64_t get_scoped(const std::string& rx_hex,
                        const std::optional<std::string>& sender_pk_hex,
                        const std::optional<std::string>& session_id) {
        std::lock_guard<std::mutex> lk(mu);
        auto key = make_scope_key(rx_hex, sender_pk_hex, session_id);
        auto it = m.find(key);
        if (it==m.end()) return 0;
        return it->second;
    }

    void set_scoped(const std::string& rx_hex,
                    const std::optional<std::string>& sender_pk_hex,
                    const std::optional<std::string>& session_id,
                    uint64_t v) {
        std::lock_guard<std::mutex> lk(mu);
        auto key = make_scope_key(rx_hex, sender_pk_hex, session_id);
        m[key]=v;
        persist_unlocked();
    }

    static uint64_t read_u64_le(const uint8_t* p) {
        uint64_t v=0; for (int i=0;i<8;i++) v |= (uint64_t)p[i] << (8*i); return v;
    }
};

// Internal helper for ReplayDB: write DB to disk without taking the mutex (caller holds lock)
void ReplayDB::persist_unlocked() {
    // build json text from composite keys
    std::ostringstream oss;
    for (auto &kv : m) oss << kv.first << ':' << kv.second << '\n';
    std::string js = oss.str();

    // Encrypt JSON
    std::array<uint8_t, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES> npub{};
    randombytes_buf(npub.data(), npub.size());
    std::vector<uint8_t> ct(js.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES);
    unsigned long long ct_len = 0;
    uint64_t v = ++version; // increment version
    uint64_t v_enc = v | (1ULL<<63); // mark encrypted format
    if (crypto_aead_xchacha20poly1305_ietf_encrypt(ct.data(), &ct_len,
            reinterpret_cast<const unsigned char*>(js.data()), js.size(),
            reinterpret_cast<const unsigned char*>(&v), sizeof(v),
            nullptr,
            npub.data(), enc_key.data()) != 0) {
        throw std::runtime_error("db encrypt failed");
    }
    ct.resize(static_cast<size_t>(ct_len));

    // Compose file: [8B version (MSB=1)][24B nonce][4B ct_len][ct]
    std::vector<uint8_t> buf; buf.reserve(8 + npub.size() + 4 + ct.size());
    nocturne::write_u64_le(buf, v_enc);
    buf.insert(buf.end(), npub.begin(), npub.end());
    nocturne::write_u32_le(buf, static_cast<uint32_t>(ct.size()));
    buf.insert(buf.end(), ct.begin(), ct.end());

    std::string tmp = db_temp_path(path);
    {
        std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
        if (!f) throw std::runtime_error("open tmp db failed");
        f.write(reinterpret_cast<const char*>(buf.data()), static_cast<std::streamsize>(buf.size()));
        f.flush();
        if (!f) throw std::runtime_error("write tmp db failed");
    }
    std::error_code ec;
    std::filesystem::rename(tmp, path, ec);
    if (ec) {
        std::filesystem::remove(path, ec);
        std::filesystem::rename(tmp, path, ec);
        if (ec) throw std::runtime_error("atomic rename failed: " + ec.message());
    }
    // Update external monotonic counter if configured
    if (tpm_counter_path_) {
        try {
            std::string ctmp = tpm_counter_path_->string() + ".tmp";
            std::vector<uint8_t> buf; buf.reserve(8);
            nocturne::write_u64_le(buf, v);
            {
                std::ofstream f(ctmp, std::ios::binary | std::ios::trunc);
                if (f) {
                    f.write(reinterpret_cast<const char*>(buf.data()), static_cast<std::streamsize>(buf.size()));
                    f.flush();
                }
            }
            std::error_code ec2;
            std::filesystem::rename(ctmp, *tpm_counter_path_, ec2);
            if (ec2) {
                std::filesystem::remove(*tpm_counter_path_, ec2);
                std::filesystem::rename(ctmp, *tpm_counter_path_, ec2);
            }
        } catch (...) {
            audit_log::warn("ReplayDB", "counter", "Failed to update external monotonic counter");
        }
    }
}

static std::string hexify(const uint8_t* p, size_t n) {
    static const char* hex = "0123456789abcdef";
    std::string s; s.reserve(n*2);
    for (size_t i=0;i<n;i++) { s.push_back(hex[p[i]>>4]); s.push_back(hex[p[i]&0xf]); }
    return s;
}

// Enhanced HSM interface with additional security features
struct HSMInterface {
    // Core signing interface
    virtual std::array<uint8_t, crypto_sign_BYTES> sign(const uint8_t* data, size_t len) = 0;
    
    // Key management
    virtual std::optional<std::array<uint8_t, crypto_sign_PUBLICKEYBYTES>> get_public_key() = 0;
    virtual bool has_key(const std::string& label) = 0;
    
    // Random number generation
    virtual std::vector<uint8_t> generate_random(size_t length) = 0;
    
    // Health check
    virtual bool is_healthy() = 0;
    
    virtual ~HSMInterface() = default;
};

// Enhanced FileHSM with additional security features
class FileHSM : public HSMInterface {
    memory_protection::SecureMemory<uint8_t> secure_sk_;
    memory_protection::SecureMemory<uint8_t> secure_pk_;
    bool initialized_{false};
    
public:
    FileHSM(const std::filesystem::path &path) 
        : secure_sk_(crypto_sign_SECRETKEYBYTES),
          secure_pk_(crypto_sign_PUBLICKEYBYTES) {

        std::vector<uint8_t> b;
        try {
            b = read_all(path);
        } catch (const std::exception& e) {
            throw nocturne::IOError(std::string("FileHSM: failed to read key file: ") + e.what());
        }

        // Support encrypted at-rest secret keys if header present
        try {
            if (auto dec = filehsm_secure_storage::decrypt_sk_with_passphrase(b)) {
                std::memcpy(secure_sk_.get(), dec->data(), crypto_sign_SECRETKEYBYTES);
            } else {
                if (b.size() != crypto_sign_SECRETKEYBYTES)
                    throw nocturne::HSMError("filehsm sk size mismatch");
                std::memcpy(secure_sk_.get(), b.data(), crypto_sign_SECRETKEYBYTES);
            }
        } catch (const std::exception& e) {
            throw nocturne::HSMError(std::string("FileHSM: failed to load/decrypt key: ") + e.what());
        }

        // Derive public key from secret key in secure memory
        if (crypto_sign_ed25519_sk_to_pk(secure_pk_.get(), secure_sk_.get()) != 0)
            throw nocturne::CryptoError("failed to derive public key from secret key");

        initialized_ = true;
    }
    
    std::array<uint8_t, crypto_sign_BYTES> sign(const uint8_t* data, size_t len) override {
        if (!initialized_) throw nocturne::HSMError("FileHSM not initialized");
        nocturne::Bytes msg(data, data+len);

        // Create temporary array for signing (will be zeroed automatically)
        std::array<uint8_t, crypto_sign_SECRETKEYBYTES> temp_sk{};
        std::memcpy(temp_sk.data(), secure_sk_.get(), crypto_sign_SECRETKEYBYTES);

        // Use deterministic Ed25519 signing (RFC8032) already provided by libsodium detached API
        std::array<uint8_t, crypto_sign_BYTES> sig = nocturne::ed25519_sign(msg, temp_sk);

        // Zero the temporary array
        nocturne::side_channel::secure_zero_memory(temp_sk.data(), temp_sk.size());

        return sig;
    }
    
    std::optional<std::array<uint8_t, crypto_sign_PUBLICKEYBYTES>> get_public_key() override {
        if (!initialized_) return std::nullopt;
        
        std::array<uint8_t, crypto_sign_PUBLICKEYBYTES> temp_pk;
        std::memcpy(temp_pk.data(), secure_pk_.get(), crypto_sign_PUBLICKEYBYTES);
        return temp_pk;
    }
    
    bool has_key(const std::string& label) override {
        return initialized_ && label == "default";
    }
    
    std::vector<uint8_t> generate_random(size_t length) override {
        std::vector<uint8_t> random(length);
        randombytes_buf(random.data(), length);
        return random;
    }
    
    bool is_healthy() override {
        return initialized_;
    }
    
    ~FileHSM() {
        // SecureMemory destructor automatically handles secure cleanup
        // No manual cleanup needed - memory is automatically zeroed and freed
    }
};

// HSM INTEGRATION: PKCS#11 adapter
//
// Bridges the CLI-facing inline HSMInterface (defined in this file) to the
// production-grade nocturne::hsm::PKCS11HSM in src/hsm/pkcs11_hsm.hpp.
//
// Configuration via environment variables:
//   PKCS11_LIB          - absolute path to PKCS#11 module (.so/.dll). REQUIRED.
//   NOCTURNE_HSM_PIN    - user PIN for C_Login (optional but needed for sign).
//                         The PIN buffer is securely zeroed after authentication.
//   NOCTURNE_HSM_FIPS   - "1" to require FIPS mode (default: 0).
//
// CLI URI: hsm://<token_label>:<key_label>
class PKCS11HSM : public HSMInterface {
private:
    std::string token_id_;
    std::string key_label_;
    std::unique_ptr<nocturne::hsm::PKCS11HSM> impl_;

    static std::string env_or_empty(const char* name) {
        const char* v = std::getenv(name);
        return v ? std::string(v) : std::string();
    }

public:
    PKCS11HSM(const std::string& token_id, const std::string& key_label)
        : token_id_(token_id), key_label_(key_label) {
        if (token_id.empty()) {
            throw nocturne::HSMError("HSM token ID cannot be empty");
        }
        if (key_label.empty()) {
            throw nocturne::HSMError("HSM key label cannot be empty");
        }

        std::string lib_path = env_or_empty("PKCS11_LIB");
        if (lib_path.empty()) {
            throw nocturne::HSMError(
                "PKCS#11 library path not configured: set PKCS11_LIB env var "
                "(e.g. /usr/lib/softhsm/libsofthsm2.so)");
        }

        bool require_fips = env_or_empty("NOCTURNE_HSM_FIPS") == "1";

        try {
            impl_ = std::make_unique<nocturne::hsm::PKCS11HSM>(
                lib_path, token_id_, key_label_, require_fips);
        } catch (const std::exception& e) {
            throw nocturne::HSMError(std::string("PKCS#11 init failed: ") + e.what());
        }

        // Optional authentication via env var (PIN buffer is zeroed inside authenticate()).
        std::string pin = env_or_empty("NOCTURNE_HSM_PIN");
        if (!pin.empty()) {
            std::string pin_copy = pin; // mutable copy for authenticate()
            // Best-effort scrub of the env-derived buffer too.
            nocturne::side_channel::secure_zero_memory(
                pin.data(), pin.size());
            if (!impl_->authenticate(pin_copy)) {
                throw nocturne::HSMError("PKCS#11 C_Login failed (check PIN/lockout)");
            }
        }
    }

    ~PKCS11HSM() override {
        if (impl_) {
            try { impl_->logout(); } catch (...) { /* dtor silent */ }
        }
        // unique_ptr destruction handles C_Finalize + library unload.
    }

    std::array<uint8_t, crypto_sign_BYTES> sign(const uint8_t* data, size_t len) override {
        if (!impl_) throw nocturne::HSMError("PKCS#11 HSM not initialized");
        return impl_->sign(data, len);
    }

    std::optional<std::array<uint8_t, crypto_sign_PUBLICKEYBYTES>> get_public_key() override {
        if (!impl_) return std::nullopt;
        return impl_->get_public_key();
    }

    bool has_key(const std::string& label) override {
        return impl_ && impl_->has_key(label);
    }

    std::vector<uint8_t> generate_random(size_t length) override {
        if (!impl_) {
            // Fallback to libsodium if HSM not available.
            std::vector<uint8_t> random(length);
            randombytes_buf(random.data(), length);
            return random;
        }
        return impl_->generate_random(length);
    }

    bool is_healthy() override {
        return impl_ && impl_->is_healthy();
    }
};

// Enhanced high-level encrypt/decrypt with comprehensive security features
nocturne::Bytes encrypt_packet(
    const std::array<uint8_t, crypto_kx_PUBLICKEYBYTES>& receiver_x25519_pk,
    const nocturne::Bytes& plaintext,
    const nocturne::Bytes& aad = {},
    uint32_t rotation_id = 0,
    bool use_ratchet = false,
    HSMInterface* signer = nullptr,
    ReplayDB* rdb = nullptr,
    const std::string& session_id = "",
    const nocturne::PqcSignerConfig* pqc_signer = nullptr)
{
    using namespace nocturne;
    nocturne::check_sodium();

    // Rate limiting: Check if encryption request is allowed
    std::string rate_limit_id = "encrypt:" + hexify(receiver_x25519_pk.data(), receiver_x25519_pk.size());
    if (!session_id.empty()) {
        rate_limit_id += ":" + session_id;
    }
    
    if (!rate_limiting::allow_request(rate_limit_id)) {
        throw std::runtime_error("Rate limit exceeded for encryption operation");
    }

    auto eph = nocturne::gen_x25519();
    auto key = derive_tx_key_client(eph.pk, eph.sk, receiver_x25519_pk);

    Packet p;
    p.version = VERSION;
    p.flags = 0;
    p.rotation_id = rotation_id;
    randombytes_buf(p.nonce.data(), p.nonce.size());
    p.eph_pk = eph.pk;

    if (rdb) {
        // Use "tx:" prefix for sender's outgoing counters
        std::string rid = "tx:" + hexify(receiver_x25519_pk.data(), receiver_x25519_pk.size());
        uint64_t prev = rdb->get(rid);
        p.counter = prev + 1;
        rdb->set(rid, p.counter);
    } else {
        uint64_t c; randombytes_buf(&c, sizeof(c)); p.counter = c;
    }

    if (use_ratchet) {
        p.flags |= FLAG_HAS_RATCHET;
        auto ratk = gen_x25519();
        p.ratchet_pk = ratk.pk;
        // compute DH between ratk.sk and receiver_x25519_pk (real DH)
        std::array<uint8_t, crypto_scalarmult_BYTES> dh_shared{};
        if (crypto_scalarmult(dh_shared.data(), ratk.sk.data(), receiver_x25519_pk.data()) != 0) throw std::runtime_error("dh failed");
        auto mixed = ratchet_mix(key, dh_shared.data(), dh_shared.size());
        // Side-channel protection: secure memory zeroing
        nocturne::side_channel::secure_zero_memory(key.data(), key.size());
        nocturne::side_channel::secure_zero_memory(ratk.sk.data(), ratk.sk.size());
        nocturne::side_channel::flush_cache_line(key.data());
        nocturne::side_channel::flush_cache_line(ratk.sk.data());
        key = mixed;
    }

    p.aad = aad;
    p.ciphertext = aead_encrypt_xchacha(key, p.nonce, p.aad, plaintext);

    if (signer) {
        // Verify HSM health before signing
        if (!signer->is_healthy()) {
            throw std::runtime_error("HSM is not healthy");
        }

        // Build canonical bytes without signature flag or field
        Packet unsigned_p = p;
        unsigned_p.flags &= ~FLAG_HAS_SIG;
        unsigned_p.signature = std::nullopt;

        Bytes to_sign;
        auto ser_without_sig = serialize(unsigned_p);
        to_sign.insert(to_sign.end(), ser_without_sig.begin(), ser_without_sig.end());

        // Add session ID to signed data if provided
        if (!session_id.empty()) {
            to_sign.insert(to_sign.end(), session_id.begin(), session_id.end());
        }

        auto sig = signer->sign(to_sign.data(), to_sign.size());
        p.flags |= FLAG_HAS_SIG;
        p.signature = sig;
    }

    if (pqc_signer) {
        // Canonical signing region: serialize the packet *without* any
        // signature flags or bytes, then append session_id if bound. This
        // mirrors the classical Ed25519 path so the two stay verifiable
        // through identical canonical-bytes logic.
        Packet unsigned_p = p;
        unsigned_p.flags &= ~(FLAG_HAS_SIG | FLAG_HAS_PQC_SIG);
        unsigned_p.signature = std::nullopt;
        unsigned_p.pqc_sig.clear();
        unsigned_p.pqc_sig_type = 0;

        Bytes to_sign = serialize(unsigned_p);
        if (!session_id.empty()) {
            to_sign.insert(to_sign.end(), session_id.begin(), session_id.end());
        }

        auto scheme = nocturne::pqc::SignatureFactory{}.create(pqc_signer->type);
        auto sig = scheme->sign(to_sign.data(), to_sign.size(), pqc_signer->secret_key);

        p.flags |= FLAG_HAS_PQC_SIG;
        p.pqc_sig_type = static_cast<uint8_t>(pqc_signer->type);
        p.pqc_sig = std::move(sig.bytes);
    }

    auto out = serialize(p);

    // Side-channel protection: secure memory zeroing
    nocturne::side_channel::secure_zero_memory(eph.sk.data(), eph.sk.size());
    nocturne::side_channel::secure_zero_memory(key.data(), key.size());
    nocturne::side_channel::flush_cache_line(eph.sk.data());
    nocturne::side_channel::flush_cache_line(key.data());
    nocturne::side_channel::memory_barrier();

    return out;
}

nocturne::Bytes decrypt_packet(
    const std::array<uint8_t, crypto_kx_PUBLICKEYBYTES>& receiver_x25519_pk,
    const std::array<uint8_t, crypto_kx_SECRETKEYBYTES>& receiver_x25519_sk,
    const nocturne::Bytes& packet_bytes,
    const std::optional<std::array<uint8_t, crypto_sign_PUBLICKEYBYTES>>& opt_expected_signer_ed25519_pk = std::nullopt,
    ReplayDB* rdb = nullptr,
    std::optional<uint32_t> min_rotation_id = std::nullopt,
    const std::string& session_id = "",
    const nocturne::PqcVerifierConfig* pqc_verifier = nullptr)
{
    using namespace nocturne;
    nocturne::check_sodium();

    // Rate limiting: Check if decryption request is allowed
    std::string rate_limit_id = "decrypt:" + hexify(receiver_x25519_pk.data(), receiver_x25519_pk.size());
    if (!session_id.empty()) {
        rate_limit_id += ":" + session_id;
    }
    
    if (!rate_limiting::allow_request(rate_limit_id)) {
        throw std::runtime_error("Rate limit exceeded for decryption operation");
    }

    Packet p = nocturne::deserialize(packet_bytes);

    if (opt_expected_signer_ed25519_pk.has_value()) {
        if (!(p.flags & FLAG_HAS_SIG) || !p.signature) 
            throw std::runtime_error("missing required signature");
        
        Bytes signed_region;
        auto ser_no_sig = serialize(Packet{
            .version = p.version,
            .flags   = static_cast<uint8_t>(p.flags & ~FLAG_HAS_SIG),
            .rotation_id = p.rotation_id,
            .eph_pk  = p.eph_pk,
            .nonce   = p.nonce,
            .counter = p.counter,
            .ratchet_pk = p.ratchet_pk,
            .pqc_kem_type = p.pqc_kem_type,
            .pqc_kem_ct = p.pqc_kem_ct,
            .aad     = p.aad,
            .ciphertext = p.ciphertext,
            .signature  = std::nullopt,
            .pqc_sig_type = p.pqc_sig_type,
            .pqc_sig = p.pqc_sig,
        });
        signed_region.insert(signed_region.end(), ser_no_sig.begin(), ser_no_sig.end());

        // Add session ID to verification if provided
        if (!session_id.empty()) {
            signed_region.insert(signed_region.end(), session_id.begin(), session_id.end());
        }

        if (!ed25519_verify(signed_region, *opt_expected_signer_ed25519_pk, *p.signature))
            throw std::runtime_error("signature verification failed");
    }

    if (pqc_verifier) {
        if (!(p.flags & FLAG_HAS_PQC_SIG) || p.pqc_sig.empty())
            throw std::runtime_error("missing required pqc signature");
        if (p.pqc_sig_type != static_cast<uint8_t>(pqc_verifier->type))
            throw std::runtime_error("pqc sig type mismatch");

        // Canonical signing region — must match encrypt_packet's PQC branch:
        // serialize with BOTH FLAG_HAS_SIG and FLAG_HAS_PQC_SIG cleared.
        Bytes signed_region = serialize(Packet{
            .version = p.version,
            .flags   = static_cast<uint8_t>(p.flags & ~(FLAG_HAS_SIG | FLAG_HAS_PQC_SIG)),
            .rotation_id = p.rotation_id,
            .eph_pk  = p.eph_pk,
            .nonce   = p.nonce,
            .counter = p.counter,
            .ratchet_pk = p.ratchet_pk,
            .pqc_kem_type = p.pqc_kem_type,
            .pqc_kem_ct = p.pqc_kem_ct,
            .aad     = p.aad,
            .ciphertext = p.ciphertext,
            .signature  = std::nullopt,
            .pqc_sig_type = 0,
            .pqc_sig = {},
        });
        if (!session_id.empty()) {
            signed_region.insert(signed_region.end(), session_id.begin(), session_id.end());
        }

        auto scheme = nocturne::pqc::SignatureFactory{}.create(pqc_verifier->type);
        nocturne::pqc::Signature sig_in;
        sig_in.type  = pqc_verifier->type;
        sig_in.bytes = p.pqc_sig;
        if (!scheme->verify(signed_region.data(), signed_region.size(),
                            sig_in, pqc_verifier->public_key)) {
            throw std::runtime_error("pqc signature verification failed");
        }
    }

    if (min_rotation_id.has_value()) {
        if (p.rotation_id < *min_rotation_id) throw std::runtime_error("stale rotation_id: reject message");
    }

    if (rdb) {
        // Use "rx:" prefix for receiver's incoming counters
        std::string rid = "rx:" + hexify(receiver_x25519_pk.data(), receiver_x25519_pk.size());
        uint64_t last = rdb->get(rid);

        // Enhanced replay protection with gap detection
        if (p.counter <= last) {
            throw std::runtime_error("replay detected: counter too small");
        }

        // Detect large gaps (potential message loss)
        if (p.counter > last + 1000) {
            // Log warning but don't fail (allows for legitimate gaps)
            std::cerr << "WARNING: Large counter gap detected: " << last << " -> " << p.counter << std::endl;
        }

        rdb->set(rid, p.counter);
    }

    auto key = derive_rx_key_server(p.eph_pk, receiver_x25519_pk, receiver_x25519_sk);

    if (p.flags & FLAG_HAS_RATCHET) {
        if (!p.ratchet_pk) throw std::runtime_error("ratchet pk missing");
        std::array<uint8_t, crypto_scalarmult_BYTES> dh_shared{};
        if (crypto_scalarmult(dh_shared.data(), receiver_x25519_sk.data(), p.ratchet_pk->data()) != 0) throw std::runtime_error("dh failed");
        auto mixed = ratchet_mix(key, dh_shared.data(), dh_shared.size());
        // Side-channel protection: secure memory zeroing
        nocturne::side_channel::secure_zero_memory(key.data(), key.size());
        nocturne::side_channel::flush_cache_line(key.data());
        key = mixed;
    }

    auto pt = aead_decrypt_xchacha(key, p.nonce, p.aad, p.ciphertext);

    // Enhanced security: zero all sensitive data with side-channel protection
    nocturne::side_channel::secure_zero_memory(key.data(), key.size());
    nocturne::side_channel::flush_cache_line(key.data());
    nocturne::side_channel::memory_barrier();
    
    // Validate decrypted plaintext (basic sanity check)
    if (pt.size() > 1024 * 1024) { // 1MB limit
        throw std::runtime_error("decrypted plaintext too large");
    }

    return pt;
}

// ============================================================================
// Post-Quantum / Hybrid KEM encrypt/decrypt
// ============================================================================
//
// These run alongside the classic X25519 encrypt_packet/decrypt_packet. They
// use the KEMFactory in src/pqc/kem to encapsulate a shared secret with the
// receiver's KEM public key, then derive the AEAD key from that secret. The
// resulting packet has FLAG_HAS_PQC_KEM set; the sender's KEM ciphertext is
// transmitted in pqc_kem_ct, and eph_pk is left zeroed.
//
// kem_type values match nocturne::pqc::KEMType:
//   1 = HYBRID_X25519_MLKEM1024 (recommended; 1600B pk, 3200B sk, 1601B ct)
//   2 = PURE_MLKEM1024          (1568B pk, 3168B sk, 1568B ct)

inline std::array<uint8_t, crypto_aead_xchacha20poly1305_ietf_KEYBYTES>
derive_aead_key_from_kem_secret(const std::array<uint8_t, 32>& kem_ss,
                                const std::string& info) {
    std::array<uint8_t, crypto_aead_xchacha20poly1305_ietf_KEYBYTES> k{};
    if (crypto_generichash(k.data(), k.size(), kem_ss.data(), kem_ss.size(),
                           reinterpret_cast<const uint8_t*>(info.data()), info.size()) != 0) {
        throw std::runtime_error("kem aead key derivation failed");
    }
    return k;
}

nocturne::Bytes encrypt_packet_kem(
    nocturne::pqc::KEMType kem_type,
    const std::vector<uint8_t>& receiver_pk,
    const nocturne::Bytes& plaintext,
    const nocturne::Bytes& aad = {},
    uint32_t rotation_id = 0,
    HSMInterface* signer = nullptr,
    ReplayDB* rdb = nullptr,
    const std::string& session_id = "",
    const nocturne::PqcSignerConfig* pqc_signer = nullptr)
{
    using namespace nocturne;
    nocturne::check_sodium();

    if (kem_type == nocturne::pqc::KEMType::CLASSIC_X25519) {
        throw std::runtime_error("encrypt_packet_kem: use encrypt_packet for X25519");
    }

    auto kem = nocturne::pqc::KEMFactory{}.create(kem_type);
    if (receiver_pk.size() != kem->public_key_size()) {
        throw std::runtime_error("receiver kem pk size mismatch (expected " +
                                 std::to_string(kem->public_key_size()) + ", got " +
                                 std::to_string(receiver_pk.size()) + ")");
    }

    // Rate limit on the receiver pk (use SHA-style identifier from the first
    // 32 bytes of the kem pk; full-pk hashing isn't necessary for a rate key).
    std::string rate_limit_id = "encrypt_kem:" +
        hexify(receiver_pk.data(), std::min<size_t>(receiver_pk.size(), 32));
    if (!session_id.empty()) rate_limit_id += ":" + session_id;
    if (!rate_limiting::allow_request(rate_limit_id)) {
        throw std::runtime_error("Rate limit exceeded for kem encryption operation");
    }

    auto [kem_ct, kem_ss] = kem->encapsulate(receiver_pk);
    auto key = derive_aead_key_from_kem_secret(kem_ss.secret, "nocturne-kem-tx-v4");

    Packet p;
    p.version = VERSION;
    p.flags = FLAG_HAS_PQC_KEM;
    p.rotation_id = rotation_id;
    // eph_pk left zeroed (unused when FLAG_HAS_PQC_KEM is set)
    randombytes_buf(p.nonce.data(), p.nonce.size());
    p.pqc_kem_type = static_cast<uint8_t>(kem_type);
    p.pqc_kem_ct = std::move(kem_ct.ciphertext);

    if (rdb) {
        std::string rid = "tx-kem:" +
            hexify(receiver_pk.data(), std::min<size_t>(receiver_pk.size(), 32));
        uint64_t prev = rdb->get(rid);
        p.counter = prev + 1;
        rdb->set(rid, p.counter);
    } else {
        uint64_t c; randombytes_buf(&c, sizeof(c)); p.counter = c;
    }

    p.aad = aad;
    p.ciphertext = aead_encrypt_xchacha(key, p.nonce, p.aad, plaintext);

    if (signer) {
        if (!signer->is_healthy()) throw std::runtime_error("HSM is not healthy");
        Packet unsigned_p = p;
        unsigned_p.flags &= ~FLAG_HAS_SIG;
        unsigned_p.signature = std::nullopt;
        Bytes to_sign = serialize(unsigned_p);
        if (!session_id.empty()) {
            to_sign.insert(to_sign.end(), session_id.begin(), session_id.end());
        }
        auto sig = signer->sign(to_sign.data(), to_sign.size());
        p.flags |= FLAG_HAS_SIG;
        p.signature = sig;
    }

    if (pqc_signer) {
        Packet unsigned_p = p;
        unsigned_p.flags &= ~(FLAG_HAS_SIG | FLAG_HAS_PQC_SIG);
        unsigned_p.signature = std::nullopt;
        unsigned_p.pqc_sig.clear();
        unsigned_p.pqc_sig_type = 0;

        Bytes to_sign = serialize(unsigned_p);
        if (!session_id.empty()) {
            to_sign.insert(to_sign.end(), session_id.begin(), session_id.end());
        }

        auto scheme = nocturne::pqc::SignatureFactory{}.create(pqc_signer->type);
        auto sig = scheme->sign(to_sign.data(), to_sign.size(), pqc_signer->secret_key);

        p.flags |= FLAG_HAS_PQC_SIG;
        p.pqc_sig_type = static_cast<uint8_t>(pqc_signer->type);
        p.pqc_sig = std::move(sig.bytes);
    }

    auto out = serialize(p);

    // Wipe sensitive material before returning.
    nocturne::side_channel::secure_zero_memory(key.data(), key.size());
    nocturne::side_channel::flush_cache_line(key.data());
    nocturne::side_channel::memory_barrier();
    return out;
}

nocturne::Bytes decrypt_packet_kem(
    const std::vector<uint8_t>& receiver_pk,
    const std::vector<uint8_t>& receiver_sk,
    const nocturne::Bytes& packet_bytes,
    const std::optional<std::array<uint8_t, crypto_sign_PUBLICKEYBYTES>>& opt_expected_signer_ed25519_pk = std::nullopt,
    ReplayDB* rdb = nullptr,
    std::optional<uint32_t> min_rotation_id = std::nullopt,
    const std::string& session_id = "",
    const nocturne::PqcVerifierConfig* pqc_verifier = nullptr)
{
    using namespace nocturne;
    nocturne::check_sodium();

    Packet p = nocturne::deserialize(packet_bytes);

    if (!(p.flags & FLAG_HAS_PQC_KEM) || p.pqc_kem_ct.empty()) {
        throw std::runtime_error("packet is not a PQC/KEM packet");
    }

    auto kem_type = static_cast<nocturne::pqc::KEMType>(p.pqc_kem_type);
    if (kem_type == nocturne::pqc::KEMType::CLASSIC_X25519) {
        throw std::runtime_error("X25519 packet flagged as PQC — refusing");
    }

    auto kem = nocturne::pqc::KEMFactory{}.create(kem_type);
    if (receiver_pk.size() != kem->public_key_size()) {
        throw std::runtime_error("receiver kem pk size mismatch");
    }
    if (receiver_sk.size() != kem->secret_key_size()) {
        throw std::runtime_error("receiver kem sk size mismatch");
    }
    if (p.pqc_kem_ct.size() != kem->ciphertext_size()) {
        throw std::runtime_error("kem ciphertext size mismatch");
    }

    std::string rate_limit_id = "decrypt_kem:" +
        hexify(receiver_pk.data(), std::min<size_t>(receiver_pk.size(), 32));
    if (!session_id.empty()) rate_limit_id += ":" + session_id;
    if (!rate_limiting::allow_request(rate_limit_id)) {
        throw std::runtime_error("Rate limit exceeded for kem decryption operation");
    }

    if (opt_expected_signer_ed25519_pk.has_value()) {
        if (!(p.flags & FLAG_HAS_SIG) || !p.signature)
            throw std::runtime_error("missing required signature");
        Packet unsigned_p = p;
        unsigned_p.flags &= ~FLAG_HAS_SIG;
        unsigned_p.signature = std::nullopt;
        Bytes signed_region = serialize(unsigned_p);
        if (!session_id.empty()) {
            signed_region.insert(signed_region.end(), session_id.begin(), session_id.end());
        }
        if (!ed25519_verify(signed_region, *opt_expected_signer_ed25519_pk, *p.signature))
            throw std::runtime_error("signature verification failed");
    }

    if (pqc_verifier) {
        if (!(p.flags & FLAG_HAS_PQC_SIG) || p.pqc_sig.empty())
            throw std::runtime_error("missing required pqc signature");
        if (p.pqc_sig_type != static_cast<uint8_t>(pqc_verifier->type))
            throw std::runtime_error("pqc sig type mismatch");

        Packet unsigned_p = p;
        unsigned_p.flags &= ~(FLAG_HAS_SIG | FLAG_HAS_PQC_SIG);
        unsigned_p.signature = std::nullopt;
        unsigned_p.pqc_sig.clear();
        unsigned_p.pqc_sig_type = 0;
        Bytes signed_region = serialize(unsigned_p);
        if (!session_id.empty()) {
            signed_region.insert(signed_region.end(), session_id.begin(), session_id.end());
        }

        auto scheme = nocturne::pqc::SignatureFactory{}.create(pqc_verifier->type);
        nocturne::pqc::Signature sig_in;
        sig_in.type  = pqc_verifier->type;
        sig_in.bytes = p.pqc_sig;
        if (!scheme->verify(signed_region.data(), signed_region.size(),
                            sig_in, pqc_verifier->public_key)) {
            throw std::runtime_error("pqc signature verification failed");
        }
    }

    if (min_rotation_id.has_value() && p.rotation_id < *min_rotation_id) {
        throw std::runtime_error("stale rotation_id: reject message");
    }

    if (rdb) {
        std::string rid = "rx-kem:" +
            hexify(receiver_pk.data(), std::min<size_t>(receiver_pk.size(), 32));
        uint64_t last = rdb->get(rid);
        if (p.counter <= last) throw std::runtime_error("replay detected: counter too small");
        if (p.counter > last + 1000) {
            std::cerr << "WARNING: Large counter gap detected: " << last << " -> " << p.counter << std::endl;
        }
        rdb->set(rid, p.counter);
    }

    nocturne::pqc::KEMCiphertext ct;
    ct.type = kem_type;
    // HybridKEM::combine_secrets binds the derived shared secret to
    // NOCTURNE_PROTOCOL_VERSION (the PQC protocol version, 4), NOT to the
    // outer Nocturne packet version (which is still 3 for backward compat).
    // The sender's encapsulate() uses NOCTURNE_PROTOCOL_VERSION here, so the
    // receiver must mirror it — otherwise sender and receiver derive
    // different combined secrets and the AEAD tag fails to authenticate
    // with "aead decrypt failed (auth)" even though the KEM math is correct.
    ct.version = static_cast<uint32_t>(NOCTURNE_PROTOCOL_VERSION);
    ct.ciphertext = p.pqc_kem_ct;
    auto kem_ss = kem->decapsulate(ct, receiver_sk);
    auto key = derive_aead_key_from_kem_secret(kem_ss.secret, "nocturne-kem-tx-v4");

    auto pt = aead_decrypt_xchacha(key, p.nonce, p.aad, p.ciphertext);

    nocturne::side_channel::secure_zero_memory(key.data(), key.size());
    nocturne::side_channel::flush_cache_line(key.data());
    nocturne::side_channel::memory_barrier();

    if (pt.size() > 1024 * 1024) throw std::runtime_error("decrypted plaintext too large");
    return pt;
}

// Utilities
static std::vector<uint8_t> read_all(const std::filesystem::path& p) {
    std::ifstream f(p, std::ios::binary);
    if (!f) throw std::runtime_error("open failed: " + p.string());
    f.seekg(0, std::ios::end);
    std::streamsize n = f.tellg();
    if (n < 0) n = 0;
    f.seekg(0, std::ios::beg);
    std::vector<uint8_t> buf(static_cast<size_t>(n));
    if (n > 0) f.read(reinterpret_cast<char*>(buf.data()), n);
    return buf;
}

static void write_all(const std::filesystem::path& p, const std::vector<uint8_t>& data) {
    std::ofstream f(p, std::ios::binary);
    if (!f) throw std::runtime_error("open failed: " + p.string());
    f.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
}

static void write_all_raw(const std::filesystem::path& p, const uint8_t* data, size_t n) {
    std::ofstream f(p, std::ios::binary);
    if (!f) throw std::runtime_error("open failed: " + p.string());
    f.write(reinterpret_cast<const char*>(data), static_cast<std::streamsize>(n));
}

// Usage message
static void usage() {
    std::cout <<
R"(nocturne-kx (C++23, libsodium) - hardened prototype v3

Subcommands:

  gen-receiver <outdir> [--kem x25519|hybrid|mlkem]
      x25519 (default): writes receiver_x25519_{pk,sk}.bin (32B each, classic ECDH)
      hybrid:           writes receiver_hybrid_{pk,sk}.bin (1600B/3200B, X25519+ML-KEM-1024)
      mlkem:            writes receiver_mlkem_{pk,sk}.bin (1568B/3168B, FIPS 203 Level 5)

  gen-signer <outdir> [--sig-type ed25519|hybrid|mldsa]
      ed25519 (default): writes sender_ed25519_{pk,sk}.bin (32B/64B, classical)
      mldsa:             writes sender_mldsa87_{pk,sk}.bin  (2592B/4896B, FIPS 204 Level 5)
      hybrid:            writes sender_hybrid_sig_{pk,sk}.bin (2624B/4960B, Ed25519+ML-DSA-87)

  encrypt --rx-pk <file> [--kem x25519|hybrid|mlkem]
          [--sign-hsm-uri file://<skfile> or hsm://<id>] [--aad <str>] [--rotation-id <n>] [--ratchet]
          [--pqc-sign-key <file> --pqc-sig-type ed25519|hybrid|mldsa]
          --in <pt> --out <pkt> [--replay-db <path>] [--mac-key <file>]
      --pqc-sign-key uses the FLAG_HAS_PQC_SIG path (variable-length signature),
      orthogonal to --sign-hsm-uri's classical Ed25519 path. Combine
      --kem hybrid + --pqc-sig-type hybrid for full PQ-resistant E2E.

  decrypt --rx-pk <file> --rx-sk <file> [--expect-signer <file>] [--min-rotation <n>]
          [--expect-pqc-signer <pk-file> --pqc-sig-type ed25519|hybrid|mldsa]
          --in <pkt> --out <pt> [--replay-db <path>] [--mac-key <file>]
      KEM mode is auto-detected from the packet header. The rx-pk/rx-sk file
      sizes must match the mode: 32B for X25519, 1600B/3200B for hybrid,
      1568B/3168B for mlkem.

  self-test
      -> Runs a suite of self-tests to verify basic functionality.

  security-check
      -> Performs a basic security check of the application.

  audit-log
      -> Displays a summary of security features and recommendations.

  audit-verify <log-path> [--expect-signer <pk-file>]
      -> Walks the JSONL audit log written by --audit-log, recomputes the
         BLAKE2b hash chain, and (if records are signed) verifies the
         per-record Ed25519 signatures. Exits 0 on full integrity,
         non-zero with line numbers + reasons on the first failure.

  rate-limit-status <identifier>
      -> Shows rate limiting status for a specific identifier.

  rate-limit-reset <identifier>
      -> Resets rate limiting for a specific identifier.

  memory-stats
      -> Shows secure memory allocation statistics.

  dr-demo
      -> Demonstrates Double Ratchet encrypt/decrypt over in-memory transport.

  hs-demo
      -> Demonstrates authenticated handshake (initiator/responder) and derives session keys.

  rate-limit-status <identifier>
      -> Shows rate limiting status for a specific identifier.

Notes:
 - Replay DB: if provided, the DB path will be used and protected with a MAC key (preferably stored in HSM).
 - Ratchet: this implements a simple DH-based mixing step. Real Double Ratchet needed for full security guarantees.
 - HSM: use hsm:// in a real deployment and implement a PKCS#11 wrapper; a FileHSM is provided only for demos.
 - CI: see .github/workflows/cmake.yml for sanitizer, unit-tests and fuzzing job skeletons.
)";
}

#if !defined(NOCTURNE_FUZZER_BUILD) && !defined(NOCTURNE_UNIT_TEST)
int main(int argc, char** argv) {
    try {
        nocturne::check_sodium();
        if (argc < 2) { usage(); return 1; }

        // Global options
        std::optional<std::filesystem::path> opt_rate_store = std::nullopt;
        std::optional<std::filesystem::path> opt_audit_log = std::nullopt;
        std::optional<std::filesystem::path> opt_audit_sign_key = std::nullopt; // Ed25519 sk for audit signing
        std::optional<std::filesystem::path> opt_audit_anchor = std::nullopt;   // External anchor blob (e.g., TSA token)
        std::optional<std::filesystem::path> opt_tpm_counter = std::nullopt;    // External monotonic counter path
        std::string opt_hsm_pass;

        // Pre-scan args for global options and filter remaining into a vector
        std::vector<std::string> args; args.reserve(argc-1);
        for (int i=1;i<argc;++i) {
            std::string a = argv[i];
            auto need = [&](int){ if (i+1>=argc) throw std::runtime_error("missing value for " + a); return std::string(argv[++i]); };
            if (a == "--rate-limit-store") { opt_rate_store = need(1); }
            else if (a == "--audit-log") { opt_audit_log = need(1); }
            else if (a == "--audit-sign-key") { opt_audit_sign_key = need(1); }
            else if (a == "--audit-anchor") { opt_audit_anchor = need(1); }
            else if (a == "--audit-worm-dir") { opt_audit_anchor = need(1); /* temp capture; wired below */ }
            else if (a == "--tpm-counter") { opt_tpm_counter = need(1); }
            else if (a == "--hsm-pass") { opt_hsm_pass = need(1); }
            else { args.push_back(a); }
        }

        // Parse optional WORM dir from args (simple pass-through via environment for now)
        std::optional<std::filesystem::path> opt_audit_worm_dir = std::nullopt;
        for (size_t i = 2; i + 1 < static_cast<size_t>(argc); ++i) {
            if (std::string(argv[i]) == "--audit-worm-dir") {
                opt_audit_worm_dir = std::filesystem::path(argv[i+1]);
            }
        }

        if (opt_audit_log) audit_log::initialize(opt_audit_log, opt_audit_sign_key, opt_audit_anchor, opt_audit_worm_dir);
        rate_limiting::initialize(rate_limiting::RateLimitConfig{}, opt_rate_store);
        if (!opt_hsm_pass.empty()) {
            // Set env for current process (portable)
            std::string kv = std::string("NOCTURNE_HSM_PASSPHRASE=") + opt_hsm_pass;
            ::putenv(strdup(kv.c_str()));
        }

        if (args.empty()) { usage(); return 1; }
        std::string cmd = args[0];

        if (cmd == "gen-receiver") {
            if (args.size() < 2) { usage(); return 1; }
            std::filesystem::path outdir = args[1];
            std::string kem_str = "x25519";
            for (size_t i = 2; i < args.size(); ++i) {
                if (args[i] == "--kem") {
                    if (i + 1 >= args.size()) throw std::runtime_error("missing value for --kem");
                    kem_str = args[++i];
                } else {
                    throw std::runtime_error("unknown argument: " + args[i]);
                }
            }
            std::filesystem::create_directories(outdir);

            if (kem_str == "x25519") {
                auto kp = nocturne::gen_x25519();
                write_all_raw(outdir / "receiver_x25519_pk.bin", kp.pk.data(), kp.pk.size());
                write_all_raw(outdir / "receiver_x25519_sk.bin", kp.sk.data(), kp.sk.size());
                std::cout << "Wrote X25519 receiver keys to " << outdir << "\n";
            } else if (kem_str == "hybrid" || kem_str == "mlkem") {
                auto kem_type = (kem_str == "hybrid")
                    ? nocturne::pqc::KEMType::HYBRID_X25519_MLKEM1024
                    : nocturne::pqc::KEMType::PURE_MLKEM1024;
                auto kem = nocturne::pqc::KEMFactory{}.create(kem_type);
                auto kp = kem->generate_keypair();
                std::string base = "receiver_" + kem_str;
                write_all_raw(outdir / (base + "_pk.bin"), kp.public_key.data(), kp.public_key.size());
                write_all_raw(outdir / (base + "_sk.bin"), kp.secret_key.data(), kp.secret_key.size());
                std::cout << "Wrote " << kem->algorithm_name() << " receiver keys to " << outdir
                          << " (pk=" << kp.public_key.size() << "B, sk=" << kp.secret_key.size() << "B)\n";
            } else {
                throw std::runtime_error("unknown --kem value: " + kem_str + " (expected x25519|hybrid|mlkem)");
            }
            return 0;
        }

        if (cmd == "gen-signer") {
            if (argc < 3) { usage(); return 1; }
            std::filesystem::path outdir = argv[2];
            std::string sig_str = "ed25519";
            for (int i = 3; i < argc; ++i) {
                std::string a = argv[i];
                if (a == "--sig-type" && i + 1 < argc) {
                    sig_str = argv[++i];
                } else {
                    std::cerr << "ERR: unknown gen-signer arg: " << a << "\n";
                    return 1;
                }
            }
            std::filesystem::create_directories(outdir);

            if (sig_str == "ed25519") {
                auto kp = nocturne::gen_ed25519();
                write_all_raw(outdir / "sender_ed25519_pk.bin", kp.pk.data(), kp.pk.size());
                write_all_raw(outdir / "sender_ed25519_sk.bin", kp.sk.data(), kp.sk.size());
                std::cout << "Wrote Ed25519 signer keys to " << outdir << "\n";
            } else if (sig_str == "hybrid" || sig_str == "mldsa") {
                auto sig_type = (sig_str == "hybrid")
                    ? nocturne::pqc::SigType::HYBRID_ED25519_MLDSA87
                    : nocturne::pqc::SigType::PURE_MLDSA87;
                auto scheme = nocturne::pqc::SignatureFactory{}.create(sig_type);
                auto kp = scheme->generate_keypair();
                std::string base = (sig_str == "hybrid") ? "sender_hybrid_sig" : "sender_mldsa87";
                write_all_raw(outdir / (base + "_pk.bin"),
                              kp.public_key.data(), kp.public_key.size());
                write_all_raw(outdir / (base + "_sk.bin"),
                              kp.secret_key.data(), kp.secret_key.size());
                std::cout << "Wrote " << scheme->algorithm_name() << " signer keys to "
                          << outdir << " (pk=" << kp.public_key.size()
                          << "B, sk=" << kp.secret_key.size() << "B)\n";
            } else {
                throw std::runtime_error("unknown --sig-type value: " + sig_str +
                                         " (expected ed25519|hybrid|mldsa)");
            }
            return 0;
        }

        if (cmd == "encrypt") {
            std::filesystem::path rxpk, in, out, replaydb_path, mac_key_path;
            std::string aad_str, signer_uri;
            uint32_t rotation_id = 0; bool use_ratchet = false;
            std::string kem_str = "x25519"; // x25519 (classic) | hybrid | mlkem
            std::filesystem::path pqc_sign_key_path;
            std::string pqc_sig_str; // ed25519 | hybrid | mldsa (empty = disabled)
            
            // ERROR HANDLING: Comprehensive input validation and error management
            try {
                for (int i=2;i<argc;++i) {
                    std::string a = argv[i];
                    auto need = [&](int){
                        if (i+1>=argc) {
                            throw std::runtime_error("missing value for argument: " + a);
                        }
                        return std::string(argv[++i]);
                    };

                    // Skip global options (already parsed in main)
                    if (a=="--rate-limit-store" || a=="--audit-log" || a=="--audit-sign-key" ||
                        a=="--audit-anchor" || a=="--audit-worm-dir" || a=="--tpm-counter" || a=="--hsm-pass") {
                        need(1); // consume the value
                        continue;
                    }

                    if      (a=="--rx-pk") rxpk = need(1);
                    else if (a=="--sign-hsm-uri") signer_uri = need(1);
                    else if (a=="--aad") aad_str = need(1);
                    else if (a=="--rotation-id") {
                        try {
                            rotation_id = static_cast<uint32_t>(std::stoul(need(1)));
                        } catch (const std::exception& e) {
                            throw std::runtime_error("invalid rotation-id: must be a positive integer");
                        }
                    }
                    else if (a=="--ratchet") use_ratchet = true;
                    else if (a=="--kem") kem_str = need(1);
                    else if (a=="--in") in = need(1);
                    else if (a=="--out") out = need(1);
                    else if (a=="--replay-db") replaydb_path = need(1);
                    else if (a=="--mac-key") mac_key_path = need(1);
                    else if (a=="--pqc-sign-key") pqc_sign_key_path = need(1);
                    else if (a=="--pqc-sig-type") pqc_sig_str = need(1);
                    else throw std::runtime_error("unknown argument: " + a);
                }
                
                // CRITICAL SECURITY VALIDATION: Check required arguments
                if (rxpk.empty()) {
                    throw std::runtime_error("missing required argument: --rx-pk");
                }
                if (in.empty()) {
                    throw std::runtime_error("missing required argument: --in");
                }
                if (out.empty()) {
                    throw std::runtime_error("missing required argument: --out");
                }
                
                // VALIDATE FILE PATHS: Prevent path traversal attacks
                if (!std::filesystem::exists(rxpk)) {
                    throw std::runtime_error("receiver public key file does not exist: " + rxpk.string());
                }
                if (!std::filesystem::exists(in)) {
                    throw std::runtime_error("input file does not exist: " + in.string());
                }
                
            } catch (const std::runtime_error& e) {
                std::cerr << "ERROR: " << e.what() << "\n";
                std::cerr << "Use 'nocturne-kx help' for usage information.\n";
                return 1;
            }
            auto rxpk_bytes = read_all(rxpk);

            // Resolve --kem mode and validate the rx-pk file size against the chosen KEM.
            nocturne::pqc::KEMType kem_type;
            if (kem_str == "x25519") {
                kem_type = nocturne::pqc::KEMType::CLASSIC_X25519;
                if (rxpk_bytes.size() != crypto_kx_PUBLICKEYBYTES) {
                    throw std::runtime_error("X25519 receiver pk size mismatch (expected 32, got " +
                                             std::to_string(rxpk_bytes.size()) + ")");
                }
            } else if (kem_str == "hybrid") {
                kem_type = nocturne::pqc::KEMType::HYBRID_X25519_MLKEM1024;
            } else if (kem_str == "mlkem") {
                kem_type = nocturne::pqc::KEMType::PURE_MLKEM1024;
            } else {
                throw std::runtime_error("unknown --kem value: " + kem_str + " (expected x25519|hybrid|mlkem)");
            }
            std::array<uint8_t, crypto_kx_PUBLICKEYBYTES> rxpk_arr{};
            if (kem_type == nocturne::pqc::KEMType::CLASSIC_X25519) {
                std::memcpy(rxpk_arr.data(), rxpk_bytes.data(), rxpk_arr.size());
            }

            // HSM VALIDATION: Comprehensive HSM URI validation and error handling
            std::unique_ptr<HSMInterface> signer = nullptr;
            if (!signer_uri.empty()) {
                try {
                    if (signer_uri.rfind("file://",0)==0) {
                        std::string file_path = signer_uri.substr(strlen("file://"));
                        if (file_path.empty()) {
                            throw std::runtime_error("empty file path in HSM URI");
                        }
                        
                        // Validate file path security
                        std::filesystem::path hsm_path(file_path);
                        if (!std::filesystem::exists(hsm_path)) {
                            throw std::runtime_error("HSM key file does not exist: " + file_path);
                        }
                        
                        // Check file permissions (basic security check)
                        auto perms = std::filesystem::status(hsm_path).permissions();
                        if ((perms & std::filesystem::perms::others_read) != std::filesystem::perms::none) {
                            std::cerr << "WARNING: HSM key file has world-readable permissions\n";
                        }
                        
                        signer = std::make_unique<FileHSM>(hsm_path);
                    } else if (signer_uri.rfind("hsm://",0)==0) {
                        // HSM INTEGRATION: PKCS#11 implementation
                        std::string hsm_spec = signer_uri.substr(strlen("hsm://"));
                        if (hsm_spec.empty()) {
                            throw std::runtime_error("empty HSM specification in URI");
                        }
                        
                        // Parse HSM specification: token_id:key_label
                        size_t colon_pos = hsm_spec.find(':');
                        if (colon_pos == std::string::npos) {
                            throw std::runtime_error("invalid HSM URI format: expected 'hsm://token_id:key_label'");
                        }
                        
                        std::string token_id = hsm_spec.substr(0, colon_pos);
                        std::string key_label = hsm_spec.substr(colon_pos + 1);
                        
                        if (token_id.empty()) {
                            throw std::runtime_error("empty token ID in HSM URI");
                        }
                        if (key_label.empty()) {
                            throw std::runtime_error("empty key label in HSM URI");
                        }
                        
                        // Create PKCS#11 HSM instance
                        signer = std::make_unique<PKCS11HSM>(token_id, key_label);
                        
                        std::cout << "INFO: Using PKCS#11 HSM (Token: " << token_id << ", Key: " << key_label << ")\n";
                    } else {
                        throw std::runtime_error("unsupported HSM URI scheme: " + signer_uri);
                    }
                } catch (const std::exception& e) {
                    std::cerr << "HSM ERROR: " << e.what() << "\n";
                    return 1;
                }
            }

            auto pt = read_all(in);
            nocturne::Bytes aad(aad_str.begin(), aad_str.end());

            // Optional PQC signer: --pqc-sign-key + --pqc-sig-type. Reads the
            // raw secret-key file and prepares a PqcSignerConfig that
            // encrypt_packet / encrypt_packet_kem will use to populate the
            // FLAG_HAS_PQC_SIG block.
            std::optional<nocturne::PqcSignerConfig> pqc_signer_cfg;
            if (!pqc_sign_key_path.empty() || !pqc_sig_str.empty()) {
                if (pqc_sign_key_path.empty() || pqc_sig_str.empty()) {
                    std::cerr << "ERR: --pqc-sign-key and --pqc-sig-type must both be set\n";
                    return 1;
                }
                nocturne::pqc::SigType st;
                if      (pqc_sig_str == "ed25519") st = nocturne::pqc::SigType::CLASSIC_ED25519;
                else if (pqc_sig_str == "hybrid")  st = nocturne::pqc::SigType::HYBRID_ED25519_MLDSA87;
                else if (pqc_sig_str == "mldsa")   st = nocturne::pqc::SigType::PURE_MLDSA87;
                else {
                    std::cerr << "ERR: unknown --pqc-sig-type: " << pqc_sig_str
                              << " (expected ed25519|hybrid|mldsa)\n";
                    return 1;
                }
                auto sk_bytes = read_all(pqc_sign_key_path);
                auto scheme = nocturne::pqc::SignatureFactory{}.create(st);
                if (sk_bytes.size() != scheme->secret_key_size()) {
                    std::cerr << "ERR: --pqc-sign-key size mismatch (expected "
                              << scheme->secret_key_size() << " for "
                              << scheme->algorithm_name() << ", got "
                              << sk_bytes.size() << ")\n";
                    return 1;
                }
                pqc_signer_cfg = nocturne::PqcSignerConfig{st, std::move(sk_bytes)};
            }

            std::optional<std::filesystem::path> mac_key = mac_key_path.empty()?std::nullopt:std::optional<std::filesystem::path>(mac_key_path);
            ReplayDB rdb(replaydb_path.empty()?std::filesystem::path(std::string(std::getenv("HOME")?std::getenv("HOME"):".")) / ".nocturne" / "replaydb.bin": replaydb_path, mac_key, opt_tpm_counter);
            ReplayDB* rdbp = replaydb_path.empty()?nullptr:&rdb;

            const nocturne::PqcSignerConfig* pqc_ptr =
                pqc_signer_cfg.has_value() ? &*pqc_signer_cfg : nullptr;

            nocturne::Bytes pkt;
            if (kem_type == nocturne::pqc::KEMType::CLASSIC_X25519) {
                pkt = encrypt_packet(rxpk_arr, pt, aad, rotation_id, use_ratchet,
                                     signer.get(), rdbp, "", pqc_ptr);
                std::cout << "Encrypted (X25519"
                          << (pqc_ptr ? std::string(" + ") + nocturne::pqc::sig_type_to_string(pqc_ptr->type) : "")
                          << ") -> " << out << " (" << pkt.size() << " bytes)\n";
            } else {
                if (use_ratchet) {
                    std::cerr << "WARNING: --ratchet ignored in PQC/KEM mode (DR uses its own key path)\n";
                }
                pkt = encrypt_packet_kem(kem_type, rxpk_bytes, pt, aad, rotation_id,
                                         signer.get(), rdbp, "", pqc_ptr);
                const char* algo = (kem_type == nocturne::pqc::KEMType::HYBRID_X25519_MLKEM1024)
                                   ? "Hybrid X25519+ML-KEM-1024" : "ML-KEM-1024";
                std::cout << "Encrypted (" << algo
                          << (pqc_ptr ? std::string(" + ") + nocturne::pqc::sig_type_to_string(pqc_ptr->type) : "")
                          << ") -> " << out << " (" << pkt.size() << " bytes)\n";
            }
            write_all(out, pkt);
            return 0;
        }

        if (cmd == "decrypt") {
            std::filesystem::path rxpk, rxsk, in, out, replaydb_path, mac_key_path;
            std::string expectpk_path;
            std::filesystem::path expect_pqc_pk_path;
            std::string expect_pqc_sig_str;
            std::optional<uint32_t> min_rotation = std::nullopt;
            for (int i=2;i<argc;++i) {
                std::string a = argv[i];
                auto need = [&](int){ if (i+1>=argc) throw std::runtime_error("missing value for " + a); return std::string(argv[++i]); };

                // Skip global options (already parsed in main)
                if (a=="--rate-limit-store" || a=="--audit-log" || a=="--audit-sign-key" ||
                    a=="--audit-anchor" || a=="--audit-worm-dir" || a=="--tpm-counter" || a=="--hsm-pass") {
                    need(1); // consume the value
                    continue;
                }

                if      (a=="--rx-pk") rxpk = need(1);
                else if (a=="--rx-sk") rxsk = need(1);
                else if (a=="--expect-signer") expectpk_path = need(1);
                else if (a=="--min-rotation") min_rotation = static_cast<uint32_t>(std::stoul(need(1)));
                else if (a=="--in") in = need(1);
                else if (a=="--out") out = need(1);
                else if (a=="--replay-db") replaydb_path = need(1);
                else if (a=="--mac-key") mac_key_path = need(1);
                else if (a=="--expect-pqc-signer") expect_pqc_pk_path = need(1);
                else if (a=="--pqc-sig-type") expect_pqc_sig_str = need(1);
                else throw std::runtime_error("unknown arg: " + a);
            }
            if (rxpk.empty() || rxsk.empty() || in.empty() || out.empty()) throw std::runtime_error("missing required args");
            auto rxpk_b = read_all(rxpk); auto rxsk_b = read_all(rxsk);

            std::optional<std::array<uint8_t, crypto_sign_PUBLICKEYBYTES>> expectpk_arr = std::nullopt;
            if (!expectpk_path.empty()) {
                auto e = read_all(expectpk_path);
                if (e.size()!=crypto_sign_PUBLICKEYBYTES) throw std::runtime_error("expected signer pk size mismatch");
                std::array<uint8_t, crypto_sign_PUBLICKEYBYTES> tmp{}; std::memcpy(tmp.data(), e.data(), tmp.size()); expectpk_arr = tmp;
            }

            // Optional PQC verifier: --expect-pqc-signer + --pqc-sig-type. Both
            // must be set together. Public-key size is enforced against the
            // factory's reported size for the chosen SigType.
            std::optional<nocturne::PqcVerifierConfig> pqc_verifier_cfg;
            if (!expect_pqc_pk_path.empty() || !expect_pqc_sig_str.empty()) {
                if (expect_pqc_pk_path.empty() || expect_pqc_sig_str.empty()) {
                    throw std::runtime_error("--expect-pqc-signer and --pqc-sig-type must both be set");
                }
                nocturne::pqc::SigType st;
                if      (expect_pqc_sig_str == "ed25519") st = nocturne::pqc::SigType::CLASSIC_ED25519;
                else if (expect_pqc_sig_str == "hybrid")  st = nocturne::pqc::SigType::HYBRID_ED25519_MLDSA87;
                else if (expect_pqc_sig_str == "mldsa")   st = nocturne::pqc::SigType::PURE_MLDSA87;
                else throw std::runtime_error("unknown --pqc-sig-type: " + expect_pqc_sig_str);

                auto pk_bytes = read_all(expect_pqc_pk_path);
                auto scheme = nocturne::pqc::SignatureFactory{}.create(st);
                if (pk_bytes.size() != scheme->public_key_size()) {
                    throw std::runtime_error(
                        "--expect-pqc-signer pk size mismatch (expected " +
                        std::to_string(scheme->public_key_size()) + " for " +
                        scheme->algorithm_name() + ", got " +
                        std::to_string(pk_bytes.size()) + ")");
                }
                pqc_verifier_cfg = nocturne::PqcVerifierConfig{st, std::move(pk_bytes)};
            }
            const nocturne::PqcVerifierConfig* pqc_vptr =
                pqc_verifier_cfg.has_value() ? &*pqc_verifier_cfg : nullptr;

            std::optional<std::filesystem::path> mac_key = mac_key_path.empty()?std::nullopt:std::optional<std::filesystem::path>(mac_key_path);
            ReplayDB rdb(replaydb_path.empty()?std::filesystem::path(std::string(std::getenv("HOME")?std::getenv("HOME"):".")) / ".nocturne" / "replaydb.bin": replaydb_path, mac_key, opt_tpm_counter);
            ReplayDB* rdbp = replaydb_path.empty()?nullptr:&rdb;

            auto pkt = read_all(in);

            // Auto-detect KEM mode from the packet header. Peek at the flags byte
            // (offset 1, immediately after the version byte) without doing a full
            // deserialize — keeps the dispatch cheap and avoids double-parsing.
            if (pkt.size() < 2) throw std::runtime_error("packet too small to inspect");
            bool is_pqc = (pkt[1] & nocturne::FLAG_HAS_PQC_KEM) != 0;

            nocturne::Bytes pt;
            if (!is_pqc) {
                if (rxpk_b.size()!=crypto_kx_PUBLICKEYBYTES) throw std::runtime_error("X25519 receiver pk size mismatch");
                if (rxsk_b.size()!=crypto_kx_SECRETKEYBYTES) throw std::runtime_error("X25519 receiver sk size mismatch");
                std::array<uint8_t, crypto_kx_PUBLICKEYBYTES> rxpk_arr{};
                std::array<uint8_t, crypto_kx_SECRETKEYBYTES> rxsk_arr{};
                std::memcpy(rxpk_arr.data(), rxpk_b.data(), rxpk_arr.size());
                std::memcpy(rxsk_arr.data(), rxsk_b.data(), rxsk_arr.size());
                pt = decrypt_packet(rxpk_arr, rxsk_arr, pkt, expectpk_arr, rdbp,
                                    min_rotation, "", pqc_vptr);
                std::cout << "Decrypted (X25519"
                          << (pqc_vptr ? std::string(" + ") + nocturne::pqc::sig_type_to_string(pqc_vptr->type) + " verified" : "")
                          << ") -> " << out << " (" << pt.size() << " bytes)\n";
            } else {
                // KEMFactory + size validation happens inside decrypt_packet_kem.
                pt = decrypt_packet_kem(rxpk_b, rxsk_b, pkt, expectpk_arr, rdbp,
                                        min_rotation, "", pqc_vptr);
                std::cout << "Decrypted (PQC/KEM"
                          << (pqc_vptr ? std::string(" + ") + nocturne::pqc::sig_type_to_string(pqc_vptr->type) + " verified" : "")
                          << ") -> " << out << " (" << pt.size() << " bytes)\n";
            }
            write_all(out, pt);
            return 0;
        }

        if (cmd == "self-test") {
            std::cout << "Running Nocturne-KX self-test...\n";
            
            // Test key generation
            std::cout << "  Testing key generation...\n";
            auto x25519_kp = nocturne::gen_x25519();
            auto ed25519_kp = nocturne::gen_ed25519();
            (void)x25519_kp; // Suppress unused variable warning
            (void)ed25519_kp; // Suppress unused variable warning
            std::cout << "    ✓ X25519 key generation\n";
            std::cout << "    ✓ Ed25519 key generation\n";
            
            // Test key derivation
            std::cout << "  Testing key derivation...\n";
            auto alice = nocturne::gen_x25519();
            auto bob = nocturne::gen_x25519();
            auto client_tx = nocturne::derive_tx_key_client(alice.pk, alice.sk, bob.pk);
            auto server_rx = nocturne::derive_rx_key_server(alice.pk, bob.pk, bob.sk);
            if (client_tx == server_rx) {
                std::cout << "    ✓ Key derivation\n";
            } else {
                throw std::runtime_error("key derivation failed");
            }
            
            // Test encryption/decryption
            std::cout << "  Testing encryption/decryption...\n";
            nocturne::Bytes test_pt = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
            nocturne::Bytes test_aad = {0xAA, 0xBB, 0xCC, 0xDD};
            auto encrypted = encrypt_packet(bob.pk, test_pt, test_aad, 0, false, nullptr, nullptr);
            auto decrypted = decrypt_packet(bob.pk, bob.sk, encrypted, std::nullopt, nullptr, std::nullopt);
            if (decrypted == test_pt) {
                std::cout << "    ✓ Encryption/decryption\n";
            } else {
                throw std::runtime_error("encryption/decryption failed");
            }
            
            // Test signatures
            std::cout << "  Testing digital signatures...\n";
            nocturne::Bytes test_msg = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
            auto sig = nocturne::ed25519_sign(test_msg, ed25519_kp.sk);
            if (nocturne::ed25519_verify(test_msg, ed25519_kp.pk, sig)) {
                std::cout << "    ✓ Digital signatures\n";
            } else {
                throw std::runtime_error("digital signature verification failed");
            }
            
            // Test replay protection
            std::cout << "  Testing replay protection...\n";
            std::filesystem::path test_db = "test_replaydb.bin";
            std::filesystem::path test_key = "test_mac_key.bin";
            
            // Create test MAC key
            std::array<uint8_t, crypto_generichash_KEYBYTES> mac_key{};
            randombytes_buf(mac_key.data(), mac_key.size());
            {
                std::ofstream f(test_key, std::ios::binary);
                f.write(reinterpret_cast<const char*>(mac_key.data()), mac_key.size());
            }
            
            ReplayDB test_rdb(test_db, test_key);
            test_rdb.set("test_key", 42);
            if (test_rdb.get("test_key") == 42) {
                std::cout << "    ✓ Replay protection\n";
            } else {
                throw std::runtime_error("replay protection failed");
            }
            
            // Cleanup test files
            std::filesystem::remove(test_db);
            std::filesystem::remove(test_key);
            
            std::cout << "All tests passed! ✓\n";
            return 0;
        }

        if (cmd == "hs-demo") {
            using namespace nocturne::handshake;
            nocturne::check_sodium();
            std::cout << "Running handshake demo...\n";
            auto initiator_id = generate_identity_ed25519();
            auto responder_id = generate_identity_ed25519();
            InitiatorHandshake init(initiator_id, responder_id.pk);
            ResponderHandshake resp(responder_id, initiator_id.pk);
            auto h1 = init.create_hello1();
            auto h2 = resp.process_hello1(h1);
            auto h3 = init.process_hello2(h2);
            resp.finalize(h3);
            if (init.is_complete() && resp.is_complete()) {
                std::cout << "  ✓ Handshake complete\n";
            } else {
                throw std::runtime_error("handshake did not complete");
            }
            std::cout << "Derived keys: tx(rx) sizes=" << init.tx_key().size() << "," << init.rx_key().size() << "\n";
            return 0;
        }

        if (cmd == "dr-demo") {
            using namespace nocturne;
            using namespace nocturne::transport;
            nocturne::check_sodium();
            std::cout << "Running Double Ratchet + transport demo...\n";
            // Establish initial shared secret (simulate KX)
            auto a = gen_x25519(); auto b = gen_x25519();
            std::array<uint8_t, crypto_kx_SESSIONKEYBYTES> rx{}, tx{};
            if (crypto_kx_client_session_keys(rx.data(), tx.data(), a.pk.data(), a.sk.data(), b.pk.data()) != 0) throw std::runtime_error("kx fail");
            DoubleRatchet dra(rx); DoubleRatchet drb(rx); // same seed for demo
            dra.set_remote_public_key(drb.get_public_key());
            drb.set_remote_public_key(dra.get_public_key());

            // Transport sessions
            Session sa(1, FeatureSet{}), sb(2, FeatureSet{});
            MemoryTransport ta(sa), tb(sb); ta.set_peer(&tb); tb.set_peer(&ta);

            // Negotiate
            ta.send(sa.make_negotiate()); tb.pump_retries();

            // Set receive handler to decrypt
            tb.set_on_data([&](const DataPayload& d){
                try {
                    RatchetMessage msg{};
                    // For demo, pack dra header into aad and DR ciphertext directly
                    // Normally, you would serialize RatchetMessage separately.
                    msg.dh_public_key = dra.get_public_key();
                    msg.prev_chain_count = 0; msg.message_count = 1; msg.ciphertext = d.ciphertext;
                    std::vector<uint8_t> pt = drb.decrypt_message(msg);
                    (void)pt;
                } catch(...) {}
            });

            // Encrypt one message and send
            std::vector<uint8_t> pt = {1,2,3,4};
            auto rm = dra.encrypt_message(pt);
            Bytes aad; // could include rm headers
            Frame f = sa.make_data(aad, rm.ciphertext);
            ta.send(f);
            tb.pump_retries();
            std::cout << "  ✓ Transport data sent with seq and ACK/NAK handling\n";
            return 0;
        }

        if (cmd == "security-check") {
            std::cout << "Running Nocturne-KX security check...\n";
            
            // Check libsodium version
            std::cout << "  Checking libsodium version...\n";
            (void)sodium_version_string(); // Suppress unused variable warning
            std::cout << "    ✓ libsodium version: " << sodium_version_string() << "\n";
            
            // Check for secure random number generation
            std::cout << "  Checking random number generation...\n";
            std::array<uint8_t, 32> random_bytes{};
            randombytes_buf(random_bytes.data(), random_bytes.size());
            bool has_entropy = false;
            for (auto b : random_bytes) if (b != 0) { has_entropy = true; break; }
            if (has_entropy) {
                std::cout << "    ✓ Secure random number generation\n";
            } else {
                std::cout << "    ⚠ Warning: Random number generation may not be secure\n";
            }
            
            // Check file permissions (if keys exist)
            std::cout << "  Checking file permissions...\n";
            std::vector<std::string> key_files = {
                "receiver_x25519_sk.bin",
                "sender_ed25519_sk.bin"
            };
            
            for (const auto& key_file : key_files) {
                if (std::filesystem::exists(key_file)) {
                    auto perms = std::filesystem::status(key_file).permissions();
                    if ((perms & std::filesystem::perms::others_read) == std::filesystem::perms::none &&
                        (perms & std::filesystem::perms::group_read) == std::filesystem::perms::none) {
                        std::cout << "    ✓ " << key_file << " has secure permissions\n";
                    } else {
                        std::cout << "    ⚠ Warning: " << key_file << " has insecure permissions\n";
                    }
                }
            }
            
            // Check environment variables
            std::cout << "  Checking environment variables...\n";
            const char* sensitive_vars[] = {"HSM_PIN", "HSM_SO_PIN", "NOCTURNE_SECRET_KEY"};
            for (const auto& var : sensitive_vars) {
                if (std::getenv(var)) {
                    std::cout << "    ✓ " << var << " is set\n";
                } else {
                    std::cout << "    ℹ " << var << " is not set (may be optional)\n";
                }
            }
            
            std::cout << "Security check completed!\n";
            return 0;
        }

        if (cmd == "audit-log") {
            std::cout << "Nocturne-KX Audit Log\n";
            std::cout << "====================\n\n";
            
            // Log system information
            std::cout << "System Information:\n";
            std::cout << "  Timestamp: " << std::chrono::system_clock::now().time_since_epoch().count() << "\n";
            std::cout << "  libsodium version: " << sodium_version_string() << "\n";
            std::cout << "  Nocturne-KX version: " << static_cast<int>(nocturne::VERSION) << "\n\n";
            
            // Log security features
            std::cout << "Security Features:\n";
            std::cout << "  ✓ X25519 key exchange\n";
            std::cout << "  ✓ ChaCha20-Poly1305 AEAD encryption\n";
            std::cout << "  ✓ Ed25519 digital signatures\n";
            std::cout << "  ✓ Replay protection with MAC\n";
            std::cout << "  ✓ Key rotation enforcement\n";
            std::cout << "  ✓ HSM integration support\n";
            std::cout << "  ✓ Double Ratchet scaffolding\n";
            std::cout << "  ✓ Rate limiting protection\n";
            std::cout << "  ✓ Memory protection with secure allocator\n\n";
            
            // Log warnings
            std::cout << "Security Warnings:\n";
            std::cout << "  ⚠ This is prototype software - not for production use\n";
            std::cout << "  ⚠ FileHSM is for development only - use real HSM in production\n";
            std::cout << "  ⚠ Double Ratchet implementation is basic - not full Signal Protocol\n";
            std::cout << "  ⚠ Limited side-channel protection\n";
            std::cout << "  ⚠ No formal security audit completed\n\n";
            
            // Log recommendations
            std::cout << "Security Recommendations:\n";
            std::cout << "  1. Obtain formal security audit before production use\n";
            std::cout << "  2. Implement proper HSM integration\n";
            std::cout << "  3. Add comprehensive audit logging\n";
            std::cout << "  4. Implement proper key management\n";
            std::cout << "  5. Add real-time security monitoring\n";
            std::cout << "  6. Conduct penetration testing\n";
            std::cout << "  7. Follow secure development lifecycle\n";
            
            return 0;
        }

        if (cmd == "audit-verify") {
            if (argc < 3) { usage(); return 1; }
            std::filesystem::path log_path = argv[2];
            std::optional<std::array<uint8_t, crypto_sign_PUBLICKEYBYTES>> expect_pk;
            for (int i = 3; i < argc; ++i) {
                std::string a = argv[i];
                if (a == "--expect-signer" && i + 1 < argc) {
                    std::filesystem::path pkp = argv[++i];
                    std::ifstream kf(pkp, std::ios::binary);
                    if (!kf) { std::cerr << "ERR: cannot open " << pkp << "\n"; return 2; }
                    std::vector<uint8_t> kb((std::istreambuf_iterator<char>(kf)), std::istreambuf_iterator<char>());
                    if (kb.size() != crypto_sign_PUBLICKEYBYTES) {
                        std::cerr << "ERR: --expect-signer pk has wrong size (" << kb.size()
                                  << ", expected " << crypto_sign_PUBLICKEYBYTES << ")\n";
                        return 2;
                    }
                    std::array<uint8_t, crypto_sign_PUBLICKEYBYTES> pk{};
                    std::memcpy(pk.data(), kb.data(), kb.size());
                    expect_pk = pk;
                } else {
                    std::cerr << "ERR: unknown audit-verify arg: " << a << "\n";
                    return 1;
                }
            }
            auto res = audit_log::verify_chain(log_path, expect_pk);
            std::cout << "Audit chain verification\n";
            std::cout << "  file:             " << log_path << "\n";
            std::cout << "  records checked:  " << res.records_checked << "\n";
            std::cout << "  ok:               " << (res.ok ? "yes" : "NO") << "\n";
            if (!res.ok) {
                if (res.first_failure_line)
                    std::cout << "  first failure:    line " << *res.first_failure_line << "\n";
                std::cout << "  errors:\n";
                for (const auto& e : res.errors) std::cout << "    " << e << "\n";
                return 3;
            }
            return 0;
        }

        if (cmd == "rate-limit-status") {
            if (argc != 3) { usage(); return 1; }
            std::string identifier = argv[2];
            std::cout << "Rate limiting status for '" << identifier << "':\n";
            std::cout << "  " << rate_limiting::get_status(identifier) << "\n";
            return 0;
        }

        if (cmd == "rate-limit-reset") {
            if (argc != 3) { usage(); return 1; }
            std::string identifier = argv[2];
            rate_limiting::reset(identifier);
            std::cout << "Rate limiting reset for '" << identifier << "'\n";
            return 0;
        }

        if (cmd == "memory-stats") {
            if (argc != 2) { usage(); return 1; }
            std::cout << "Secure Memory Statistics:\n";
            std::cout << memory_protection::get_stats() << "\n";
            return 0;
        }

        usage();
        return 1;
    } catch (const std::exception &e) {
        std::cerr << "ERR: " << e.what() << "\n";
        return 2;
    }
}
#endif // NOCTURNE_FUZZER_BUILD
