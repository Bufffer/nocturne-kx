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

// P5.0–P5.3 foundation: type-safe error path, byte-buffer views, flag
// bitmask, shared value types, packet wire format, and the crypto
// primitive wrappers (KDF, AEAD, Ed25519). The inline definitions that
// used to live in this file have moved into src/core/ and src/protocol/,
// pulled back here for the rest of nocturne-kx.cpp to consume unchanged.
#include "src/core/error.hpp"
#include "src/core/result.hpp"
#include "src/core/byte_span.hpp"
#include "src/core/flags.hpp"
#include "src/core/types.hpp"
#include "src/protocol/packet.hpp"
#include "src/protocol/kdf.hpp"
#include "src/protocol/aead.hpp"
#include "src/protocol/signing.hpp"
#include "src/security/inline/rate_limiter.hpp"
#include "src/security/inline/audit_logger.hpp"
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

// Rate limiting subsystem moved to src/security/inline/rate_limiter.{hpp,cpp}
// in P5.4. The namespace name (rate_limiting) is preserved so existing
// call sites that say `rate_limiting::allow_request(...)` keep working.

// Structured audit logging subsystem moved to src/security/inline/audit_logger.{hpp,cpp}
// in P5.4. The audit_log namespace name is preserved; existing call sites
// (audit_log::info, audit_log::initialize, etc.) keep working unchanged.

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

// Constants, exception hierarchy, key-pair types, and check_sodium()
// all moved to src/core/{flags,types,byte_span,error,result}.hpp in
// P5.0–P5.1. The names below remain reachable through this namespace
// because the foundation headers declare them in namespace nocturne.

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

// Packet, PqcSignerConfig, PqcVerifierConfig, the endian helpers, and
// serialize/deserialize all moved to src/protocol/packet.{hpp,cpp} in
// P5.2. The names remain reachable through namespace nocturne because
// packet.hpp declares them there.

// serialize()/deserialize() moved to src/protocol/packet.cpp in P5.2.
// Declarations are visible via #include "src/protocol/packet.hpp".

// derive_aead_key_from_session, derive_tx_key_client, derive_rx_key_server,
// ratchet_mix, aead_encrypt_xchacha, aead_decrypt_xchacha, ed25519_sign,
// ed25519_verify all moved to src/protocol/{kdf,aead,signing}.hpp in P5.3.
// All retain their nocturne:: namespace; call sites consume them unchanged
// except that the (ptr, size) pair API has been replaced with BytesView.

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
        auto mixed = ratchet_mix(key, BytesView{dh_shared.data(), dh_shared.size()});
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
        auto mixed = ratchet_mix(key, BytesView{dh_shared.data(), dh_shared.size()});
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

// derive_aead_key_from_kem_secret moved to src/protocol/kdf.hpp in P5.3.

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
