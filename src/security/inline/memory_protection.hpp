/// @file memory_protection.hpp
/// @brief Process-local secure-memory allocator with guard pages,
///        mlock/VirtualLock pinning, and zero-on-deallocate scrubbing.
///
/// **Why this exists.** The cryptographic hot path holds 32-byte
/// AEAD/KEM keys and 64-byte Ed25519/ML-DSA secret keys in process
/// memory for milliseconds at a time. The default `new`/`malloc` lets
/// the kernel page them to swap and leaves their bytes intact after
/// `free` — an attacker with read access to the heap or swap can
/// recover them. This allocator addresses both problems:
///   - **mlock / VirtualLock**: keep pages resident, never swap.
///   - **Guard pages**: NOACCESS pages before/after the allocation so
///     accidental linear overruns crash immediately instead of
///     silently scribbling on adjacent data.
///   - **Zero on free**: volatile-byte wipe + memory barrier to defeat
///     dead-store-elimination optimization.
///
/// **Scope.** The @c SecureMemory<T> template is the ergonomic RAII
/// wrapper most call sites use. The bare `allocate_secure` /
/// `deallocate_secure` free functions are for places that can't fit
/// into the RAII template (libsodium boundary, C-style APIs).
///
/// @par Thread safety
///   SecureAllocator::allocate / deallocate / get_stats / update_config
///   all take the same internal mutex; safe to call concurrently.
///   SecureMemory<T> is not copyable; moves are noexcept. Concurrent
///   access to a single SecureMemory instance from multiple threads
///   needs external synchronisation.
/// @par Exception safety
///   Construction throws std::runtime_error on allocation failure
///   (size = 0, OOM, exceeded quota). Deallocation is nothrow.
///
/// @version 1.0.0

#pragma once

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_map>

#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <windows.h>
#else
#  include <sys/mman.h>
#endif

namespace memory_protection {

/// @brief Configurable knobs for @ref SecureAllocator.
struct MemoryProtectionConfig {
    bool          enable_memory_locking    = true;
    bool          enable_secure_allocator  = true;
    bool          enable_memory_encryption = false;  // Experimental.
    bool          enable_guard_pages       = true;
    std::size_t   guard_page_size          = 4096;
    bool          enable_memory_scrubbing  = true;
    bool          enable_secure_heap       = false;
    std::uint32_t max_secure_allocations   = 1000;
    std::size_t   max_total_memory         = 100 * 1024 * 1024;  // 100 MiB.
};

// Sentinel — the absolute per-allocation cap; mirrors the value that
// used to be a project-wide constant in nocturne-kx.cpp.
inline constexpr std::size_t kMaxAllocationSize = 16 * 1024 * 1024;  // 16 MiB.

/// @brief Page-aligned, mlock-pinned, guard-padded secure allocator.
///
/// One process-wide instance is owned by the global accessors below.
/// Direct construction is supported but rare; most callers go through
/// @ref allocate_secure / @ref deallocate_secure or @ref SecureMemory.
class SecureAllocator {
  public:
    explicit SecureAllocator(const MemoryProtectionConfig& config = MemoryProtectionConfig{})
        : config_{config} {}

    /// @brief Allocate @p size bytes with the configured protections.
    /// @return Non-null pointer to writeable memory of at least @p size.
    /// @par Exception safety: Throws on size=0, oversize, quota
    ///                        exhaustion, or OOM.
    void* allocate(std::size_t size) {
        std::lock_guard<std::mutex> lock{mutex_};
        if (size == 0) {
            throw std::runtime_error{"zero size allocation not allowed"};
        }
        if (size > kMaxAllocationSize) {
            throw std::runtime_error{"allocation size exceeds maximum allowed"};
        }
        if (allocation_count_ >= config_.max_secure_allocations) {
            throw std::runtime_error{"Maximum secure allocations exceeded"};
        }
        std::size_t total_allocated = 0;
        for (const auto& [_, info] : allocations_) total_allocated += info.size;
        if (total_allocated + size > config_.max_total_memory) {
            throw std::runtime_error{"total memory limit exceeded"};
        }

        void* ptr = config_.enable_guard_pages
                        ? allocate_with_guards(size)
                        : std::malloc(size);
        if (!ptr) {
            throw std::runtime_error{"Secure memory allocation failed"};
        }

        bool is_locked = false;
        if (config_.enable_memory_locking) {
            is_locked = lock_memory(ptr, size);
            if (!is_locked) {
                std::cerr << "WARNING: Failed to lock memory in RAM" << std::endl;
            }
        }

        allocations_[ptr] = AllocationInfo{ptr, size, is_locked, false};
        total_allocated_ += size;
        allocation_count_++;
        return ptr;
    }

    /// @brief Release memory previously returned by @ref allocate.
    /// @par Exception safety: Nothrow. Unknown pointers fall back to
    ///                        plain @c std::free.
    void deallocate(void* ptr) noexcept {
        if (!ptr) return;
        std::lock_guard<std::mutex> lock{mutex_};

        auto it = allocations_.find(ptr);
        if (it == allocations_.end()) {
            std::free(ptr);
            return;
        }
        // Snapshot the metadata so the map mutation below cannot UAF
        // the captured fields.
        const AllocationInfo info_copy = it->second;

        scrub_memory(ptr, info_copy.size);
        if (info_copy.is_locked) {
            unlock_memory(ptr, info_copy.size);
        }
        total_allocated_ -= info_copy.size;
        allocation_count_--;
        allocations_.erase(it);

        if (config_.enable_guard_pages) {
            free_with_guards(ptr, info_copy.size);
        } else {
            std::free(ptr);
        }
    }

    /// @brief Human-readable allocator statistics.
    [[nodiscard]] std::string get_stats() {
        std::lock_guard<std::mutex> lock{mutex_};
        std::ostringstream oss;
        oss << "Secure Allocator Stats:\n"
            << "  Total allocated: "    << total_allocated_  << " bytes\n"
            << "  Active allocations: " << allocation_count_ << "\n"
            << "  Memory locking: "     << (config_.enable_memory_locking  ? "enabled" : "disabled") << "\n"
            << "  Guard pages: "        << (config_.enable_guard_pages     ? "enabled" : "disabled") << "\n"
            << "  Memory scrubbing: "   << (config_.enable_memory_scrubbing? "enabled" : "disabled");
        return oss.str();
    }

    void update_config(const MemoryProtectionConfig& config) {
        std::lock_guard<std::mutex> lock{mutex_};
        config_ = config;
    }

  private:
    struct AllocationInfo {
        void*                                 ptr           = nullptr;
        std::size_t                           size          = 0;
        bool                                  is_locked     = false;
        bool                                  is_encrypted  = false;
        std::chrono::steady_clock::time_point allocation_time =
            std::chrono::steady_clock::now();

        AllocationInfo() = default;
        AllocationInfo(void* p, std::size_t s, bool locked, bool encrypted)
            : ptr{p}, size{s}, is_locked{locked}, is_encrypted{encrypted} {}
    };

    bool lock_memory(void* ptr, std::size_t size) noexcept {
#ifdef _WIN32
        return VirtualLock(ptr, size) != 0;
#else
        return mlock(ptr, size) == 0;
#endif
    }

    bool unlock_memory(void* ptr, std::size_t size) noexcept {
#ifdef _WIN32
        return VirtualUnlock(ptr, size) != 0;
#else
        return munlock(ptr, size) == 0;
#endif
    }

    void* allocate_with_guards(std::size_t size) {
        if (size == 0) return nullptr;
        if (size > kMaxAllocationSize) {
            throw std::runtime_error{"allocation size exceeds maximum allowed"};
        }
        if (!config_.enable_guard_pages) {
            void* ptr = std::malloc(size);
            if (!ptr) throw std::runtime_error{"memory allocation failed"};
            return ptr;
        }

        const std::size_t total = size + (2 * config_.guard_page_size);
#ifdef _WIN32
        void* ptr = VirtualAlloc(nullptr, total, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!ptr) return nullptr;
        DWORD old_protect;
        VirtualProtect(ptr, config_.guard_page_size, PAGE_NOACCESS, &old_protect);
        VirtualProtect(static_cast<char*>(ptr) + total - config_.guard_page_size,
                       config_.guard_page_size, PAGE_NOACCESS, &old_protect);
        return static_cast<char*>(ptr) + config_.guard_page_size;
#else
        void* ptr = mmap(nullptr, total, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (ptr == MAP_FAILED) return nullptr;
        mprotect(ptr, config_.guard_page_size, PROT_NONE);
        mprotect(static_cast<char*>(ptr) + total - config_.guard_page_size,
                 config_.guard_page_size, PROT_NONE);
        return static_cast<char*>(ptr) + config_.guard_page_size;
#endif
    }

    void free_with_guards(void* ptr, std::size_t original_size) noexcept {
        if (!config_.enable_guard_pages) {
            std::free(ptr);
            return;
        }
#ifdef _WIN32
        void* base = static_cast<char*>(ptr) - config_.guard_page_size;
        VirtualFree(base, 0, MEM_RELEASE);
#else
        void* base = static_cast<char*>(ptr) - config_.guard_page_size;
        munmap(base, config_.guard_page_size * 2 + original_size);
#endif
    }

    void scrub_memory(void* ptr, std::size_t size) noexcept {
        if (!config_.enable_memory_scrubbing) return;
        // Volatile byte writes defeat dead-store-elimination; the
        // following fence ensures the writes complete before the
        // pointer is released back to the system allocator.
        volatile std::uint8_t* p = static_cast<volatile std::uint8_t*>(ptr);
        for (std::size_t i = 0; i < size; ++i) p[i] = 0;
        std::atomic_thread_fence(std::memory_order_seq_cst);
    }

    std::unordered_map<void*, AllocationInfo> allocations_;
    std::mutex                                mutex_;
    MemoryProtectionConfig                    config_;
    std::size_t                               total_allocated_  = 0;
    std::size_t                               allocation_count_ = 0;
};

// -----------------------------------------------------------------------
// Global accessors — instance lives in memory_protection.cpp.
// -----------------------------------------------------------------------

void initialize(const MemoryProtectionConfig& config = MemoryProtectionConfig{});

[[nodiscard]] void* allocate_secure(std::size_t size);
void                 deallocate_secure(void* ptr) noexcept;
[[nodiscard]] std::string get_stats();

// -----------------------------------------------------------------------
// SecureMemory<T> — RAII wrapper.
// -----------------------------------------------------------------------

/// @brief Owning view over a @p count -element T array allocated from
///        the global secure allocator. Zeroed on destruction.
///
/// Move-only; copies are deleted to keep ownership unambiguous.
/// @tparam T Trivially-copyable element type — secret-key bytes,
///           AEAD nonces, etc.
template <typename T>
class SecureMemory {
  public:
    explicit SecureMemory(std::size_t count = 1)
        : size_{count * sizeof(T)} {
        ptr_ = static_cast<T*>(allocate_secure(size_));
    }

    ~SecureMemory() {
        if (ptr_) deallocate_secure(ptr_);
    }

    SecureMemory(const SecureMemory&)            = delete;
    SecureMemory& operator=(const SecureMemory&) = delete;

    SecureMemory(SecureMemory&& other) noexcept
        : ptr_{other.ptr_}, size_{other.size_} {
        other.ptr_  = nullptr;
        other.size_ = 0;
    }

    SecureMemory& operator=(SecureMemory&& other) noexcept {
        if (this != &other) {
            if (ptr_) deallocate_secure(ptr_);
            ptr_       = other.ptr_;
            size_      = other.size_;
            other.ptr_ = nullptr;
            other.size_ = 0;
        }
        return *this;
    }

    [[nodiscard]] T*        get()           noexcept { return ptr_; }
    [[nodiscard]] const T*  get()     const noexcept { return ptr_; }
    [[nodiscard]] T&        operator*()           noexcept { return *ptr_; }
    [[nodiscard]] const T&  operator*()    const noexcept { return *ptr_; }
    [[nodiscard]] T*        operator->()          noexcept { return ptr_; }
    [[nodiscard]] const T*  operator->()   const noexcept { return ptr_; }
    [[nodiscard]] T&        operator[](std::size_t i)       noexcept { return ptr_[i]; }
    [[nodiscard]] const T&  operator[](std::size_t i) const noexcept { return ptr_[i]; }

    [[nodiscard]] std::size_t size()       const noexcept { return size_ / sizeof(T); }
    [[nodiscard]] std::size_t size_bytes() const noexcept { return size_; }

  private:
    T*          ptr_  = nullptr;
    std::size_t size_ = 0;
};

}  // namespace memory_protection
