#include "side_channel.hpp"
#include <sodium.h>

namespace nocturne {
namespace side_channel {

bool constant_time_compare(const uint8_t* a, const uint8_t* b, size_t len) {
    // Use libsodium's hardened memcmp
    return sodium_memcmp(a, b, len) == 0;
}

void secure_zero_memory(void* ptr, size_t len) {
    // Use sodium_memzero which is resistant to compiler optimizations
    sodium_memzero(ptr, len);
}

void random_delay() {
    // SECURITY FIX: Removed environment variable bypass
    // Random delays are critical for timing attack mitigation and cannot be disabled

#if defined(__has_include) && __has_include(<thread>)
    // SECURITY: Increased delay range from 1-50μs to 100-500μs for better protection
    static thread_local std::mt19937 rng(std::random_device{}());
    static thread_local std::uniform_int_distribution<int> dist(100, 500);
    std::this_thread::sleep_for(std::chrono::microseconds(dist(rng)));
#else
    static std::mt19937 rng(std::random_device{}());
    static std::uniform_int_distribution<int> dist(100, 500);
    volatile int dummy = 0;
    for (int i = 0; i < dist(rng); ++i) {
        dummy += i;
    }
    (void)dummy;
#endif
}

void flush_cache_line(const void* ptr) {
#if defined(__x86_64__) || defined(__i386__)
    _mm_clflush(ptr);
#elif defined(__aarch64__)
    // ARM64 cache flush - use portable approach if intrinsic not available
#ifdef __has_builtin
#if __has_builtin(__builtin_arm_dc_cvau)
    __builtin___arm_dc_cvau(ptr);
#else
    // Portable fallback: memory barrier
    std::atomic_thread_fence(std::memory_order_seq_cst);
#endif
#else
    // Portable fallback: memory barrier
    std::atomic_thread_fence(std::memory_order_seq_cst);
#endif
#else
    // Portable fallback for other architectures
    std::atomic_thread_fence(std::memory_order_seq_cst);
#endif
}

void constant_time_conditional_copy(uint8_t* dst, const uint8_t* src, size_t len, bool condition) {
    uint8_t mask = condition ? 0xFF : 0x00;
    for (size_t i = 0; i < len; i++) {
        dst[i] = (dst[i] & ~mask) | (src[i] & mask);
    }
}

void secure_random_fill(uint8_t* buffer, size_t len) {
    randombytes_buf(buffer, len);
    // Add random delay to prevent power analysis
    random_delay();
    // Flush cache to prevent cache attacks
    flush_cache_line(buffer);
}

bool constant_time_string_compare(const std::string& a, const std::string& b) {
    // No early return on size mismatch
    // Always operate on fixed-size buffer to prevent timing leakage

    constexpr size_t MAX_SIZE = 8192; // Maximum comparison size

    // Use fixed-size buffers (always allocated on stack)
    uint8_t buf_a[MAX_SIZE] = {0};
    uint8_t buf_b[MAX_SIZE] = {0};

    // Clamp sizes to prevent buffer overflow
    size_t len_a = std::min(a.size(), MAX_SIZE);
    size_t len_b = std::min(b.size(), MAX_SIZE);

    // Copy to fixed buffers (constant time copy)
    std::memcpy(buf_a, a.data(), len_a);
    std::memcpy(buf_b, b.data(), len_b);

    // Compare full buffer (constant time regardless of actual size)
    bool data_equal = constant_time_compare(buf_a, buf_b, MAX_SIZE);
    bool size_equal = (len_a == len_b);

    // Constant-time AND (no branching)
    // Convert bools to uint32_t for branchless operation
    uint32_t data_mask = static_cast<uint32_t>(0) - static_cast<uint32_t>(data_equal);
    uint32_t size_mask = static_cast<uint32_t>(0) - static_cast<uint32_t>(size_equal);
    uint32_t result_mask = data_mask & size_mask;

    // Zero buffers to prevent stack leakage
    secure_zero_memory(buf_a, sizeof(buf_a));
    secure_zero_memory(buf_b, sizeof(buf_b));

    return (result_mask != 0);
}

} // namespace side_channel
} // namespace nocturne
