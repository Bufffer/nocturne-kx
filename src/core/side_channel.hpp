#ifndef NOCTURNE_CORE_SIDE_CHANNEL_HPP
#define NOCTURNE_CORE_SIDE_CHANNEL_HPP

#include <cstdint>
#include <cstring>
#include <string>
#include <atomic>
#include <chrono>
#include <thread>
#include <random>
#include <cstdlib>

// Platform-specific headers for side-channel protection
#if defined(__x86_64__) || defined(__i386__)
#include <immintrin.h>
#endif

namespace nocturne {
namespace side_channel {

/**
 * @brief Constant-time comparison to prevent timing attacks
 * @param a First buffer
 * @param b Second buffer
 * @param len Length of buffers
 * @return true if buffers are equal, false otherwise
 * @note Uses libsodium's hardened memcmp (sodium_memcmp)
 */
bool constant_time_compare(const uint8_t* a, const uint8_t* b, size_t len);

/**
 * @brief Constant-time memory zeroing
 * @param ptr Pointer to memory to zero
 * @param len Length of memory to zero
 * @note Uses sodium_memzero which is resistant to compiler optimizations
 */
void secure_zero_memory(void* ptr, size_t len);

/**
 * @brief Generate constant-time mask (branchless)
 * @param condition Boolean condition
 * @return 0xFFFFFFFF if true, 0x00000000 if false
 */
inline uint32_t ct_mask(bool condition) {
    return static_cast<uint32_t>(0) - static_cast<uint32_t>(condition);
}

/**
 * @brief Constant-time selection between two values (branchless)
 * @param a First value
 * @param b Second value
 * @param pick_b Select b if true, a if false
 * @return Selected value without branching
 */
inline uint32_t ct_select_u32(uint32_t a, uint32_t b, bool pick_b) {
    uint32_t m = ct_mask(pick_b);
    return (a & ~m) | (b & m);
}

/**
 * @brief Random delay to prevent timing attacks
 * @note Can be disabled by setting NOCTURNE_DISABLE_RANDOM_DELAY environment variable
 */
void random_delay();

/**
 * @brief Flush cache line to prevent cache attacks
 * @param ptr Pointer to cache line to flush
 * @note Architecture-specific implementation (x86-64, ARM64, portable fallback)
 */
void flush_cache_line(const void* ptr);

/**
 * @brief Memory barrier to prevent reordering attacks
 */
inline void memory_barrier() {
    std::atomic_thread_fence(std::memory_order_seq_cst);
}

/**
 * @brief Constant-time conditional copy
 * @param dst Destination buffer
 * @param src Source buffer
 * @param len Length of buffers
 * @param condition Copy if true, no-op if false
 */
void constant_time_conditional_copy(uint8_t* dst, const uint8_t* src, size_t len, bool condition);

/**
 * @brief Secure random number generation with side-channel protection
 * @param buffer Buffer to fill with random bytes
 * @param len Length of buffer
 * @note Includes random delay and cache flush
 */
void secure_random_fill(uint8_t* buffer, size_t len);

/**
 * @brief Constant-time string comparison (DEPRECATED - use fixed-size comparison)
 * @param a First string
 * @param b Second string
 * @return true if strings are equal, false otherwise
 * @warning Size comparison may leak timing information - use with caution
 * @deprecated Use constant_time_compare_padded() for variable-size data
 */
bool constant_time_string_compare(const std::string& a, const std::string& b);

/**
 * @brief Fixed-size constant-time comparison (no size leakage)
 * @tparam N Size of arrays
 * @param a First array
 * @param b Second array
 * @return true if arrays are equal, false otherwise
 * @note Recommended for cryptographic keys and authentication tags
 */
template<size_t N>
inline bool constant_time_compare_fixed(const uint8_t (&a)[N], const uint8_t (&b)[N]) {
    return constant_time_compare(a, b, N);
}

/**
 * @brief Branchless conditional select (template version)
 * @tparam T Trivially copyable type
 * @param a First value
 * @param b Second value
 * @param condition Select b if true, a if false
 * @return Selected value
 */
template<typename T>
inline T ct_select(T a, T b, bool condition) {
    static_assert(std::is_trivially_copyable_v<T>, "T must be trivially copyable");

    T result;
    unsigned char* p_result = reinterpret_cast<unsigned char*>(&result);
    const unsigned char* p_a = reinterpret_cast<const unsigned char*>(&a);
    const unsigned char* p_b = reinterpret_cast<const unsigned char*>(&b);

    uint8_t mask = static_cast<uint8_t>(0) - static_cast<uint8_t>(condition);

    for (size_t i = 0; i < sizeof(T); ++i) {
        p_result[i] = (p_a[i] & ~mask) | (p_b[i] & mask);
    }

    return result;
}

/**
 * @brief Cache-timing resistant table lookup
 * @tparam T Element type
 * @tparam N Table size
 * @param table Lookup table
 * @param index Index to lookup (must be < N)
 * @return Element at index (access all elements to prevent cache timing)
 */
template<typename T, size_t N>
inline T cache_resistant_lookup(const T (&table)[N], size_t index) {
    T result{};

    // Access all elements to prevent cache-timing attacks
    for (size_t i = 0; i < N; ++i) {
        bool match = (i == index);
        result = ct_select(result, table[i], match);
    }

    return result;
}

} // namespace side_channel
} // namespace nocturne

#endif // NOCTURNE_CORE_SIDE_CHANNEL_HPP
