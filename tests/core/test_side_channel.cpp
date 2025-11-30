/**
 * @file test_side_channel.cpp
 * @brief Side-channel protection validation tests
 *
 * Tests:
 * - Constant-time operations
 * - Timing attack resistance
 * - Cache attack mitigations
 * - Memory safety
 * - Random delay functionality
 */

#include <catch2/catch_test_macros.hpp>
#include <catch2/benchmark/catch_benchmark.hpp>
#include "../../src/core/side_channel.hpp"
#include <sodium.h>
#include <vector>
#include <chrono>
#include <numeric>
#include <cmath>

using namespace nocturne::side_channel;

TEST_CASE("Constant-Time Comparison", "[side-channel][ct]") {
    if (sodium_init() < 0) {
        FAIL("Failed to initialize libsodium");
    }

    SECTION("Equal Buffers") {
        std::array<uint8_t, 32> a, b;
        randombytes_buf(a.data(), a.size());
        std::copy(a.begin(), a.end(), b.begin());

        REQUIRE(constant_time_compare(a.data(), b.data(), 32));
    }

    SECTION("Different Buffers") {
        std::array<uint8_t, 32> a, b;
        randombytes_buf(a.data(), a.size());
        randombytes_buf(b.data(), b.size());

        // Statistically should be different
        REQUIRE_FALSE(constant_time_compare(a.data(), b.data(), 32));
    }

    SECTION("Single Bit Difference") {
        std::array<uint8_t, 32> a, b;
        randombytes_buf(a.data(), a.size());
        std::copy(a.begin(), a.end(), b.begin());

        // Flip one bit
        b[16] ^= 0x01;

        REQUIRE_FALSE(constant_time_compare(a.data(), b.data(), 32));
    }

    SECTION("Zero Length Comparison") {
        uint8_t a = 0, b = 0;
        REQUIRE(constant_time_compare(&a, &b, 0));
    }

    SECTION("Large Buffer Comparison") {
        std::vector<uint8_t> a(10240), b(10240);
        randombytes_buf(a.data(), a.size());
        std::copy(a.begin(), a.end(), b.begin());

        REQUIRE(constant_time_compare(a.data(), b.data(), a.size()));

        // Change one byte in the middle
        b[5000] ^= 0xFF;
        REQUIRE_FALSE(constant_time_compare(a.data(), b.data(), a.size()));
    }
}

TEST_CASE("Constant-Time Comparison Timing", "[side-channel][timing]") {
    if (sodium_init() < 0) {
        FAIL("Failed to initialize libsodium");
    }

    SECTION("Timing Should Be Independent of Data") {
        std::array<uint8_t, 32> a, b_equal, b_diff_first, b_diff_last;

        randombytes_buf(a.data(), a.size());
        std::copy(a.begin(), a.end(), b_equal.begin());
        std::copy(a.begin(), a.end(), b_diff_first.begin());
        std::copy(a.begin(), a.end(), b_diff_last.begin());

        b_diff_first[0] ^= 0xFF;
        b_diff_last[31] ^= 0xFF;

        const int iterations = 10000;
        std::vector<double> times_equal, times_diff_first, times_diff_last;

        // Measure equal buffers
        for (int i = 0; i < iterations; ++i) {
            auto start = std::chrono::high_resolution_clock::now();
            volatile bool result = constant_time_compare(a.data(), b_equal.data(), 32);
            auto end = std::chrono::high_resolution_clock::now();
            (void)result;

            times_equal.push_back(
                std::chrono::duration<double, std::nano>(end - start).count());
        }

        // Measure different at first byte
        for (int i = 0; i < iterations; ++i) {
            auto start = std::chrono::high_resolution_clock::now();
            volatile bool result = constant_time_compare(a.data(), b_diff_first.data(), 32);
            auto end = std::chrono::high_resolution_clock::now();
            (void)result;

            times_diff_first.push_back(
                std::chrono::duration<double, std::nano>(end - start).count());
        }

        // Measure different at last byte
        for (int i = 0; i < iterations; ++i) {
            auto start = std::chrono::high_resolution_clock::now();
            volatile bool result = constant_time_compare(a.data(), b_diff_last.data(), 32);
            auto end = std::chrono::high_resolution_clock::now();
            (void)result;

            times_diff_last.push_back(
                std::chrono::duration<double, std::nano>(end - start).count());
        }

        // Calculate means
        double mean_equal = std::accumulate(times_equal.begin(), times_equal.end(), 0.0) / iterations;
        double mean_diff_first = std::accumulate(times_diff_first.begin(), times_diff_first.end(), 0.0) / iterations;
        double mean_diff_last = std::accumulate(times_diff_last.begin(), times_diff_last.end(), 0.0) / iterations;

        // Timing should be roughly equal (within 20% variance due to system noise)
        double max_mean = std::max({mean_equal, mean_diff_first, mean_diff_last});
        double min_mean = std::min({mean_equal, mean_diff_first, mean_diff_last});

        double variance_ratio = (max_mean - min_mean) / min_mean;

        INFO("Mean equal: " << mean_equal << " ns");
        INFO("Mean diff first: " << mean_diff_first << " ns");
        INFO("Mean diff last: " << mean_diff_last << " ns");
        INFO("Variance ratio: " << variance_ratio);

        // Allow up to 30% variance (generous for CI environments)
        REQUIRE(variance_ratio < 0.30);
    }
}

TEST_CASE("Secure Memory Zeroing", "[side-channel][memory]") {
    SECTION("Zero Memory") {
        std::vector<uint8_t> buffer(1024);
        for (auto& b : buffer) b = 0xFF;

        secure_zero_memory(buffer.data(), buffer.size());

        bool all_zero = true;
        for (auto b : buffer) {
            if (b != 0) {
                all_zero = false;
                break;
            }
        }

        REQUIRE(all_zero);
    }

    SECTION("Zero Large Buffer") {
        std::vector<uint8_t> buffer(1024 * 1024); // 1 MB
        std::fill(buffer.begin(), buffer.end(), 0xAA);

        secure_zero_memory(buffer.data(), buffer.size());

        for (auto b : buffer) {
            REQUIRE(b == 0);
        }
    }

    SECTION("Zero Alignment") {
        // Test various alignments
        for (size_t offset = 0; offset < 16; ++offset) {
            std::vector<uint8_t> buffer(1024 + offset);
            std::fill(buffer.begin(), buffer.end(), 0x55);

            secure_zero_memory(buffer.data() + offset, 1024);

            // Check zeroed region
            for (size_t i = offset; i < offset + 1024; ++i) {
                REQUIRE(buffer[i] == 0);
            }
        }
    }
}

TEST_CASE("Random Delay Functionality", "[side-channel][delay]") {
    SECTION("Random Delay Executes") {
        // Should not crash or hang
        for (int i = 0; i < 100; ++i) {
            random_delay();
        }
        REQUIRE(true);
    }

    SECTION("Random Delay Timing Variance") {
        const int iterations = 1000;
        std::vector<double> delays;

        for (int i = 0; i < iterations; ++i) {
            auto start = std::chrono::high_resolution_clock::now();
            random_delay();
            auto end = std::chrono::high_resolution_clock::now();

            delays.push_back(
                std::chrono::duration<double, std::micro>(end - start).count());
        }

        // Calculate statistics
        double mean = std::accumulate(delays.begin(), delays.end(), 0.0) / iterations;
        double min_delay = *std::min_element(delays.begin(), delays.end());
        double max_delay = *std::max_element(delays.begin(), delays.end());

        INFO("Mean delay: " << mean << " μs");
        INFO("Min delay: " << min_delay << " μs");
        INFO("Max delay: " << max_delay << " μs");

        // Expect delays in range 100-500 μs (as per implementation)
        // Allow some variance for system scheduling
        REQUIRE(min_delay >= 80);   // 80 μs minimum (20% tolerance)
        REQUIRE(max_delay <= 600);  // 600 μs maximum (20% tolerance)
        REQUIRE(max_delay > min_delay); // Should have variance
    }
}

TEST_CASE("Cache Line Flush", "[side-channel][cache]") {
    SECTION("Flush Does Not Crash") {
        std::array<uint8_t, 64> buffer;
        randombytes_buf(buffer.data(), buffer.size());

        // Should not crash
        flush_cache_line(buffer.data());
        REQUIRE(true);
    }

    SECTION("Flush Multiple Lines") {
        std::vector<uint8_t> buffer(4096);
        randombytes_buf(buffer.data(), buffer.size());

        // Flush every cache line (64 bytes typical)
        for (size_t i = 0; i < buffer.size(); i += 64) {
            flush_cache_line(buffer.data() + i);
        }

        REQUIRE(true);
    }
}

TEST_CASE("Memory Barrier", "[side-channel][barrier]") {
    SECTION("Memory Barrier Executes") {
        std::atomic<int> counter{0};

        counter.store(1);
        memory_barrier();
        int value = counter.load();

        REQUIRE(value == 1);
    }

    SECTION("Memory Barrier Prevents Reordering") {
        std::atomic<bool> flag{false};
        std::atomic<int> data{0};

        // Write data then set flag
        data.store(42);
        memory_barrier();
        flag.store(true);

        // If barrier works, flag=true implies data=42
        memory_barrier();
        if (flag.load()) {
            REQUIRE(data.load() == 42);
        }
    }
}

TEST_CASE("Constant-Time Conditional Copy", "[side-channel][ct-copy]") {
    SECTION("Copy When True") {
        std::array<uint8_t, 32> dst, src;
        std::fill(dst.begin(), dst.end(), 0x00);
        std::fill(src.begin(), src.end(), 0xFF);

        constant_time_conditional_copy(dst.data(), src.data(), 32, true);

        for (auto b : dst) {
            REQUIRE(b == 0xFF);
        }
    }

    SECTION("No Copy When False") {
        std::array<uint8_t, 32> dst, src;
        std::fill(dst.begin(), dst.end(), 0x00);
        std::fill(src.begin(), src.end(), 0xFF);

        constant_time_conditional_copy(dst.data(), src.data(), 32, false);

        for (auto b : dst) {
            REQUIRE(b == 0x00);
        }
    }

    SECTION("Partial Copy") {
        std::array<uint8_t, 64> dst, src;
        std::fill(dst.begin(), dst.end(), 0xAA);
        std::fill(src.begin(), src.end(), 0x55);

        // Copy first 32 bytes
        constant_time_conditional_copy(dst.data(), src.data(), 32, true);

        // First 32 should be copied
        for (size_t i = 0; i < 32; ++i) {
            REQUIRE(dst[i] == 0x55);
        }

        // Last 32 should be unchanged
        for (size_t i = 32; i < 64; ++i) {
            REQUIRE(dst[i] == 0xAA);
        }
    }
}

TEST_CASE("Secure Random Fill", "[side-channel][random]") {
    if (sodium_init() < 0) {
        FAIL("Failed to initialize libsodium");
    }

    SECTION("Fill With Random Data") {
        std::array<uint8_t, 32> buffer{};

        secure_random_fill(buffer.data(), buffer.size());

        // Should not be all zeros (statistically impossible)
        bool has_nonzero = false;
        for (auto b : buffer) {
            if (b != 0) {
                has_nonzero = true;
                break;
            }
        }

        REQUIRE(has_nonzero);
    }

    SECTION("Multiple Fills Produce Different Data") {
        std::array<uint8_t, 32> buf1, buf2;

        secure_random_fill(buf1.data(), buf1.size());
        secure_random_fill(buf2.data(), buf2.size());

        REQUIRE_FALSE(constant_time_compare(buf1.data(), buf2.data(), 32));
    }

    SECTION("Large Buffer Random Fill") {
        std::vector<uint8_t> buffer(10240);

        secure_random_fill(buffer.data(), buffer.size());

        // Check for sufficient entropy (simple test)
        std::array<int, 256> byte_counts{};
        for (auto b : buffer) {
            byte_counts[b]++;
        }

        // Each byte value should appear at least once in 10KB
        int unique_bytes = 0;
        for (auto count : byte_counts) {
            if (count > 0) unique_bytes++;
        }

        // Expect at least 250/256 unique byte values
        REQUIRE(unique_bytes > 250);
    }
}

TEST_CASE("Constant-Time String Comparison", "[side-channel][ct-string]") {
    SECTION("Equal Strings") {
        std::string a = "Hello, World!";
        std::string b = "Hello, World!";

        REQUIRE(constant_time_string_compare(a, b));
    }

    SECTION("Different Strings Same Length") {
        std::string a = "Hello, World!";
        std::string b = "Hello, Alice!";

        REQUIRE_FALSE(constant_time_string_compare(a, b));
    }

    SECTION("Different String Lengths") {
        std::string a = "Short";
        std::string b = "Much Longer String";

        REQUIRE_FALSE(constant_time_string_compare(a, b));
    }

    SECTION("Empty Strings") {
        std::string a = "";
        std::string b = "";

        REQUIRE(constant_time_string_compare(a, b));
    }
}

TEST_CASE("Constant-Time Mask Operations", "[side-channel][ct-ops]") {
    SECTION("CT Mask True") {
        uint32_t mask = ct_mask(true);
        REQUIRE(mask == 0xFFFFFFFF);
    }

    SECTION("CT Mask False") {
        uint32_t mask = ct_mask(false);
        REQUIRE(mask == 0x00000000);
    }

    SECTION("CT Select") {
        uint32_t a = 0x12345678;
        uint32_t b = 0xABCDEF00;

        uint32_t result_true = ct_select_u32(a, b, true);
        uint32_t result_false = ct_select_u32(a, b, false);

        REQUIRE(result_true == b);
        REQUIRE(result_false == a);
    }
}

TEST_CASE("Side-Channel Protection Performance", "[side-channel][benchmark]") {
    if (sodium_init() < 0) {
        FAIL("Failed to initialize libsodium");
    }

    std::array<uint8_t, 32> a, b;
    randombytes_buf(a.data(), a.size());
    randombytes_buf(b.data(), b.size());

    BENCHMARK("Constant-Time Compare (32 bytes)") {
        return constant_time_compare(a.data(), b.data(), 32);
    };

    std::array<uint8_t, 1024> large_buf;
    BENCHMARK("Secure Zero Memory (1 KB)") {
        secure_zero_memory(large_buf.data(), large_buf.size());
        return large_buf;
    };

    BENCHMARK("Random Delay") {
        random_delay();
    };

    BENCHMARK("Cache Flush") {
        flush_cache_line(a.data());
    };

    BENCHMARK("Memory Barrier") {
        memory_barrier();
    };

    BENCHMARK("Secure Random Fill (32 bytes)") {
        secure_random_fill(a.data(), a.size());
        return a;
    };
}
